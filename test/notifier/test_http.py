# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Queue
from rohmu.notifier.http import (
    background_http_request,
    BackgroundHTTPNotifier,
    HTTPNotifyJob,
    initialize_background_thread,
    Operation,
)
from types import TracebackType
from typing import Any, Iterator, List, Tuple, Type

import json
import requests
import threading
import time


class _TestSession:
    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pylint: disable=super-init-not-called,unused-argument
        self.post_called: List[Tuple[Any, ...]] = []

    def post(self, *args: Any, **kwargs: Any) -> None:
        self.post_called.append((args, kwargs))

    def __enter__(self) -> None:
        pass

    def __exit__(
        self, type: Type[BaseException], value: BaseException, traceback: TracebackType  # pylint: disable=redefined-builtin
    ) -> None:
        pass


def _join_queue_with_timeout(queue: Queue[HTTPNotifyJob], *, timeout: float, iteration: float = 0.1) -> None:
    while queue.unfinished_tasks and timeout > 0.0:
        time.sleep(iteration)
        timeout -= iteration

    assert not queue.unfinished_tasks, "queue is not empty after timeout"


@contextmanager
def _make_notifier(url: str) -> Iterator[BackgroundHTTPNotifier]:
    # pylint: disable=protected-access

    session = requests.Session()
    notifier = BackgroundHTTPNotifier(
        url=url,
        stop_event_check_timeout=0.2,
        session=session,
    )

    with closing(notifier):
        yield notifier

        assert notifier._thread.is_alive(), "background thread must not die during the test execution"

    assert not notifier._thread.is_alive(), "background thread must be stopped once close is called"


@contextmanager
def _create_local_server() -> Iterator[Tuple[HTTPServer, List[Any]]]:
    post_called: List[Any] = []

    class _TestServerRequestHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            content_length = int(self.headers.get("Content-Length") or 0)
            data = self.rfile.read(content_length)
            post_called.append((self.command, self.path, data))
            self.send_response(200)
            self.end_headers()

    server = HTTPServer(("", 0), _TestServerRequestHandler)

    try:
        yield server, post_called
    finally:
        server.server_close()


@contextmanager
def _create_server_and_configured_notifier(
    path: str,
) -> Iterator[Tuple[BackgroundHTTPNotifier, HTTPServer, List[Any]]]:
    """Creates a server and a notifier configured to communicated with that server.

    Note: The server does not run in the background and should be driven by the
    test with calls to `handle_request`.
    """
    with _create_local_server() as (server, post_called):
        url = f"http://{server.server_name}:{server.server_port}{path}"

        with _make_notifier(url=url) as notifier:
            yield notifier, server, post_called


def test_background_http_request() -> None:
    session = _TestSession()
    stop_event = threading.Event()
    stop_event_check_timeout = 0.2
    queue: Queue[HTTPNotifyJob] = Queue()
    url = "http://test_background_http_request.com"
    data = json.dumps(["test", "background", "http", "request"])

    thread = threading.Thread(
        target=background_http_request,
        args=(
            session,
            queue,
            stop_event,
            stop_event_check_timeout,
        ),
    )
    thread.start()
    assert thread.is_alive()

    queue.put(HTTPNotifyJob(url, data))
    _join_queue_with_timeout(queue, timeout=5)

    assert len(session.post_called) == 1, "data must be POSTed"
    assert session.post_called[0][0][0] == url, "URL didn't match expected value"
    assert session.post_called[0][0][1] == data, "data didn't match expected value"

    assert thread.is_alive()
    stop_event.set()
    thread.join(timeout=5)
    assert not thread.is_alive(), "thread must quit when stop event is set"


def test_initialize_background_thread() -> None:
    stop_event = threading.Event()
    stop_event_check_timeout = 0.2
    queue: Queue[HTTPNotifyJob] = Queue()
    thread = initialize_background_thread(
        queue,
        stop_event,
        stop_event_check_timeout=stop_event_check_timeout,
    )
    assert thread.is_alive(), "freshly created thread must be healthy and running"
    assert thread.daemon is True, "background thread must be daemon so that it won't prevent main thread from exiting"
    stop_event.set()
    thread.join(timeout=5)
    assert not thread.is_alive(), "thread must exit after stop_event is set"


def test_BackgroundHTTPNotifier_target_url_not_available() -> None:
    # pylint: disable=protected-access

    hopefully_unused_port = 7543
    key = "test_BackgroundHTTPNotifier_target_url_not_available"
    size = 1

    with _make_notifier(url=f"http://localhost:{hopefully_unused_port}/bad/path") as notifier:
        notifier.object_created(key=key, size=size, metadata=None)
        # the queue must be consumed by the background thread and the job discarded if the target
        # url is invalid
        _join_queue_with_timeout(notifier._queue, timeout=5.0)


def test_BackgroundHTTPNotifier_object_create_size_none() -> None:
    key = "test_BackgroundHTTPNotifier_object_create_size_none"
    size = None

    with _create_server_and_configured_notifier(path=f"/{key}") as (notifier, server, post_called):
        notifier.object_created(key=key, size=size, metadata=None)
        assert len(post_called) == 0
        server.handle_request()
        assert len(post_called) == 1
        object_created_data = json.loads(post_called[0][2])
        assert object_created_data["op"] == Operation.UPLOAD.value
        assert object_created_data["key"] == key
        assert object_created_data["size"] == size
        assert datetime.fromisoformat(object_created_data["last_modified"])


def test_BackgroundHTTPNotifier_object_create() -> None:
    key = "test_BackgroundHTTPNotifier_object_create"
    size = 3

    with _create_server_and_configured_notifier(path=f"/{key}") as (notifier, server, post_called):
        notifier.object_created(key=key, size=size, metadata=None)
        assert len(post_called) == 0
        server.handle_request()
        assert len(post_called) == 1
        object_created_data = json.loads(post_called[0][2])
        assert object_created_data["op"] == Operation.UPLOAD.value
        assert object_created_data["key"] == key
        assert object_created_data["size"] == size
        assert datetime.fromisoformat(object_created_data["last_modified"])


def test_BackgroundHTTPNotifier_object_deleted() -> None:
    key = "test_BackgroundHTTPNotifier_object_deleted"

    with _create_server_and_configured_notifier(path=f"/{key}") as (notifier, server, post_called):
        notifier.object_deleted(key=key)
        assert len(post_called) == 0
        server.handle_request()
        assert len(post_called) == 1
        object_created_data = json.loads(post_called[0][2])
        assert object_created_data["op"] == Operation.DELETE.value
        assert object_created_data["key"] == key


def test_BackgroundHTTPNotifier_tree_deleted() -> None:
    key = "test_BackgroundHTTPNotifier_tree_deleted"

    with _create_server_and_configured_notifier(path=f"/{key}") as (notifier, server, post_called):
        notifier.tree_deleted(key=key)
        assert len(post_called) == 0
        server.handle_request()
        assert len(post_called) == 1
        object_created_data = json.loads(post_called[0][2])
        assert object_created_data["op"] == Operation.DELETE_TREE.value
        assert object_created_data["key"] == key


def test_BackgroundHTTPNotifier_object_copied() -> None:
    key = "test_BackgroundHTTPNotifier_object_create"
    size = 3

    with _create_server_and_configured_notifier(path=f"/{key}") as (notifier, server, post_called):
        notifier.object_copied(key=key, size=size, metadata=None)
        assert len(post_called) == 0
        server.handle_request()
        assert len(post_called) == 1
        object_created_data = json.loads(post_called[0][2])
        assert object_created_data["op"] == Operation.UPLOAD.value
        assert object_created_data["key"] == key
        assert object_created_data["size"] == size
        assert datetime.fromisoformat(object_created_data["last_modified"])
