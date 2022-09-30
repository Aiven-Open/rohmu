"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from .interface import Notifier
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, unique
from logging import getLogger
from queue import Empty, Queue
from requests.exceptions import RequestException
from typing import Optional

import json
import requests
import threading

LOG = getLogger(__name__)


# Notifiers can be a short-lived objects, the threads must quit so to not leak resources. This
# timeout controls how often a thread will check for termination.
_CHECK_STOP_EVENT_TIMEOUT = 5
_THREAD_JOIN_TIMEOUT = 7
msg = "thread wait must be larger than check wait"
assert _THREAD_JOIN_TIMEOUT >= _CHECK_STOP_EVENT_TIMEOUT, msg


@unique
class Operation(Enum):
    UPLOAD = "UPLOAD"
    DELETE = "DELETE"
    DELETE_TREE = "DELETE_TREE"


def _get_requests_session() -> requests.Session:
    retry = requests.adapters.Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods={"POST"},
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    request_session = requests.Session()
    request_session.mount("http://", adapter)
    request_session.mount("https://", adapter)
    return request_session


@dataclass(frozen=True)
class HTTPNotifyJob:
    url: str
    json: str


def background_http_request(
    session: requests.Session,
    queue: "Queue[HTTPNotifyJob]",
    stop_event: threading.Event,
    stop_event_check_timeout: float,
) -> None:
    with session:
        while not stop_event.is_set():
            try:
                notification = queue.get(timeout=stop_event_check_timeout)
            except Empty:
                notification = None

            if notification is not None:
                try:
                    session.post(notification.url, notification.json)
                except RequestException as e:
                    LOG.warning(
                        "[BackgroundHTTPNotifier] POST request to %r failed with %r, dropping event",
                        notification.url,
                        str(e),
                    )

                # The session is configured to do automatic retries, and that should handle most
                # transients errors. Situations that takes longer than the configured retries will
                # cause events to be dropped because we can't differentiate it from a non-transient
                # errors.
                #
                # For non-transient errors the thread must kept running to consume from the queue,
                # because there is no mechanism to stop producing to it. Hopefully the failure is
                # fast enough that the queue won't grow faster than this threads consumes from it.
                queue.task_done()


def initialize_background_thread(
    queue: Queue,
    stop_event: threading.Event,
    stop_event_check_timeout: float = _CHECK_STOP_EVENT_TIMEOUT,
    session: requests.Session = None,
) -> threading.Thread:
    thread_session = session or _get_requests_session()
    thread_args = (thread_session, queue, stop_event, stop_event_check_timeout)
    thread = threading.Thread(
        target=background_http_request,
        args=thread_args,
        name="BackgroundHTTPNotifierThread",
        # The thread is a daemon thread to prevent it from blocking the shutdown. This would happen
        # if the current notifier is not closed.
        daemon=True,
    )
    thread.start()
    return thread


class BackgroundHTTPNotifier(Notifier):
    def __init__(
        self,
        url: str,
        stop_event_check_timeout: float = _CHECK_STOP_EVENT_TIMEOUT,
        session: requests.Session = None,
    ) -> None:
        self._url = url
        self._queue: "Queue[HTTPNotifyJob]" = Queue()
        self._stop_event = threading.Event()
        self._thread = initialize_background_thread(
            self._queue,
            self._stop_event,
            stop_event_check_timeout,
            session=session,
        )

    def __del__(self) -> None:
        # Set the stop event on a best effort. If the event is not set the background thread leaks
        # because it has a strong reference to itself.
        self.close()

    def close(self) -> None:
        self._stop_event.set()
        self._thread.join(_THREAD_JOIN_TIMEOUT)

    def object_created(self, key: str, size: Optional[int], metadata: Optional[dict]) -> None:
        self._queue.put(
            HTTPNotifyJob(
                self._url,
                json.dumps(
                    {
                        "op": Operation.UPLOAD.value,
                        "key": key,
                        "size": size,
                        "last_modified": datetime.now(tz=timezone.utc).isoformat(),
                        "metadata": metadata,
                    }
                ),
            )
        )

    def object_deleted(self, key: str) -> None:
        self._queue.put(
            HTTPNotifyJob(
                self._url,
                json.dumps(
                    {
                        "op": Operation.DELETE.value,
                        "key": key,
                    }
                ),
            )
        )

    def tree_deleted(self, key: str) -> None:
        self._queue.put(
            HTTPNotifyJob(
                self._url,
                json.dumps(
                    {
                        "op": Operation.DELETE_TREE.value,
                        "key": key,
                    }
                ),
            )
        )
