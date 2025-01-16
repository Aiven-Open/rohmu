# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from datetime import datetime
from io import BytesIO
from tempfile import NamedTemporaryFile
from types import ModuleType
from typing import Union
from unittest.mock import call, MagicMock, patch

import pytest
import sys


@pytest.fixture(scope="module", name="swift_module")
def fixture_swift_module() -> ModuleType:
    with patch.dict(sys.modules, {"swiftclient": MagicMock()}):
        import rohmu.object_storage.swift

    return rohmu.object_storage.swift


def test_store_file_from_disk(swift_module: ModuleType) -> None:
    notifier = MagicMock()
    connection = MagicMock()
    swift_module.client.Connection.return_value = connection
    transfer = swift_module.SwiftTransfer(
        user="testuser",
        key="testkey",
        container_name="test_container",
        auth_url="http://auth.example.com",
        notifier=notifier,
    )
    test_data = b"test-data"
    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    with NamedTemporaryFile() as tmpfile:
        tmpfile.write(test_data)
        tmpfile.flush()
        transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name, metadata=metadata)

    connection.put_object.assert_called()
    notifier.object_created.assert_called_once_with(
        key="test_key1", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
    )


def test_store_file_object(swift_module: ModuleType) -> None:
    notifier = MagicMock()
    connection = MagicMock()
    swift_module.client.Connection.return_value = connection
    transfer = swift_module.SwiftTransfer(
        user="testuser",
        key="testkey",
        container_name="test_container",
        auth_url="http://auth.example.com",
        notifier=notifier,
    )
    test_data = b"test-data"
    file_object = BytesIO(test_data)
    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata)

    connection.put_object.assert_called()
    notifier.object_created.assert_called_once_with(
        key="test_key2", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
    )


def test_iter_key_with_empty_key(swift_module: ModuleType) -> None:
    notifier = MagicMock()
    connection = MagicMock(get_container=MagicMock(return_value=[None, {}]))
    swift_module.client.Connection.return_value = connection
    transfer = swift_module.SwiftTransfer(
        user="testuser",
        key="testkey",
        container_name="test_container",
        auth_url="http://auth.example.com",
        notifier=notifier,
    )
    list(transfer.iter_key(""))
    transfer.conn.get_container.assert_called_with("test_container", prefix="", full_listing=True, delimiter="/")


@pytest.mark.parametrize(
    ("key", "preserve_trailing_slash", "expected_key"),
    [
        ("1", True, "test-prefix/1"),
        ("2/", True, "test-prefix/2/"),
        ("1", False, "test-prefix/1"),
        ("2/", False, "test-prefix/2"),
        ("1", None, "test-prefix/1"),
        ("2/", None, "test-prefix/2"),
    ],
)
def test_delete_key(
    swift_module: ModuleType, key: str, preserve_trailing_slash: Union[bool, None], expected_key: str
) -> None:
    notifier = MagicMock()
    connection = MagicMock()
    swift_module.client.Connection.return_value = connection
    transfer = swift_module.SwiftTransfer(
        user="testuser",
        key="testkey",
        container_name="test_container",
        auth_url="http://auth.example.com",
        notifier=notifier,
        prefix="test-prefix/",
    )
    if preserve_trailing_slash is None:
        transfer.delete_key(key=key)
    else:
        transfer.delete_key(key=key, preserve_trailing_slash=preserve_trailing_slash)

    connection.assert_has_calls(
        [
            # ensure container exists
            call.get_container("test_container", headers={}, limit=1),
            call.head_object("test_container", expected_key),
            call.head_object().__contains__("x-object-manifest"),
            call.delete_object("test_container", expected_key),
        ]
    )


@pytest.mark.parametrize("preserve_trailing_slash", [True, False, None])
def test_delete_keys(swift_module: ModuleType, preserve_trailing_slash: Union[bool, None]) -> None:
    notifier = MagicMock()
    connection = MagicMock()
    swift_module.client.Connection.return_value = connection
    transfer = swift_module.SwiftTransfer(
        user="testuser",
        key="testkey",
        container_name="test_container",
        auth_url="http://auth.example.com",
        notifier=notifier,
        prefix="test-prefix/",
    )
    if preserve_trailing_slash is None:
        transfer.delete_keys(["2", "3", "4/"])
    else:
        transfer.delete_keys(["2", "3", "4/"], preserve_trailing_slash=preserve_trailing_slash)

    expected_calls = [call.get_container("test_container", headers={}, limit=1)]
    expected_keys = ["2", "3", "4/"] if preserve_trailing_slash else ["2", "3", "4"]
    for expected_key in expected_keys:
        expected_calls.extend(
            [
                call.head_object("test_container", f"test-prefix/{expected_key}"),
                call.head_object().__contains__("x-object-manifest"),
                call.delete_object("test_container", f"test-prefix/{expected_key}"),
            ]
        )
    connection.assert_has_calls(expected_calls)
