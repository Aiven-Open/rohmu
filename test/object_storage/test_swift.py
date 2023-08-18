"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from datetime import datetime
from io import BytesIO
from tempfile import NamedTemporaryFile
from types import ModuleType
from unittest.mock import MagicMock, patch

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
