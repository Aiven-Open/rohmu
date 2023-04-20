"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from io import BytesIO
from rohmu.object_storage.local import LocalTransfer
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import MagicMock

import os


def test_store_file_from_disk() -> None:
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
        )
        test_data = b"test-data"
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(test_data)
            tmpfile.flush()
            transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name)

        assert open(os.path.join(destdir, "test_key1"), "rb").read() == test_data
        notifier.object_created.assert_called_once_with(
            key="test_key1", size=len(test_data), metadata={"Content-Length": "9"}
        )


def test_store_file_object() -> None:
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
        )
        test_data = b"test-data-2"
        file_object = BytesIO(test_data)

        transfer.store_file_object(key="test_key2", fd=file_object)

        assert open(os.path.join(destdir, "test_key2"), "rb").read() == test_data
        notifier.object_created.assert_called_once_with(key="test_key2", size=len(test_data), metadata={})
