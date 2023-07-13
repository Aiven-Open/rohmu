"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from io import BytesIO
from pathlib import Path
from rohmu.errors import InvalidByteRangeError
from rohmu.object_storage.base import KEY_TYPE_OBJECT
from rohmu.object_storage.local import LocalTransfer
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import MagicMock

import json
import os
import pytest


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

        assert Path(os.path.join(destdir, "test_key1")).read_bytes() == test_data
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

        assert Path(os.path.join(destdir, "test_key2")).read_bytes() == test_data
        notifier.object_created.assert_called_once_with(key="test_key2", size=len(test_data), metadata={})

        data, _ = transfer.get_contents_to_string("test_key2")
        assert data == test_data

        data, _ = transfer.get_contents_to_string("test_key2", byte_range=(1, 123456))
        assert data == test_data[1:]

        data, _ = transfer.get_contents_to_string("test_key2", byte_range=(0, len(test_data) - 2))
        assert data == test_data[:-1]


def test_get_contents_to_fileobj_raises_error_on_invalid_byte_range() -> None:
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
        )
        with pytest.raises(InvalidByteRangeError):
            transfer.get_contents_to_fileobj(
                key="testkey",
                fileobj_to_store_to=BytesIO(),
                byte_range=(100, 10),
            )


def test_can_handle_metadata_without_md5() -> None:
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

        # override the metadata file removing the hash.
        # this simulates files stored by older versions of rohmu
        target_file = transfer.format_key_for_backend("test_key1")
        metadata_file = target_file + ".metadata"
        old_metadata = {"Content-Length": str(len(test_data))}
        with open(metadata_file, "w") as metadata_fp:
            json.dump(old_metadata, metadata_fp)

        # we can read the metadata
        assert transfer.get_metadata_for_key("test_key1") == old_metadata
        # and we can also load the file information iterating over the storage
        item = next(transfer.iter_key("test_key1", with_metadata=True, include_key=True))
        assert item.type == KEY_TYPE_OBJECT
        result = item.value
        assert isinstance(result, dict)
        expected_value = {
            "name": "test_key1",
            "size": len(test_data),
            "metadata": old_metadata,
        }
        last_modified = result.pop("last_modified")
        assert last_modified is not None
        assert result == expected_value
