"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from rohmu.errors import FileNotFoundFromStorageError, InvalidByteRangeError, StorageError
from rohmu.object_storage.base import KEY_TYPE_OBJECT
from rohmu.object_storage.local import LocalTransfer
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import MagicMock

import hashlib
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


def test_can_upload_files_concurrently() -> None:
    with TemporaryDirectory() as destdir, TemporaryDirectory() as mpu_tmpdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
            concurrent_upload_directory=mpu_tmpdir,
        )
        upload = transfer.create_concurrent_upload(key="test_key1", metadata={"some-key": "some-value"})
        # should end up with b"Hello, World!\nHello, World!"
        expected_data = b"Hello, World!\nHello, World!"
        upload.upload_chunk(3, BytesIO(b"Hello"))
        upload.upload_chunk(4, BytesIO(b", "))
        upload.upload_chunk(1, BytesIO(b"Hello, World!"))
        upload.upload_chunk(7, BytesIO(b"!"))
        upload.upload_chunk(2, BytesIO(b"\n"))
        upload.upload_chunk(6, BytesIO(b"ld"))
        upload.upload_chunk(5, BytesIO(b"Wor"))
        upload.complete()

        # we can read the metadata
        assert transfer.get_metadata_for_key("test_key1") == {"some-key": "some-value"}
        # and we can also load the file information iterating over the storage
        item = next(transfer.iter_key("test_key1", with_metadata=True, include_key=True))
        assert item.type == KEY_TYPE_OBJECT
        result = item.value
        assert isinstance(result, dict)

        hasher = hashlib.sha256()
        hasher.update(expected_data)
        md5 = hasher.hexdigest()  # yes, currently we return an "md5" that is really the sha256 of the contents.
        expected_value = {
            "md5": md5,
            "name": "test_key1",
            "size": len(expected_data),
            "metadata": {"some-key": "some-value"},
        }
        last_modified = result.pop("last_modified")
        assert last_modified is not None
        assert result == expected_value
        # after completion of the upload we have cleaned up the temporary storage
        assert not os.path.exists(upload._upload_tmp_dir)  # type: ignore [attr-defined] # pylint: disable=protected-access

        # calling complete again does nothing
        upload.complete()

        with pytest.raises(StorageError):
            upload.abort()

        with pytest.raises(StorageError):
            upload.upload_chunk(10, BytesIO(b"more data"))


def test_can_upload_files_concurrently_with_threads() -> None:
    with TemporaryDirectory() as destdir, TemporaryDirectory() as mpu_tmpdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
            concurrent_upload_directory=mpu_tmpdir,
        )
        upload = transfer.create_concurrent_upload(key="test_key1", metadata={"some-key": "some-value"})
        # should end up with b"Hello, World!\nHello, World!"
        expected_data = b"Hello, World!\nHello, World!"

        with ThreadPoolExecutor() as pool:
            pool.map(
                upload.upload_chunk,
                [3, 4, 1, 7, 2, 6, 5],
                [
                    BytesIO(b"Hello"),
                    BytesIO(b", "),
                    BytesIO(b"Hello, World!"),
                    BytesIO(b"!"),
                    BytesIO(b"\n"),
                    BytesIO(b"ld"),
                    BytesIO(b"Wor"),
                ],
            )

        upload.complete()

        # we can read the metadata
        assert transfer.get_metadata_for_key("test_key1") == {"some-key": "some-value"}
        # and we can also load the file information iterating over the storage
        item = next(transfer.iter_key("test_key1", with_metadata=True, include_key=True))
        assert item.type == KEY_TYPE_OBJECT
        result = item.value
        assert isinstance(result, dict)

        hasher = hashlib.sha256()
        hasher.update(expected_data)
        md5 = hasher.hexdigest()  # yes, currently we return an "md5" that is really the sha256 of the contents.
        expected_value = {
            "md5": md5,
            "name": "test_key1",
            "size": len(expected_data),
            "metadata": {"some-key": "some-value"},
        }
        last_modified = result.pop("last_modified")
        assert last_modified is not None
        assert result == expected_value
        # after completion of the upload we have cleaned up the temporary storage
        assert not os.path.exists(upload._upload_tmp_dir)  # type: ignore [attr-defined] # pylint: disable=protected-access


def test_upload_files_concurrently_can_be_aborted() -> None:
    with TemporaryDirectory() as destdir, TemporaryDirectory() as mpu_tmpdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
            concurrent_upload_directory=mpu_tmpdir,
        )
        upload = transfer.create_concurrent_upload(key="test_key1", metadata={"some-key": "some-value"})
        # should end up with b"Hello, World!\nHello, World!"
        upload.upload_chunk(3, BytesIO(b"Hello"))
        upload.upload_chunk(4, BytesIO(b", "))
        upload.upload_chunk(1, BytesIO(b"Hello, World!"))
        upload.upload_chunk(7, BytesIO(b"!"))
        upload.upload_chunk(2, BytesIO(b"\n"))
        upload.upload_chunk(6, BytesIO(b"ld"))
        upload.upload_chunk(5, BytesIO(b"Wor"))
        upload.abort()

        # we should not be able to find this
        with pytest.raises(FileNotFoundFromStorageError):
            transfer.get_metadata_for_key("test_key1")

        # after abort of the upload we have cleaned up the temporary storage
        assert not os.path.exists(upload._upload_tmp_dir)  # type: ignore [attr-defined] # pylint: disable=protected-access

        # calling abort again does nothing
        upload.abort()

        with pytest.raises(StorageError):
            upload.complete()

        with pytest.raises(StorageError):
            upload.upload_chunk(10, BytesIO(b"more data"))


def test_concurrent_upload_can_be_resumed() -> None:
    with TemporaryDirectory() as destdir, TemporaryDirectory() as mpu_tmpdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
            concurrent_upload_directory=mpu_tmpdir,
        )
        upload = transfer.create_concurrent_upload(key="test_key1", metadata={"some-key": "some-value"})
        # should end up with b"Hello, World!\nHello, World!"
        expected_data = b"Hello, World!\nHello, World!"
        upload.upload_chunk(3, BytesIO(b"Hello"))
        upload.upload_chunk(4, BytesIO(b", "))
        upload.upload_chunk(1, BytesIO(b"Hello, World!"))

        new_transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
            concurrent_upload_directory=mpu_tmpdir,
        )
        new_upload = new_transfer.get_concurrent_upload(upload.upload_id)

        # client can check which chunks were uploaded previously and complete the upload
        previously_uploaded_chunks = new_upload.list_uploaded_chunks()
        assert list(previously_uploaded_chunks) == [1, 3, 4]
        new_upload.upload_chunk(7, BytesIO(b"!"))
        new_upload.upload_chunk(2, BytesIO(b"\n"))
        new_upload.upload_chunk(6, BytesIO(b"ld"))
        new_upload.upload_chunk(5, BytesIO(b"Wor"))
        new_upload.complete()

        # we can read the metadata
        assert new_transfer.get_metadata_for_key("test_key1") == {"some-key": "some-value"}
        # and we can also load the file information iterating over the storage
        item = next(new_transfer.iter_key("test_key1", with_metadata=True, include_key=True))
        assert item.type == KEY_TYPE_OBJECT
        result = item.value
        assert isinstance(result, dict)

        hasher = hashlib.sha256()
        hasher.update(expected_data)
        md5 = hasher.hexdigest()
        expected_value = {
            "md5": md5,
            "name": "test_key1",
            "size": len(expected_data),
            "metadata": {"some-key": "some-value"},
        }
        last_modified = result.pop("last_modified")
        assert last_modified is not None
        assert result == expected_value
