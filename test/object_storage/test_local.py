# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from io import BytesIO
from itertools import cycle
from rohmu.errors import Error, FileNotFoundFromStorageError, InvalidByteRangeError
from rohmu.object_storage.base import KEY_TYPE_OBJECT
from rohmu.object_storage.local import LocalTransfer
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Union
from unittest.mock import MagicMock

import glob
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

        with open(os.path.join(destdir, "test_key1"), "rb") as key1_file_handler:
            assert key1_file_handler.read() == test_data
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

        with open(os.path.join(destdir, "test_key2"), "rb") as key2_file_handler:
            assert key2_file_handler.read() == test_data
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
        with open(metadata_file, "w", encoding="utf-8") as metadata_fp:
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
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
        )
        upload = transfer.create_concurrent_upload(key="test_key1", metadata={"some-key": "some-value"})
        # should end up with b"Hello, World!\nHello, World!"
        expected_data = b"Hello, World!\nHello, World!"
        transfer.upload_concurrent_chunk(upload, 3, BytesIO(b"Hello"))
        transfer.upload_concurrent_chunk(upload, 4, BytesIO(b", "))
        transfer.upload_concurrent_chunk(upload, 1, BytesIO(b"Hello, World!"))
        transfer.upload_concurrent_chunk(upload, 7, BytesIO(b"!"))
        transfer.upload_concurrent_chunk(upload, 2, BytesIO(b"\n"))
        transfer.upload_concurrent_chunk(upload, 6, BytesIO(b"ld"))
        transfer.upload_concurrent_chunk(upload, 5, BytesIO(b"Wor"))

        # we don't see the temporary files created during upload
        assert transfer.list_prefixes(key="/") == []
        assert transfer.list_path(key="/", deep=True) == []
        assert os.path.exists(os.path.join(destdir, f".concurrent_upload_{upload.backend_id}"))

        transfer.complete_concurrent_upload(upload)

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
        # we don't leave around spurious temporary files
        assert not os.path.exists(os.path.join(destdir, f".concurrent_upload_{upload}"))


def test_can_upload_files_concurrently_with_threads() -> None:
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
        )
        upload = transfer.create_concurrent_upload(key="test_key1", metadata={"some-key": "some-value"})
        # should end up with b"Hello, World!\nHello, World!"
        expected_data = b"Hello, World!\nHello, World!"

        with ThreadPoolExecutor() as pool:
            pool.map(
                partial(transfer.upload_concurrent_chunk, upload),
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

        transfer.complete_concurrent_upload(upload)

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


def test_can_upload_files_concurrently_with_threads_using_different_transfer_instances() -> None:
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        first_transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
        )
        second_transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
        )
        upload = first_transfer.create_concurrent_upload(key="test_key1", metadata={"some-key": "some-value"})
        # should end up with b"Hello, World!\nHello, World!"
        expected_data = b"Hello, World!\nHello, World!"

        with ThreadPoolExecutor() as pool:
            data_chunks = [
                BytesIO(b"Hello"),
                BytesIO(b", "),
                BytesIO(b"Hello, World!"),
                BytesIO(b"!"),
                BytesIO(b"\n"),
                BytesIO(b"ld"),
                BytesIO(b"Wor"),
            ]
            futures = []
            for i, data, transfer in zip([3, 4, 1, 7, 2, 6, 5], data_chunks, cycle([first_transfer, second_transfer])):
                futures.append(pool.submit(partial(transfer.upload_concurrent_chunk, upload), i, data))
            for future in futures:
                future.result()
        first_transfer.complete_concurrent_upload(upload)

        # we can read the metadata
        assert first_transfer.get_metadata_for_key("test_key1") == {"some-key": "some-value"}
        # and we can also load the file information iterating over the storage
        item = next(first_transfer.iter_key("test_key1", with_metadata=True, include_key=True))
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


def test_upload_files_concurrently_can_be_aborted() -> None:
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
        )
        upload = transfer.create_concurrent_upload(key="test_key1", metadata={"some-key": "some-value"})

        total = 0

        def inc_progress(size: int) -> None:
            nonlocal total
            total += size

        # should end up with b"Hello, World!\nHello, World!"
        transfer.upload_concurrent_chunk(upload, 3, BytesIO(b"Hello"), upload_progress_fn=inc_progress)
        transfer.upload_concurrent_chunk(upload, 4, BytesIO(b", "), upload_progress_fn=inc_progress)
        transfer.upload_concurrent_chunk(upload, 1, BytesIO(b"Hello, World!"), upload_progress_fn=inc_progress)
        transfer.upload_concurrent_chunk(upload, 7, BytesIO(b"!"), upload_progress_fn=inc_progress)
        transfer.upload_concurrent_chunk(upload, 2, BytesIO(b"\n"), upload_progress_fn=inc_progress)
        transfer.upload_concurrent_chunk(upload, 6, BytesIO(b"ld"), upload_progress_fn=inc_progress)
        transfer.upload_concurrent_chunk(upload, 5, BytesIO(b"Wor"), upload_progress_fn=inc_progress)
        transfer.abort_concurrent_upload(upload)

        assert total == 27

        # we should not be able to find this
        with pytest.raises(FileNotFoundFromStorageError):
            transfer.get_metadata_for_key("test_key1")


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
def test_delete_key(key: str, preserve_trailing_slash: Union[bool, None], expected_key: str) -> None:
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
            prefix="test-prefix/",
        )

        transfer.store_file_from_memory(key, memstring=b"Hello")
        found_files = glob.glob(os.path.join(destdir, "test-prefix", "*"))
        # ensure we have created some files
        assert found_files
        if preserve_trailing_slash:
            with pytest.raises(Error):
                transfer.delete_key(key, preserve_trailing_slash=True)
        else:
            if preserve_trailing_slash is None:
                transfer.delete_key(key)
            else:
                transfer.delete_key(key, preserve_trailing_slash=preserve_trailing_slash)

            # all files got deleted
            found_files = glob.glob(os.path.join(destdir, "test-prefix", "*"))
            assert not found_files


@pytest.mark.parametrize("preserve_trailing_slash", [True, False, None])
def test_delete_keys(preserve_trailing_slash: Union[bool, None]) -> None:
    with TemporaryDirectory() as destdir:
        notifier = MagicMock()
        transfer = LocalTransfer(
            directory=destdir,
            notifier=notifier,
            prefix="test-prefix/",
        )

        transfer.store_file_from_memory("2", memstring=b"Hello")
        transfer.store_file_from_memory("3", memstring=b"Hello")
        transfer.store_file_from_memory("4/", memstring=b"Hello")
        found_files = glob.glob(os.path.join(destdir, "test-prefix", "*"))
        # ensure we have created some files
        assert found_files
        if preserve_trailing_slash:
            with pytest.raises(Error):
                transfer.delete_keys(["2", "3", "4/"], preserve_trailing_slash=True)
        else:
            if preserve_trailing_slash is None:
                transfer.delete_keys(["2", "3", "4/"])
            else:
                transfer.delete_keys(["2", "3", "4/"], preserve_trailing_slash=preserve_trailing_slash)

            # all files got deleted
            found_files = glob.glob(os.path.join(destdir, "test-prefix", "*"))
            assert not found_files
