"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
from googleapiclient.http import MediaUploadProgress
from io import BytesIO
from rohmu.common.models import StorageOperation
from rohmu.errors import InvalidByteRangeError
from rohmu.object_storage.base import IterKeyItem
from rohmu.object_storage.google import GoogleTransfer, MediaIoBaseDownloadWithByteRange, Reporter
from tempfile import NamedTemporaryFile
from unittest.mock import ANY, call, MagicMock, Mock, patch

import base64
import pytest


def test_store_file_from_memory() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer.get_or_create_bucket"))
        upload = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._upload"))
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        test_data = b"test-data"
        metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
        upload.return_value = {"size": len(test_data)}  # server reports the size of the uploaded object
        transfer.store_file_from_memory("test_key1", memstring=test_data, metadata=metadata)

        upload.assert_called()
        notifier.object_created.assert_called_once_with(
            key="test_key1", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
        )


def test_store_file_from_disk() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer.get_or_create_bucket"))
        upload = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._upload"))

        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        test_data = b"test-data"
        metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
        upload.return_value = {"size": len(test_data)}  # server reports the size of the uploaded object
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(test_data)
            tmpfile.flush()
            transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name, metadata=metadata)

        upload.assert_called()
        notifier.object_created.assert_called_once_with(
            key="test_key1", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
        )


def test_store_file_object() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer.get_or_create_bucket"))
        upload = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._upload"))
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        test_data = b"test-data"
        metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}

        file_object = BytesIO(test_data)
        upload.return_value = {"size": len(test_data)}  # server reports the size of the uploaded object

        transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata)

        upload.assert_called()
        notifier.object_created.assert_called_once_with(
            key="test_key2", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
        )


def test_upload_size_unknown_to_reporter() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer.get_or_create_bucket"))
        mock_retry = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._retry_on_reset"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._object_client"))
        mock_operation = stack.enter_context(patch("rohmu.common.statsd.StatsClient.operation"))
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )

        counts = [1, 5, 994]
        mock_retry.side_effect = [
            (MediaUploadProgress(counts[0], -1), None),
            (MediaUploadProgress(counts[1], -1), None),
            (None, {"size": sum(counts)}),
        ]

        # pylint: disable=protected-access
        transfer._upload(
            upload=MagicMock(),
            key="testkey",
            metadata={},
            extra_props=None,
            cache_control=None,
            reporter=Reporter(StorageOperation.store_file),
        )
        assert mock_operation.call_count == 3
        mock_operation.assert_has_calls(
            [
                call(operation=StorageOperation.store_file, size=1),
                call(operation=StorageOperation.store_file, size=4),
                call(operation=StorageOperation.store_file, size=995),
            ]
        )


def test_get_contents_to_fileobj_raises_error_on_invalid_byte_range() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer.get_or_create_bucket"))
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        with pytest.raises(InvalidByteRangeError):
            transfer.get_contents_to_fileobj(
                key="testkey",
                fileobj_to_store_to=BytesIO(),
                byte_range=(100, 10),
            )


def _mock_request(calls: list[tuple[str, bytes]]) -> Mock:
    results = []
    for call_content_range, call_content in calls:
        response = Mock()
        response.status = 206
        response.headers = {
            "content-range": call_content_range,
        }
        response.__getitem__ = lambda self, key: self.headers[key]
        response.__contains__ = lambda self, key: key in self.headers
        results.append((response, call_content))
    http_call = Mock(side_effect=lambda *args, **kwargs: results.pop(0))
    request = Mock()
    request.headers = {}
    request.http.request = http_call
    return request


def test_media_io_download_with_byte_range() -> None:
    mock_request = _mock_request([("3-8/13", b"lo, Wo")])
    result = BytesIO()
    download = MediaIoBaseDownloadWithByteRange(result, mock_request, byte_range=(3, 8))
    status, done = download.next_chunk()
    assert done
    assert status.progress() == 1.0
    assert result.getvalue() == b"lo, Wo"
    mock_request.http.request.assert_called_once_with(ANY, ANY, headers={"range": "bytes=3-8"})


def test_media_io_download_with_byte_range_and_tiny_chunks() -> None:
    mock_request = _mock_request([("3-5/13", b"lo,"), ("6-8/13", b" Wo"), ("9-10/13", b"rl")])
    result = BytesIO()
    download = MediaIoBaseDownloadWithByteRange(result, mock_request, chunksize=3, byte_range=(3, 10))
    status, done = download.next_chunk()
    assert not done
    assert status.progress() == 0.375
    assert result.getvalue() == b"lo,"

    status, done = download.next_chunk()
    assert not done
    assert status.progress() == 0.750
    assert result.getvalue() == b"lo, Wo"

    status, done = download.next_chunk()
    assert done
    assert status.progress() == 1.0
    assert result.getvalue() == b"lo, Worl"

    mock_request.http.request.assert_has_calls(
        [
            call(ANY, ANY, headers={"range": "bytes=3-5"}),
            call(ANY, ANY, headers={"range": "bytes=6-8"}),
            call(ANY, ANY, headers={"range": "bytes=9-10"}),
        ]
    )


def test_media_io_download_with_byte_range_and_very_small_object() -> None:
    mock_request = _mock_request([("3-13/13", b"lo, World!")])
    result = BytesIO()
    download = MediaIoBaseDownloadWithByteRange(result, mock_request, byte_range=(3, 100))
    status, done = download.next_chunk()
    assert done
    assert status.progress() == 1.0
    assert result.getvalue() == b"lo, World!"
    mock_request.http.request.assert_called_once_with(ANY, ANY, headers={"range": "bytes=3-100"})


def test_object_listed_when_missing_md5hash_size_and_updated() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer.get_or_create_bucket"))
        mock_operation = stack.enter_context(patch("rohmu.common.statsd.StatsClient.operation"))
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )

        # mock instance because there is decorator and context managers in the way
        mock_client = stack.enter_context(patch.object(transfer, "_object_client"))
        mock_client.return_value.__enter__.return_value.list_next.return_value = None
        object_name = (
            "aiventest/111aa1aa-1aaa-1111-11a1-11111aaaaa11/a1111111-aaa1-1aaa-aa1a-1a11aaaa11a1"
            "/tiered_storage/ccs/aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        escaped_name = object_name.replace("/", "%2F")

        # API response missing size, updated & md5Hash fields
        sample_item = {
            "bucket": "test-bucket",
            "contentType": "binary/octet-stream",
            "generation": "1111111111111111",
            "id": f"test-bucket/{object_name}/1111111111111111",
            "kind": "storage#object",
            "mediaLink": f"https://storage.googleapis.com/download/storage/v1/b/test-bucket/o/"
            f"{escaped_name}?generation=1111111111111111&alt=media",
            "metageneration": "1",
            "name": object_name,
            "selfLink": f"https://www.googleapis.com/storage/v1/b/"
            f"p812de5da-0bab-4990-90e8-57303eebfd30-99012089cf1d961516b8b3ff6/o/"
            f"{escaped_name}?generation=1111111111111111",
            "storageClass": "REGIONAL",
        }
        mock_client.return_value.__enter__.return_value.list.return_value.execute.return_value = {
            "items": [
                sample_item,
                {"size": 100, **sample_item},
                {"md5Hash": base64.encodebytes(b"Missing md5Hash!"), **sample_item},
                {"updated": "2023-11-20T16:18:00+00:00", **sample_item},
            ]
        }

        got = list(
            transfer.iter_key(
                key="testkey",
                with_metadata=False,
                deep=True,
                include_key=False,
            )
        )
        assert mock_operation.call_count == 1
        mock_operation.assert_has_calls(
            [
                call(operation=StorageOperation.iter_key),
            ]
        )
        expected = [
            IterKeyItem(type="object", value={"name": object_name, "metadata": {}}),
            IterKeyItem(type="object", value={"name": object_name, "metadata": {}, "size": 100}),
            IterKeyItem(
                type="object", value={"name": object_name, "metadata": {}, "md5": "4d697373696e67206d64354861736821"}
            ),
            IterKeyItem(
                type="object",
                value={
                    "name": object_name,
                    "metadata": {},
                    "last_modified": datetime(2023, 11, 20, 16, 18, tzinfo=timezone.utc),
                },
            ),
        ]
        assert len(got) == len(expected)
        assert got == expected
