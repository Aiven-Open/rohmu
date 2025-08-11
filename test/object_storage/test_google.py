# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
from googleapiclient.errors import HttpError
from googleapiclient.http import HttpRequest, MediaUploadProgress
from io import BytesIO
from rohmu import InvalidConfigurationError
from rohmu.common.models import StorageOperation
from rohmu.errors import InvalidByteRangeError, TransferObjectStoreMissingError, TransferObjectStorePermissionError
from rohmu.object_storage.base import IterKeyItem
from rohmu.object_storage.google import GoogleTransfer, MediaIoBaseDownloadWithByteRange, Reporter
from tempfile import NamedTemporaryFile
from typing import Any, Callable, Optional, Union
from unittest.mock import ANY, call, MagicMock, Mock, patch

import base64
import googleapiclient.errors
import httplib2
import pytest


class MockCredentials:
    def __init__(self, expired: bool = False, token: str = "mock-token") -> None:
        self.universe_domain = "googleapis.com"
        self.token = token
        self.expired = expired
        self.refresh_called = False

    def refresh(self, request: Any) -> None:
        """Mock refresh method for credential refreshing tests."""
        self.refresh_called = True
        self.expired = False
        self.token = "refreshed-token"

    def apply(self, headers: dict[str, str], token: Optional[str] = None) -> None:
        """Mock apply method for applying credentials to headers."""
        headers["Authorization"] = f"Bearer {token or self.token}"


def test_close() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
        mock_gs = Mock()
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._init_google_client", return_value=mock_gs))
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=MagicMock(),
        )
        assert transfer.gs is not None
        with transfer._object_client():
            assert transfer.gs_object_client is not None
        transfer.close()
        mock_gs.close.assert_called_once()
        assert transfer.gs_object_client is None
        assert transfer.gs is None


def _mock_403_response_from_google_api() -> Exception:
    resp = httplib2.Response({"status": "403", "reason": "Unused"})
    uri = "https://storage.googleapis.com/storage/v1/b?project=project&alt=json"
    content = (
        b'{\n  "error": {\n    "code": 403,\n    "message": "account@project.iam.gserviceaccount.com does not have stor'
        b"age.buckets.create access to the Google Cloud project. Permission 'storage.buckets.create' denied on resource "
        b'(or it may not exist).",\n    "errors": [\n      {\n        "message": "account@project.iam.gserviceaccount.com '
        b"does not have storage.buckets.create access to the Google Cloud project. Permission 'storage.buckets.create' "
        b'denied on resource (or it may not exist).",\n        "domain": "global",\n        "reason": "forbidden"'
        b"\n      }\n    ]\n  }\n}\n"
    )
    return googleapiclient.errors.HttpError(resp, content, uri)


def _mock_404_response_from_google_api() -> Exception:
    resp = httplib2.Response({"status": "404", "reason": "Unused"})
    uri = "https://storage.googleapis.com/storage/v1/b?project=project&alt=json"
    content = b"""{"error": {"code": 404, "message": "Does not matter"}}"""
    return googleapiclient.errors.HttpError(resp, content, uri)


@pytest.mark.parametrize(
    "ensure_object_store_available,bucket_exists,sabotage_create,expect_create_call",
    [
        # Happy path
        pytest.param(True, True, False, False, id="happy-path-exists"),
        pytest.param(True, False, False, True, id="happy-path-not-exists"),
        # Happy path - without attempting to create buckets
        pytest.param(False, True, False, False, id="no-create-exists"),
        pytest.param(False, False, False, False, id="no-create-not-exists"),
        # 403 failures when trying to create should not matter with ensure_object_store_available=False
        pytest.param(False, False, True, False, id="error-behaviour"),
        # 403 failures when trying to create should crash with ensure_object_store_available=False
        pytest.param(True, False, True, True, id="graceful-403-handling"),
    ],
)
def test_handle_missing_bucket(
    ensure_object_store_available: bool, bucket_exists: bool, sabotage_create: bool, expect_create_call: bool
) -> None:
    """
    As part of having nicer exception handling for bucket initialization, we need to make sure the behaviour is unchanged
    when the backwards-compatibility-flag ensure_object_store_available is set.
    """
    # Sanity check: We expect a call to the create function when in "legacy mode" and the bucket is missing
    assert expect_create_call == (ensure_object_store_available and not bucket_exists)

    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))

        _try_get_bucket = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._try_get_bucket"))
        if not bucket_exists:
            # If the bucket exists, the return value is ignored. This simulates a missing bucket.
            _try_get_bucket.side_effect = _mock_404_response_from_google_api()

        _try_create_bucket = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._try_create_bucket"))
        if sabotage_create:
            _try_create_bucket.side_effect = _mock_403_response_from_google_api()

        if expect_create_call and sabotage_create:
            with pytest.raises(googleapiclient.errors.HttpError):
                _ = GoogleTransfer(
                    project_id="test-project-id",
                    bucket_name="test-bucket",
                    ensure_object_store_available=ensure_object_store_available,
                )
        else:
            GoogleTransfer(
                project_id="test-project-id",
                bucket_name="test-bucket",
                ensure_object_store_available=ensure_object_store_available,
            )

        if ensure_object_store_available:
            _try_get_bucket.assert_called_once()
        else:
            _try_get_bucket.assert_not_called()

        if expect_create_call:
            _try_create_bucket.assert_called_once()
        else:
            _try_create_bucket.assert_not_called()


def test_store_file_from_memory() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
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
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
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
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
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


def _generate_keys(total: int, prefix: str = "test_key_") -> list[str]:
    return [f"{prefix}{i+1}" for i in range(total)]


def test_upload_size_unknown_to_reporter() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
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
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
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


def _mock_request(calls: list[tuple[str, bytes]], resumable: bool | None = None) -> Mock:
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
    request.resumable = resumable
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
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
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


def test_error_handling() -> None:
    with patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()):
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            ensure_object_store_available=False,
        )

        with patch("rohmu.object_storage.google.GoogleTransfer._try_get_bucket") as _try_get_bucket:
            # Unexpected exceptions bubble up
            _try_get_bucket.side_effect = RuntimeError("Bad unexpected error")
            with pytest.raises(RuntimeError, match="Bad unexpected error"):
                transfer.verify_object_storage()

            # Bucket not found is wrapped with our own exception
            _try_get_bucket.side_effect = _mock_404_response_from_google_api()
            with pytest.raises(TransferObjectStoreMissingError):
                transfer.verify_object_storage()

            # Permission error when checking for bucket existence is also our own exception...
            _try_get_bucket.side_effect = _mock_403_response_from_google_api()
            with pytest.raises(TransferObjectStorePermissionError):
                transfer.verify_object_storage()

        with ExitStack() as stack:
            _try_get_bucket = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._try_get_bucket"))
            _try_create_bucket = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._try_create_bucket"))
            # ... and the legacy behaviour of raising InvalidConfigurationError should not regress
            _try_get_bucket.side_effect = _mock_403_response_from_google_api()
            with pytest.raises(InvalidConfigurationError):
                transfer._create_object_store_if_needed_unwrapped()
            _try_create_bucket.assert_not_called()

        with ExitStack() as stack:
            _try_get_bucket = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._try_get_bucket"))
            _try_create_bucket = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._try_create_bucket"))
            # Simulate a missing bucket to make it attempt to create
            _try_get_bucket.side_effect = _mock_404_response_from_google_api()

            # Unexpected exceptions bubble up
            _try_create_bucket.side_effect = RuntimeError("Bad unexpected error")
            with pytest.raises(RuntimeError, match="Bad unexpected error"):
                transfer.create_object_store_if_needed()

            # Permission errors when trying to create the bucket is wrapped with our own exception
            _try_create_bucket.side_effect = _mock_403_response_from_google_api()
            with pytest.raises(TransferObjectStorePermissionError):
                transfer.create_object_store_if_needed()

            # ... and the legacy behaviour of bubbling up should not regress
            with pytest.raises(HttpError, match="403"):
                transfer._create_object_store_if_needed_unwrapped()


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
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
        _init_google_client_mock = stack.enter_context(
            patch("rohmu.object_storage.google.GoogleTransfer._init_google_client")
        )

        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            prefix="test-prefix/",
            notifier=notifier,
        )
        if preserve_trailing_slash is None:
            transfer.delete_key(key)
        else:
            transfer.delete_key(key, preserve_trailing_slash=preserve_trailing_slash)

        mock_client_delete = _init_google_client_mock.return_value.objects().delete
        mock_client_delete.assert_has_calls(
            [
                call(bucket="test-bucket", object=expected_key),
                call().execute(),
            ]
        )


@pytest.mark.parametrize("preserve_trailing_slash", [True, False, None])
def test_delete_keys_trailing_slash(preserve_trailing_slash: Union[bool, None]) -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
        _init_google_client_mock = stack.enter_context(
            patch("rohmu.object_storage.google.GoogleTransfer._init_google_client")
        )

        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            prefix="test-prefix/",
            notifier=notifier,
        )
        if preserve_trailing_slash is None:
            transfer.delete_keys(["2", "3", "4/"])
        else:
            transfer.delete_keys(["2", "3", "4/"], preserve_trailing_slash=preserve_trailing_slash)

        mock_client_delete = _init_google_client_mock.return_value.objects().delete

        expected_keys = ["2", "3", "4"] if not preserve_trailing_slash else ["2", "3", "4/"]
        expected_calls = []
        for key in expected_keys:
            expected_calls.extend(
                [
                    call(bucket="test-bucket", object=f"test-prefix/{key}"),
                ]
            )
        mock_client_delete.assert_has_calls(expected_calls)


@pytest.mark.parametrize(
    ("total_keys,expected_bulk_request_count"),
    (
        (0, 0),
        (1, 1),
        (100, 1),
        (101, 2),
        (200, 2),
        (201, 3),
        (1_000, 10),
    ),
)
def test_delete_keys_bulk(total_keys: int, expected_bulk_request_count: int) -> None:
    notifier = MagicMock()
    test_keys = _generate_keys(total_keys)
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
        mock_retry_on_reset = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._retry_on_reset"))
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        mock_client = stack.enter_context(patch.object(transfer, "_object_client"))
        mock_request = _mock_request([], resumable=None)
        mock_client.return_value.__enter__.return_value.delete.return_value = mock_request

        transfer.delete_keys(keys=test_keys)

        assert mock_retry_on_reset.call_count == expected_bulk_request_count


class BatchRequestProcessor:
    def __init__(self, callback: Callable[[str, HttpRequest | None, HttpError | None], None]) -> None:
        self.callback = callback
        self.operations: list[str] = []

    def execute(self) -> None:
        for key in self.operations:
            if "500" in key:
                self.callback(key, None, HttpError(resp=httplib2.Response({"status": "500"}), content=b"500"))
                return
            if "404" in key:
                self.callback(key, None, HttpError(resp=httplib2.Response({"status": "404"}), content=b"404"))
                return
            self.callback(key, None, None)

    def add(self, operation: HttpRequest, request_id: str) -> None:
        self.operations.append(request_id)


def test_delete_keys_callback() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
        mock_delete_key = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer.delete_key"))

        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )

        mock_batch_request = MagicMock()
        mock_batch_request.execute.return_value = None

        test_keys = ["key1", "key2", "key3_500"]

        mock_gs = MagicMock()
        mock_gs.new_batch_http_request = lambda callback: BatchRequestProcessor(callback)
        transfer.gs = mock_gs

        transfer.delete_keys(keys=test_keys)

        notifier.object_deleted.assert_has_calls([call("key1"), call("key2")])
        mock_delete_key.assert_called_once_with("key3_500", preserve_trailing_slash=False)


def test_delete_keys_callback_failure() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=MockCredentials()))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
        mock_delete_key = stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer.delete_key"))

        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )

        test_keys = ["key1", "key2", "key3_404"]

        mock_gs = MagicMock()
        mock_gs.new_batch_http_request = lambda callback: BatchRequestProcessor(callback)
        transfer.gs = mock_gs

        with pytest.raises(HttpError) as exc_info:
            transfer.delete_keys(keys=test_keys)

        assert exc_info.value.resp["status"] == "404"

        notifier.object_deleted.assert_has_calls([call("key1"), call("key2")])
        mock_delete_key.assert_not_called()


def test_google_transfer_initialization_with_credentials() -> None:
    """Test GoogleTransfer initialization with different credential types."""
    with ExitStack() as stack:
        mock_creds = MockCredentials()
        get_creds_mock = stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=mock_creds))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._init_google_client"))

        # Test with credentials dict
        creds_dict = {"type": "service_account", "project_id": "test"}
        transfer = GoogleTransfer(
            project_id="test-project-id", bucket_name="test-bucket", notifier=MagicMock(), credentials=creds_dict
        )

        get_creds_mock.assert_called_with(credential_file=None, credentials=creds_dict)
        assert transfer.google_creds is mock_creds


def test_google_transfer_initialization_with_credential_file() -> None:
    """Test GoogleTransfer initialization with credential file."""
    from tempfile import NamedTemporaryFile

    import json

    creds_data = {"type": "service_account", "project_id": "test"}

    with ExitStack() as stack:
        mock_creds = MockCredentials()
        get_creds_mock = stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=mock_creds))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._init_google_client"))

        with NamedTemporaryFile(mode="w", delete=False) as f:
            json.dump(creds_data, f)
            credential_file_path = f.name

        try:
            with open(credential_file_path) as cred_file:
                transfer = GoogleTransfer(
                    project_id="test-project-id", bucket_name="test-bucket", notifier=MagicMock(), credential_file=cred_file
                )

            # Should be called with opened file
            get_creds_mock.assert_called_once()
            call_args = get_creds_mock.call_args
            assert call_args[1]["credentials"] is None
            assert call_args[1]["credential_file"] is not None
            assert transfer.google_creds is mock_creds
        finally:
            import os

            os.unlink(credential_file_path)


def test_google_transfer_http_authorization() -> None:
    """Test that HTTP requests are properly authorized with new auth library."""
    with ExitStack() as stack:
        mock_creds = MockCredentials()
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=mock_creds))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))

        mock_http = Mock()
        mock_http.redirect_codes = {301, 302, 303, 307}  # Add redirect_codes attribute
        mock_authorized_http = Mock()

        # Mock the google_auth_httplib2.AuthorizedHttp
        auth_http_mock = stack.enter_context(patch("rohmu.object_storage.google.google_auth_httplib2.AuthorizedHttp"))
        auth_http_mock.return_value = mock_authorized_http

        # Mock httplib2.Http
        http_mock = stack.enter_context(patch("rohmu.object_storage.google.httplib2.Http"))
        http_mock.return_value = mock_http

        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=MagicMock(),
        )

        # Initialize the client to trigger HTTP setup
        with patch("rohmu.object_storage.google.build") as build_mock:
            transfer._init_google_client()

            # Verify AuthorizedHttp was called with our credentials and http instance
            auth_http_mock.assert_called_with(mock_creds, http=mock_http)

            # Verify the authorized HTTP was passed to the API client
            build_mock.assert_called_once()
            call_args = build_mock.call_args
            assert call_args[1]["http"] is mock_authorized_http


def test_google_transfer_proxy_configuration() -> None:
    """Test that proxy configuration works with the new auth setup."""
    with ExitStack() as stack:
        mock_creds = MockCredentials()
        stack.enter_context(patch("rohmu.object_storage.google.get_credentials", return_value=mock_creds))
        stack.enter_context(patch("rohmu.object_storage.google.GoogleTransfer._create_object_store_if_needed_unwrapped"))

        proxy_info: dict[str, Union[str, int]] = {
            "host": "proxy.example.com",
            "port": 8080,
            "user": "proxyuser",
            "pass": "proxypass",
        }

        mock_http = Mock()
        mock_http.redirect_codes = {301, 302, 303, 307}  # Add redirect_codes attribute
        mock_authorized_http = Mock()

        auth_http_mock = stack.enter_context(patch("rohmu.object_storage.google.google_auth_httplib2.AuthorizedHttp"))
        auth_http_mock.return_value = mock_authorized_http

        # Mock build_http instead of httplib2.Http directly
        build_http_mock = stack.enter_context(patch("rohmu.object_storage.google.build_http"))
        build_http_mock.return_value = mock_http

        proxy_info_mock = stack.enter_context(patch("rohmu.object_storage.google.httplib2.ProxyInfo"))

        transfer = GoogleTransfer(
            project_id="test-project-id", bucket_name="test-bucket", notifier=MagicMock(), proxy_info=proxy_info
        )

        with patch("rohmu.object_storage.google.build"):
            transfer._init_google_client()

            # Verify proxy was configured - ProxyInfo uses positional args for the first 3 parameters
            proxy_info_mock.assert_called_with(
                httplib2.socks.PROXY_TYPE_HTTP,  # type: ignore[attr-defined]  # proxy_type as positional arg
                "proxy.example.com",  # proxy_host as positional arg
                8080,  # proxy_port as positional arg
                proxy_user="proxyuser",
                proxy_pass="proxypass",
            )

            # Verify build_http was called to create the initial HTTP client
            assert build_http_mock.call_count >= 1

            # Verify the proxy_info was set on the HTTP object
            assert mock_http.proxy_info == proxy_info_mock.return_value

            # Verify AuthorizedHttp was called with credentials and http object
            auth_http_mock.assert_called_with(mock_creds, http=mock_http)  # Verify the HTTP client was properly authorized
            auth_http_mock.assert_called_with(mock_creds, http=mock_http)
