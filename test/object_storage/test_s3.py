# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from botocore.response import StreamingBody
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from pydantic.v1 import ValidationError
from rohmu.common.models import StorageOperation
from rohmu.errors import InvalidByteRangeError, StorageError, TransferObjectStoreMissingError
from rohmu.object_storage.base import TransferWithConcurrentUploadSupport
from rohmu.object_storage.config import S3_MAX_NUM_PARTS_PER_UPLOAD, S3ObjectStorageConfig
from rohmu.object_storage.s3 import S3Transfer
from tempfile import NamedTemporaryFile
from typing import Any, BinaryIO, Callable, Iterator, Optional, Union
from unittest.mock import ANY, call, MagicMock, patch

import botocore.exceptions
import contextlib
import pytest
import rohmu.object_storage.s3


@dataclass
class S3Infra:
    notifier: MagicMock
    operation: MagicMock
    s3_client: MagicMock
    transfer: S3Transfer


def make_mock_transfer(mocker: Any, transfer_kwargs: dict[str, Any]) -> S3Transfer:
    notifier = MagicMock()
    s3_client = MagicMock()
    create_client = MagicMock(return_value=s3_client)
    session = MagicMock(create_client=create_client)

    assert all(kwarg in transfer_kwargs for kwarg in ["region", "bucket_name", "prefix"]), "Missing required kwargs"

    @contextlib.contextmanager
    def _get_session(cls: S3Transfer) -> Iterator[MagicMock]:
        yield session

    mocker.patch("rohmu.object_storage.s3.S3Transfer._get_session", _get_session)

    transfer_kwargs["notifier"] = notifier
    transfer = S3Transfer(**transfer_kwargs)
    return transfer


def test_calculate_max_unknown_file_size(mocker: Any) -> None:
    segment_size = 100
    transfer = make_mock_transfer(
        mocker,
        {
            "region": "test-region",
            "bucket_name": "test-bucket",
            "prefix": "test-prefix",
            "segment_size": segment_size,
        },
    )

    assert transfer.calculate_max_unknown_file_size() == segment_size * S3_MAX_NUM_PARTS_PER_UPLOAD


@pytest.fixture(name="infra")
def fixture_infra(mocker: Any) -> Iterator[S3Infra]:
    operation = mocker.patch("rohmu.common.statsd.StatsClient.operation")
    transfer = make_mock_transfer(mocker, {"region": "test-region", "bucket_name": "test-bucket", "prefix": "test-prefix"})
    assert isinstance(transfer.notifier, MagicMock)
    assert isinstance(transfer.s3_client, MagicMock)
    yield S3Infra(transfer.notifier, operation, transfer.s3_client, transfer)


def test_close(infra: S3Infra) -> None:
    infra.transfer.get_client()
    assert infra.transfer.s3_client is not None
    infra.transfer.close()
    assert infra.transfer.s3_client is None
    infra.s3_client.close.assert_called_once()


def test_store_file_from_disk(infra: S3Infra) -> None:
    test_data = b"test-data"
    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    with NamedTemporaryFile() as tmpfile:
        tmpfile.write(test_data)
        tmpfile.flush()
        infra.transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name, metadata=metadata)

    infra.s3_client.put_object.assert_called_once_with(
        Bucket="test-bucket",
        Body=b"test-data",
        Key="test-prefix/test_key1",
        Metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"},
    )
    infra.notifier.object_created.assert_called_once_with(
        key="test_key1", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
    )


def test_store_file_object_large(infra: S3Infra) -> None:
    test_data = b"test-data" * 2
    chunk_size = len(test_data) // 2
    file_object = BytesIO(test_data)

    infra.transfer.default_multipart_chunk_size = chunk_size  # simulate smaller chunk size to force multiple chunks

    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    infra.transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata, multipart=True)

    notifier = infra.notifier
    s3_client = infra.s3_client

    s3_client.create_multipart_upload.assert_called()
    assert s3_client.upload_part.call_count == 2
    s3_client.complete_multipart_upload.assert_called()
    notifier.object_created.assert_called_once_with(
        key="test_key2",
        size=len(test_data),
        metadata={"Content-Length": "18", "some-date": "2022-11-15 18:30:58.486644"},
    )


@pytest.mark.parametrize("multipart", [False, None, True])
def test_store_file_object(infra: S3Infra, multipart: Optional[bool]) -> None:
    test_data = b"test-data"
    file_object = BytesIO(test_data)

    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    infra.transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata, multipart=multipart)

    notifier = infra.notifier
    s3_client = infra.s3_client

    if multipart is True:
        # store_file_object does a multipart upload
        # (if explicitly requested)
        s3_client.create_multipart_upload.assert_called()
        s3_client.upload_part.assert_called()
        s3_client.complete_multipart_upload.assert_called()
        notifier.object_created.assert_called_once_with(
            key="test_key2",
            size=len(test_data),
            metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"},
        )
    else:
        # size was known and it was small enough so default of
        # True won't be used in None case
        s3_client.put_object.assert_called_once_with(
            Bucket="test-bucket",
            Body=b"test-data",
            Key="test-prefix/test_key2",
            Metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"},
        )
        notifier.object_created.assert_called_once_with(
            key="test_key2",
            size=len(test_data),
            metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"},
        )


@pytest.mark.parametrize("has_content_length", [False, True])
def test_store_empty_file_object(infra: S3Infra, has_content_length: bool) -> None:
    metadata = {"Content-Length": "0"} if has_content_length else {}

    infra.transfer.store_file_object(
        key="test_key2",
        fd=BytesIO(b""),
        metadata=metadata,
        multipart=True,
    )
    # never try multipart upload for empty files even if its enforced

    infra.s3_client.create_multipart_upload.assert_not_called()

    called_with: dict[str, str | bytes | dict[str, str]] = {  # help: mypy
        "Bucket": "test-bucket",
        "Body": b"",
        "Key": "test-prefix/test_key2",
    }
    if metadata:
        called_with["Metadata"] = {"Content-Length": "0"}
    infra.s3_client.put_object.assert_called_once_with(**called_with)


def test_operations_reporting(infra: S3Infra) -> None:
    infra.operation.assert_called_once_with(StorageOperation.head_request)


@pytest.mark.parametrize("preserve_trailing_slash", [True, False, None])
def test_delete_keys(infra: S3Infra, preserve_trailing_slash: Union[bool, None]) -> None:
    if preserve_trailing_slash is None:
        infra.transfer.delete_keys(["2", "3", "4/"])
    else:
        infra.transfer.delete_keys(["2", "3", "4/"], preserve_trailing_slash=preserve_trailing_slash)
    infra.s3_client.delete_objects.assert_called_once_with(
        Bucket="test-bucket",
        Delete={
            "Objects": [
                {"Key": "test-prefix/2"},
                {"Key": "test-prefix/3"},
                {"Key": "test-prefix/4/" if preserve_trailing_slash else "test-prefix/4"},
            ],
        },
    )


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
def test_delete_key(infra: S3Infra, key: str, preserve_trailing_slash: Union[bool, None], expected_key: str) -> None:
    if preserve_trailing_slash is None:
        infra.transfer.delete_key(key)
    else:
        infra.transfer.delete_key(key, preserve_trailing_slash=preserve_trailing_slash)
    infra.s3_client.delete_object.assert_called_once_with(Bucket="test-bucket", Key=expected_key)


def test_get_contents_to_fileobj_raises_error_on_invalid_byte_range(infra: S3Infra) -> None:
    transfer = infra.transfer
    with pytest.raises(InvalidByteRangeError):
        transfer.get_contents_to_fileobj(
            key="testkey",
            fileobj_to_store_to=BytesIO(),
            byte_range=(100, 10),
        )


@pytest.mark.parametrize(
    "error",
    [
        botocore.exceptions.IncompleteReadError(actual_bytes=80, expected_bytes=200),
        botocore.exceptions.ReadTimeoutError(endpoint_url="https://example.org"),
    ],
    ids=type,
)
def test_get_contents_to_fileobj_resumes_on_error(infra: S3Infra, error: Exception) -> None:
    transfer = infra.transfer
    body_one = MagicMock()
    body_one.read.side_effect = [b"x" * 80, error]
    body_two = MagicMock()
    body_two.read.side_effect = [b"x" * 120]
    infra.s3_client.get_object.side_effect = [
        {"ContentLength": 200, "Body": body_one, "Metadata": {}},
        {"ContentLength": 120, "Body": body_two, "Metadata": {}},
    ]
    transfer.get_contents_to_fileobj(
        key="testkey",
        fileobj_to_store_to=BytesIO(),
    )
    assert infra.s3_client.get_object.mock_calls == [
        call(Bucket="test-bucket", Key="test-prefix/testkey"),
        call(Bucket="test-bucket", Key="test-prefix/testkey", Range="bytes=80-199"),
    ]


def test_get_contents_to_fileobj_passes_the_correct_range_header(infra: S3Infra) -> None:
    transfer = infra.transfer
    infra.s3_client.get_object.return_value = {
        "Body": StreamingBody(BytesIO(b"value"), 5),
        "ContentLength": 5,
        "Metadata": {},
    }
    transfer.get_contents_to_fileobj(
        key="test_key",
        fileobj_to_store_to=BytesIO(),
        byte_range=(10, 100),
    )
    infra.s3_client.get_object.assert_called_once_with(
        Bucket="test-bucket", Key="test-prefix/test_key", Range="bytes=10-100"
    )


@pytest.mark.parametrize("with_progress", [True, False])
def test_concurrent_upload_complete(infra: S3Infra, with_progress: bool) -> None:
    metadata = {"some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    infra.s3_client.create_multipart_upload.return_value = {"UploadId": "<aws-mpu-id>"}

    def upload_part_side_effect(Body: BinaryIO, **_kwargs: Any) -> dict[str, str]:
        # to check the progress function we need to actually consume the body
        Body.read()
        return {"ETag": "some-etag"}

    infra.s3_client.upload_part.side_effect = upload_part_side_effect
    transfer: TransferWithConcurrentUploadSupport = infra.transfer
    upload = transfer.create_concurrent_upload("test_key", metadata=metadata)

    total_progress = 0
    upload_progress_fn: Optional[Callable[[int], None]] = None
    if with_progress:

        def inc_progress(size: int) -> None:
            nonlocal total_progress
            total_progress += size

        upload_progress_fn = inc_progress

    transfer.upload_concurrent_chunk(upload, 1, BytesIO(b"Hello, "), upload_progress_fn=upload_progress_fn)
    # we can upload chunks in non-monotonically increasing order
    transfer.upload_concurrent_chunk(upload, 3, BytesIO(b"!"), upload_progress_fn=upload_progress_fn)
    transfer.upload_concurrent_chunk(upload, 2, BytesIO(b"World"), upload_progress_fn=upload_progress_fn)
    transfer.complete_concurrent_upload(upload)

    notifier = infra.notifier
    s3_client = infra.s3_client

    s3_client.create_multipart_upload.assert_called()
    s3_client.upload_part.assert_has_calls(
        [
            call(
                Bucket=infra.transfer.bucket_name,
                Key="test-prefix/test_key",
                UploadId="<aws-mpu-id>",
                PartNumber=part_number,
                Body=ANY,
            )
            for part_number in (1, 3, 2)
        ]
    )
    s3_client.complete_multipart_upload.assert_called_once_with(
        Bucket=infra.transfer.bucket_name,
        Key="test-prefix/test_key",
        MultipartUpload={"Parts": [{"ETag": "some-etag", "PartNumber": part} for part in (1, 2, 3)]},
        UploadId="<aws-mpu-id>",
        RequestPayer="requester",
    )

    # currently we do NOT notify object creation. To notify we really need the size
    notifier.object_created.assert_not_called()

    if with_progress:
        assert total_progress == 13


def test_concurrent_upload_abort(infra: S3Infra) -> None:
    infra.s3_client.create_multipart_upload.return_value = {"UploadId": "<aws-mpu-id>"}
    transfer = infra.transfer
    upload = transfer.create_concurrent_upload("test_key")
    transfer.upload_concurrent_chunk(upload, 1, BytesIO(b"Hello, "))
    transfer.abort_concurrent_upload(upload)

    notifier = infra.notifier
    s3_client = infra.s3_client

    s3_client.create_multipart_upload.assert_called()
    s3_client.upload_part.assert_called()
    s3_client.complete_multipart_upload.assert_not_called()
    s3_client.abort_multipart_upload.assert_called()

    # no notification is sent
    notifier.object_created.assert_not_called()


def test_validate_is_verify_tls_and_cert_path() -> None:
    with pytest.raises(ValidationError) as e:
        S3ObjectStorageConfig(
            region="test-region",
            bucket_name="test-bucket",
            cert_path=Path("test_cert_path"),
            aws_secret_access_key=None,
            aws_session_token=None,
        )
    assert "cert_path is set but is_verify_tls is False" in str(e.value)


@pytest.mark.parametrize(
    "is_verify_tls,cert_path,expected",
    [
        (True, Path("a_path"), "a_path"),
        (True, None, True),
        (False, None, False),
    ],
)
def test_cert_path(is_verify_tls: bool, cert_path: Optional[Path], expected: Union[str, bool]) -> None:
    with patch.object(rohmu.object_storage.s3, "create_s3_client") as mock:
        S3Transfer(
            region="test-region",
            bucket_name="test-bucket",
            cert_path=cert_path,
            is_verify_tls=is_verify_tls,
            host="host",
            port=1000,
        )
        mock.assert_called_once()
        assert mock.call_args[1]["verify"] == expected


def mb_to_bytes(size: int) -> int:
    return size * 1024 * 1024


@dataclass(frozen=True)
class TransferMinMultipartChunkSizeTestData:
    description: str
    size: int | None
    segment_size: int
    min_multipart_chunk_size: int | None
    expected_chunks: int
    expected_chunk_size: int


TEST_TRANSFER_MIN_MULTIPART_CHUNK_SIZE = [
    TransferMinMultipartChunkSizeTestData(
        description="For a 100 MB file, on a system with ~4 GB of RAM, default chunk size is 9 MB, "
        "we expect 12 chunks of 9 MB each",
        size=mb_to_bytes(100),
        segment_size=mb_to_bytes(9),
        min_multipart_chunk_size=None,
        expected_chunks=12,
        expected_chunk_size=mb_to_bytes(9),
    ),
    TransferMinMultipartChunkSizeTestData(
        description="Same as above, but min_multipart_chunk_size is set to 50 MB, " "we expect only 2 chunks of 50 MB each",
        size=mb_to_bytes(100),
        segment_size=mb_to_bytes(9),
        min_multipart_chunk_size=mb_to_bytes(50),
        expected_chunks=2,
        expected_chunk_size=mb_to_bytes(50),
    ),
    TransferMinMultipartChunkSizeTestData(
        description="for a 150 GB file, on a system with ~4 GB of RAM, default chunk size is 9 MB,"
        "we expect the chunk size to be 15 MB to fit the file size in 10000 chunks",
        size=mb_to_bytes(150_000),
        segment_size=mb_to_bytes(9),
        min_multipart_chunk_size=None,
        expected_chunks=S3_MAX_NUM_PARTS_PER_UPLOAD,
        expected_chunk_size=mb_to_bytes(15),
    ),
    TransferMinMultipartChunkSizeTestData(
        description="same as above but min_multipart_chunk_size is set to 50 MB, we expect 3000 chunks of 50 MB each",
        size=mb_to_bytes(150_000),
        segment_size=mb_to_bytes(9),
        min_multipart_chunk_size=mb_to_bytes(50),
        expected_chunks=3000,
        expected_chunk_size=mb_to_bytes(50),
    ),
    TransferMinMultipartChunkSizeTestData(
        description="When size is unknown, we expect the chunk size to be the max between "
        "segment_size & min_multipart_chunk_size",
        size=None,
        segment_size=mb_to_bytes(9),
        min_multipart_chunk_size=mb_to_bytes(50),
        expected_chunks=1,
        expected_chunk_size=mb_to_bytes(50),
    ),
    TransferMinMultipartChunkSizeTestData(
        description="When size is unknown, we expect the chunk size to be the max between "
        "segment_size & min_multipart_chunk_size",
        size=None,
        segment_size=mb_to_bytes(75),
        min_multipart_chunk_size=mb_to_bytes(50),
        expected_chunks=1,
        expected_chunk_size=mb_to_bytes(75),
    ),
]


@pytest.mark.parametrize(
    "test_data",
    TEST_TRANSFER_MIN_MULTIPART_CHUNK_SIZE,
    ids=[option.description for option in TEST_TRANSFER_MIN_MULTIPART_CHUNK_SIZE],
)
def test_transfer_with_min_multipart_chunk_size(mocker: Any, test_data: TransferMinMultipartChunkSizeTestData) -> None:
    t = make_mock_transfer(
        mocker,
        {
            "region": "test-region",
            "bucket_name": "test-bucket",
            "prefix": "test-prefix",
            "segment_size": test_data.segment_size,
            "min_multipart_chunk_size": test_data.min_multipart_chunk_size,
        },
    )

    chunks, chunk_size = t.calculate_chunks_and_chunk_size(test_data.size)
    assert chunks == test_data.expected_chunks
    assert chunk_size == test_data.expected_chunk_size


def test_calculate_chunks_and_chunk_size_error(infra: S3Infra) -> None:
    t = infra.transfer
    t.default_multipart_chunk_size = mb_to_bytes(9)
    with pytest.raises(StorageError) as e:
        t.calculate_chunks_and_chunk_size(mb_to_bytes(50000000))
    assert (
        str(e.value) == "Cannot upload a file of size 52428800000000. "
        "Chunk size 5242880000 is too big for each part of multipart upload."
    )


def test_check_or_create_bucket_ignores_bucket_already_owned_by_you_error(infra: S3Infra) -> None:
    # OVH S3 compatible Object Storage service returns BAD_REQUEST - 400 when trying to HeadBucket
    # on a bucket that exists but only allows s3:ListBucket with a condition
    transfer = infra.transfer
    mock_s3_client = infra.s3_client
    mock_s3_client.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": "400"},
            "ResponseMetadata": {
                "HTTPStatusCode": 400,
                "RequestId": "id",
                "HostId": "id",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        operation_name="head-bucket",
    )
    mock_s3_client.create_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": "BucketAlreadyOwnedByYou"},
            "ResponseMetadata": {
                "HTTPStatusCode": 400,
                "RequestId": "id",
                "HostId": "id",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        operation_name="bucket-create",
    )
    transfer.check_or_create_bucket()
    mock_s3_client.create_bucket.assert_called_once_with(
        Bucket="test-bucket", CreateBucketConfiguration={"LocationConstraint": "test-region"}
    )


def test_check_or_create_bucket_bails_out_on_bucket_already_exists(infra: S3Infra) -> None:
    transfer = infra.transfer
    mock_s3_client = infra.s3_client
    mock_s3_client.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": "400"},
            "ResponseMetadata": {
                "HTTPStatusCode": 400,
                "RequestId": "id",
                "HostId": "id",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        operation_name="head-bucket",
    )
    mock_s3_client.create_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": "BucketAlreadyExists"},
            "ResponseMetadata": {
                "HTTPStatusCode": 400,
                "RequestId": "id",
                "HostId": "id",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        operation_name="bucket-create",
    )
    with pytest.raises(botocore.exceptions.ClientError):
        transfer.check_or_create_bucket()


def test_check_or_create_bucket_does_not_try_to_create_bucket_if_forbidden(infra: S3Infra) -> None:
    transfer = infra.transfer
    mock_s3_client = infra.s3_client
    mock_s3_client.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": "403"},
            "ResponseMetadata": {
                "HTTPStatusCode": 403,
                "RequestId": "id",
                "HostId": "id",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        operation_name="head-bucket",
    )
    transfer.check_or_create_bucket()
    mock_s3_client.create_bucket.assert_not_called()


def test_check_or_create_bucket_raises_error_on_moved_permanently(infra: S3Infra) -> None:
    transfer = infra.transfer
    mock_s3_client = infra.s3_client
    mock_s3_client.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": "301"},
            "ResponseMetadata": {
                "HTTPStatusCode": 301,
                "RequestId": "id",
                "HostId": "id",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        operation_name="head-bucket",
    )
    with pytest.raises(rohmu.errors.InvalidConfigurationError):
        transfer.check_or_create_bucket()
    mock_s3_client.create_bucket.assert_not_called()


@pytest.mark.parametrize("status", [400, 404])
def test_check_or_create_bucket_tries_to_create_bucket_on_not_found_or_bad_request(infra: S3Infra, status: int) -> None:
    transfer = infra.transfer
    mock_s3_client = infra.s3_client
    mock_s3_client.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": str(status)},
            "ResponseMetadata": {
                "HTTPStatusCode": status,
                "RequestId": "id",
                "HostId": "id",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        operation_name="head-bucket",
    )
    transfer.check_or_create_bucket()
    mock_s3_client.create_bucket.assert_called_once_with(
        Bucket="test-bucket", CreateBucketConfiguration={"LocationConstraint": "test-region"}
    )


@pytest.mark.parametrize("status", [400, 404])
def test_check_or_create_bucket_raise_error_if_bucket_missing_and_creation_is_disabled(infra: S3Infra, status: int) -> None:
    transfer = infra.transfer
    mock_s3_client = infra.s3_client
    mock_s3_client.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": str(status)},
            "ResponseMetadata": {
                "HTTPStatusCode": status,
                "RequestId": "id",
                "HostId": "id",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        operation_name="head-bucket",
    )
    # NOTE: in reality this is not correct for status code 400 because for OVH EU S3-compatible
    # Object Storage service it can mean that we are lacking permissions, so we should use
    # something other than head_bucket to determine if the bucket exists or not
    with pytest.raises(TransferObjectStoreMissingError):
        transfer.check_or_create_bucket(create_if_needed=False)
