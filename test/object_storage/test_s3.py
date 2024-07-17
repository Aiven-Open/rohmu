# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from botocore.response import StreamingBody
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from pydantic.v1 import ValidationError
from rohmu.common.models import StorageOperation
from rohmu.errors import InvalidByteRangeError
from rohmu.object_storage.base import TransferWithConcurrentUploadSupport
from rohmu.object_storage.config import S3ObjectStorageConfig
from rohmu.object_storage.s3 import S3Transfer
from tempfile import NamedTemporaryFile
from typing import Any, BinaryIO, Callable, Iterator, Optional, Union
from unittest.mock import ANY, call, MagicMock, patch

import contextlib
import pytest
import rohmu.object_storage.s3


@dataclass
class S3Infra:
    notifier: MagicMock
    operation: MagicMock
    s3_client: MagicMock
    transfer: S3Transfer


@pytest.fixture(name="infra")
def fixture_infra(mocker: Any) -> Iterator[S3Infra]:
    notifier = MagicMock()
    s3_client = MagicMock()
    create_client = MagicMock(return_value=s3_client)
    session = MagicMock(create_client=create_client)

    @contextlib.contextmanager
    def _get_session(cls: S3Transfer) -> Iterator[MagicMock]:
        yield session

    mocker.patch("rohmu.object_storage.s3.S3Transfer._get_session", _get_session)

    operation = mocker.patch("rohmu.common.statsd.StatsClient.operation")
    transfer = S3Transfer(
        region="test-region",
        bucket_name="test-bucket",
        notifier=notifier,
        prefix="test-prefix",
    )
    yield S3Infra(notifier, operation, s3_client, transfer)


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

    infra.transfer.multipart_chunk_size = chunk_size  # simulate smaller chunk size to force multiple chunks

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


def test_deletion(infra: S3Infra) -> None:
    infra.transfer.delete_keys(["2", "3"])
    infra.s3_client.delete_objects.assert_called_once_with(
        Bucket="test-bucket", Delete={"Objects": [{"Key": "test-prefix/2"}, {"Key": "test-prefix/3"}]}
    )
    infra.transfer.delete_key("1")
    infra.s3_client.delete_object.assert_called_once_with(Bucket="test-bucket", Key="test-prefix/1")


def test_get_contents_to_fileobj_raises_error_on_invalid_byte_range(infra: S3Infra) -> None:
    transfer = infra.transfer
    with pytest.raises(InvalidByteRangeError):
        transfer.get_contents_to_fileobj(
            key="testkey",
            fileobj_to_store_to=BytesIO(),
            byte_range=(100, 10),
        )


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
