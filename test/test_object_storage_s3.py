"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from botocore.response import StreamingBody
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from rohmu.common.models import StorageOperation
from rohmu.errors import InvalidByteRangeError, StorageError
from rohmu.object_storage.s3 import S3Transfer
from tempfile import NamedTemporaryFile
from typing import Any, Iterator, Optional
from unittest.mock import MagicMock

import pytest


@dataclass
class S3Infra:
    notifier: MagicMock
    operation: MagicMock
    s3_client: MagicMock
    transfer: S3Transfer


@pytest.fixture(name="infra")
def fixture_infra(mocker: Any) -> Iterator[S3Infra]:
    notifier = MagicMock()
    get_session = mocker.patch("botocore.session.get_session")
    s3_client = MagicMock()
    create_client = MagicMock(return_value=s3_client)
    get_session.return_value = MagicMock(create_client=create_client)
    operation = mocker.patch("rohmu.object_storage.base.StatsClient.operation")
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


def test_operations_reporting(infra: S3Infra) -> None:
    infra.operation.assert_called_once_with(StorageOperation.head_request)  # pylint: disable=no-member


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


def test_concurrent_upload_complete(infra: S3Infra) -> None:
    metadata = {"some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    infra.s3_client.create_multipart_upload.return_value = {"UploadId": "<aws-mpu-id>"}
    upload = infra.transfer.create_concurrent_upload("test_key", metadata=metadata)
    upload.upload_chunk(1, BytesIO(b"Hello, "))
    # we can upload chunks in non-monotonically increasing order
    upload.upload_chunk(3, BytesIO(b"!"))
    upload.upload_chunk(2, BytesIO(b"World"))
    upload.complete()

    notifier = infra.notifier
    s3_client = infra.s3_client

    s3_client.create_multipart_upload.assert_called()
    s3_client.upload_part.assert_called()
    s3_client.complete_multipart_upload.assert_called()

    # we notify the creation of the object
    notifier.object_created.assert_called_once_with(
        key="test-prefix/test_key",
        size=None,
        metadata={"some-date": "2022-11-15 18:30:58.486644"},
    )
    with pytest.raises(StorageError):
        # cannot upload parts after completing an upload
        upload.upload_chunk(4, BytesIO(b"Other data"))
    with pytest.raises(StorageError):
        # cannot upload parts after completing an upload
        upload.abort()


def test_concurrent_upload_abort(infra: S3Infra) -> None:
    infra.s3_client.create_multipart_upload.return_value = {"UploadId": "<aws-mpu-id>"}
    upload = infra.transfer.create_concurrent_upload("test_key")
    upload.upload_chunk(1, BytesIO(b"Hello, "))
    upload.abort()

    notifier = infra.notifier
    s3_client = infra.s3_client

    s3_client.create_multipart_upload.assert_called()
    s3_client.upload_part.assert_called()
    s3_client.complete_multipart_upload.assert_not_called()
    s3_client.abort_multipart_upload.assert_called()

    # no notification is sent in this case!
    notifier.object_created.assert_not_called()

    with pytest.raises(StorageError):
        # cannot upload parts after aborting an upload
        upload.upload_chunk(4, BytesIO(b"Other data"))

    with pytest.raises(StorageError):
        # cannot complete an upload after an abort
        upload.complete()


def test_concurrent_upload_resumption(infra: S3Infra) -> None:
    metadata = {"some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    infra.s3_client.create_multipart_upload.return_value = {"UploadId": "<aws-mpu-id>"}
    upload = infra.transfer.create_concurrent_upload("test_key", metadata=metadata)
    upload.upload_chunk(1, BytesIO(b"Hello, "))
    # we can upload chunks in non-monotonically increasing order
    upload.upload_chunk(3, BytesIO(b"!"))

    new_upload = infra.transfer.get_concurrent_upload(upload.upload_id)
    # we expect to have the instance cached
    assert upload is new_upload

    # simulate restart of the in-memory state
    infra.transfer._mpu_cache.clear()  # pylint: disable=protected-access
    infra.s3_client.list_parts.return_value = {
        "IsTruncated": False,
        "Parts": [
            {"ETag": "first-etag", "PartNumber": 1},
            {"ETag": "second-etag", "PartNumber": 2},
            {"ETag": "third-etag", "PartNumber": 3},
        ],
    }
    # we expect that a new instance gets created
    new_upload = infra.transfer.get_concurrent_upload(upload.upload_id)
    assert upload is not new_upload
    # when resuming we need to fetch the etags associated with the parts already uploaded
    infra.s3_client.list_parts.assert_called()
