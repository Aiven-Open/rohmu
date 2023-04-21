"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from rohmu.common.models import StorageOperation
from rohmu.object_storage.s3 import S3Transfer
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock

import pytest


@dataclass
class S3Infra:
    notifier: MagicMock
    operation: MagicMock
    s3_client: MagicMock
    transfer: S3Transfer


@pytest.fixture(name="infra")
def fixture_infra(mocker):
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


def test_store_file_from_disk(infra) -> None:
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
def test_store_file_object(infra, multipart) -> None:
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


def test_operations_reporting(infra) -> None:
    infra.operation.assert_called_once_with(StorageOperation.head_request)  # pylint: disable=no-member


def test_deletion(infra: S3Infra) -> None:
    infra.transfer.delete_keys(["2", "3"])
    infra.s3_client.delete_objects.assert_called_once_with(
        Bucket="test-bucket", Delete={"Objects": [{"Key": "test-prefix/2"}, {"Key": "test-prefix/3"}]}
    )
    infra.transfer.delete_key("1")
    infra.s3_client.delete_object.assert_called_once_with(Bucket="test-bucket", Key="test-prefix/1")
