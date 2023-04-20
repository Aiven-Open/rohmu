"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from datetime import datetime
from io import BytesIO
from rohmu.common.models import StorageOperation
from rohmu.object_storage.s3 import S3Transfer
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock, patch

import pytest


def test_store_file_from_disk() -> None:
    notifier = MagicMock()
    with patch("botocore.session.get_session") as get_session:
        s3_client = MagicMock()
        create_client = MagicMock(return_value=s3_client)
        get_session.return_value = MagicMock(create_client=create_client)
        transfer = S3Transfer(
            region="test-region",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        test_data = b"test-data"
        metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(test_data)
            tmpfile.flush()
            transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name, metadata=metadata)

        s3_client.put_object.assert_called()
        notifier.object_created.assert_called_once_with(
            key="test_key1", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
        )


@pytest.mark.parametrize("multipart", [False, None, True])
def test_store_file_object(multipart) -> None:
    notifier = MagicMock()
    with patch("botocore.session.get_session") as get_session:
        s3_client = MagicMock()
        create_client = MagicMock(return_value=s3_client)
        get_session.return_value = MagicMock(create_client=create_client)
        transfer = S3Transfer(
            region="test-region",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        test_data = b"test-data"
        file_object = BytesIO(test_data)

        metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
        transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata, multipart=multipart)

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
            s3_client.put_object.assert_called()
            notifier.object_created.assert_called_once_with(
                key="test_key2",
                size=len(test_data),
                metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"},
            )


@patch("rohmu.object_storage.base.StatsClient.operation")
def test_operations_reporting(mock_operation) -> None:
    notifier = MagicMock()
    with patch("botocore.session.get_session") as get_session:
        s3_client = MagicMock()
        create_client = MagicMock(return_value=s3_client)
        get_session.return_value = MagicMock(create_client=create_client)
        S3Transfer(
            region="test-region",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        mock_operation.assert_called_once_with(StorageOperation.head_request)  # pylint: disable=no-member
