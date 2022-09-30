"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from io import BytesIO
from rohmu.object_storage.s3 import S3Transfer
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock, patch


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
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(test_data)
            tmpfile.flush()
            transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name)

        s3_client.put_object.assert_called()
        notifier.object_created.assert_called_once_with(key="test_key1", size=len(test_data), metadata=None)


def test_store_file_object() -> None:
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

        transfer.store_file_object(key="test_key2", fd=file_object)

        # store_file_object does a multipart upload
        s3_client.create_multipart_upload.assert_called()
        s3_client.upload_part.assert_called()
        s3_client.complete_multipart_upload.assert_called()
        notifier.object_created.assert_called_once_with(key="test_key2", size=len(test_data), metadata=None)
