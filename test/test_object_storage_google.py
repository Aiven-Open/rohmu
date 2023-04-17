"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from contextlib import ExitStack
from datetime import datetime
from googleapiclient.http import MediaUploadProgress
from io import BytesIO
from rohmu.common.models import StorageOperation
from rohmu.object_storage.google import GoogleTransfer, Reporter
from tempfile import NamedTemporaryFile
from unittest.mock import call, MagicMock, patch


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
