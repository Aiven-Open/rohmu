"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from io import BytesIO
from rohmu.object_storage.google import GoogleTransfer
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock, patch


def test_store_file_from_disk() -> None:
    notifier = MagicMock()
    with patch("rohmu.object_storage.google.get_credentials") as _, patch(
        "rohmu.object_storage.google.GoogleTransfer._upload"
    ) as upload, patch("rohmu.object_storage.google.GoogleTransfer.get_or_create_bucket") as _:
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        test_data = b"test-data"
        upload.return_value = {"size": len(test_data)}  # server reports the size of the uploaded object
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(test_data)
            tmpfile.flush()
            transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name)

        upload.assert_called()
        notifier.object_created.assert_called_once_with(key="test_key1", size=len(test_data))


def test_store_file_object() -> None:
    notifier = MagicMock()
    with patch("rohmu.object_storage.google.get_credentials") as _, patch(
        "rohmu.object_storage.google.GoogleTransfer._upload"
    ) as upload, patch("rohmu.object_storage.google.GoogleTransfer.get_or_create_bucket") as _:
        transfer = GoogleTransfer(
            project_id="test-project-id",
            bucket_name="test-bucket",
            notifier=notifier,
        )
        test_data = b"test-data"
        file_object = BytesIO(test_data)
        upload.return_value = {"size": len(test_data)}  # server reports the size of the uploaded object

        transfer.store_file_object(key="test_key2", fd=file_object)

        upload.assert_called()
        notifier.object_created.assert_called_once_with(key="test_key2", size=len(test_data))
