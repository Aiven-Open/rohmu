"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from io import BytesIO
from rohmu.object_storage.sftp import SFTPTransfer
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock, patch


def test_store_file_from_disk() -> None:
    notifier = MagicMock()
    with patch("paramiko.Transport") as _, patch("paramiko.SFTPClient") as sftp_client:
        client = MagicMock()
        sftp_client.from_transport.return_value = client
        transfer = SFTPTransfer(
            server="sftp.example.com",
            port=2222,
            username="testuser",
            password="testpass",
            notifier=notifier,
        )
        test_data = b"test-data"
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(test_data)
            tmpfile.flush()
            transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name)

        client.putfo.assert_called()
        notifier.object_created.assert_called_once_with(key="test_key1", size=len(test_data), metadata=None)


def test_store_file_object() -> None:
    notifier = MagicMock()
    with patch("paramiko.Transport") as _, patch("paramiko.SFTPClient") as sftp_client:
        client = MagicMock()
        sftp_client.from_transport.return_value = client
        transfer = SFTPTransfer(
            server="sftp.example.com",
            port=2222,
            username="testuser",
            password="testpass",
            notifier=notifier,
        )
        test_data = b"test-data"
        file_object = BytesIO(test_data)

        # Size reporting relies on the progress callback from paramiko
        def upload_side_effect(*args, **kwargs):  # pylint: disable=unused-argument
            if kwargs.get("callback"):
                kwargs["callback"](len(test_data), len(test_data))

        client.putfo = MagicMock(wraps=upload_side_effect)

        transfer.store_file_object(key="test_key2", fd=file_object)

        client.putfo.assert_called()
        notifier.object_created.assert_called_once_with(key="test_key2", size=len(test_data), metadata=None)
