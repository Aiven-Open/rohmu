# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from datetime import datetime
from io import BytesIO
from rohmu.errors import Error
from rohmu.object_storage.sftp import SFTPTransfer
from tempfile import NamedTemporaryFile
from typing import Any, Union
from unittest.mock import call, MagicMock, patch

import pytest


def test_store_file_from_disk() -> None:
    notifier = MagicMock()
    with patch("paramiko.Transport") as _, patch("paramiko.SFTPClient") as sftp_client:

        def _putfo() -> int:
            return 42

        client = MagicMock()

        # Size reporting relies on the progress callback from paramiko
        def upload_side_effect(*args: Any, **kwargs: Any) -> None:
            if kwargs.get("callback"):
                kwargs["callback"](len(test_data), len(test_data))

        client.putfo = MagicMock(wraps=upload_side_effect)

        sftp_client.from_transport.return_value = client
        transfer = SFTPTransfer(
            server="sftp.example.com",
            port=2222,
            username="testuser",
            password="testpass",
            notifier=notifier,
        )
        test_data = b"test-data"
        metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(test_data)
            tmpfile.flush()
            transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name, metadata=metadata)

        client.putfo.assert_called()
        notifier.object_created.assert_called_once_with(
            key="test_key1", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
        )


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
        def upload_side_effect(*args: Any, **kwargs: Any) -> None:
            if kwargs.get("callback"):
                kwargs["callback"](len(test_data), len(test_data))

        client.putfo = MagicMock(wraps=upload_side_effect)

        metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
        transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata)

        client.putfo.assert_called()
        notifier.object_created.assert_called_once_with(
            key="test_key2", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
        )


@pytest.mark.parametrize(
    ("key", "preserve_trailing_slash", "expected_key"),
    [
        ("1", True, ""),
        ("2/", True, ""),
        ("1", False, "test-prefix/1"),
        ("2/", False, "test-prefix/2"),
        ("1", None, "test-prefix/1"),
        ("2/", None, "test-prefix/2"),
    ],
)
def test_delete_key(key: str, preserve_trailing_slash: Union[bool, None], expected_key: str) -> None:
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
            prefix="test-prefix/",
        )

        if preserve_trailing_slash:
            with pytest.raises(Error):
                transfer.delete_key(key, preserve_trailing_slash=True)
            client.remove.assert_not_called()
        else:
            if preserve_trailing_slash is None:
                transfer.delete_key(key)
            else:
                transfer.delete_key(key, preserve_trailing_slash=preserve_trailing_slash)
            client.assert_has_calls(
                [
                    call.remove(expected_key.strip("/") + ".metadata"),
                    call.remove(expected_key.strip("/")),
                ]
            )


@pytest.mark.parametrize("preserve_trailing_slash", [True, False, None])
def test_delete_keys(preserve_trailing_slash: Union[bool, None]) -> None:
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
        def upload_side_effect(*args: Any, **kwargs: Any) -> None:
            if kwargs.get("callback"):
                kwargs["callback"](len(test_data), len(test_data))

        client.putfo = MagicMock(wraps=upload_side_effect)

        metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
        transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata)

        client.putfo.assert_called()
        notifier.object_created.assert_called_once_with(
            key="test_key2", size=len(test_data), metadata={"Content-Length": "9", "some-date": "2022-11-15 18:30:58.486644"}
        )
