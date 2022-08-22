# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/
from rohmu import get_transfer
from unittest.mock import MagicMock, patch

import datetime
import tempfile
import uuid


def test_setting_notification_url():
    with tempfile.TemporaryDirectory(prefix="rohmu-") as local:
        config = {"directory": str(local), "storage_type": "local", "notification_url": "http://notify/here"}
        transfer = get_transfer(config)
        assert transfer.notification_url == config["notification_url"]
        assert transfer.notifier is not None


@patch("rohmu.object_storage.base.ThreadPoolExecutor")
def test_notifiy_delete():
    with tempfile.TemporaryDirectory(prefix="rohmu-") as local:
        config = {"directory": str(local), "storage_type": "local", "notification_url": "http://notify/here"}
        transfer = get_transfer(config)
        key = str(uuid.uuid4())
        transfer.notify_delete(key=key)
        op = {"key": key, "op": "DELETE"}
        transfer.notifier.submit.assert_called_once_with(transfer._notify, op)  # pylint: disable=protected-access, no-member


@patch("rohmu.object_storage.base.datetime")
@patch("rohmu.object_storage.base.ThreadPoolExecutor")
def test_notifiy_upload(mocked_executor, mock_datetime):  # pylint: disable=unused-argument
    with tempfile.TemporaryDirectory(prefix="rohmu-") as local:
        config = {"directory": str(local), "storage_type": "local", "notification_url": "http://notify/here"}
        transfer = get_transfer(config)
        utcnow = datetime.datetime.utcnow()
        mock_datetime.datetime.utcnow.return_value = utcnow
        key = str(uuid.uuid4())
        op = {"key": key, "op": "UPLOAD", "size_bytes": 100, "last_modified": utcnow}
        transfer.notify_write(key=key, size=100)
        transfer.notifier.submit.assert_called_once_with(transfer._notify, op)  # pylint: disable=protected-access, no-member


@patch("rohmu.object_storage.base.get_requests_session")
def test_notifiy_request(mock_session):
    url = "http://notify/here"
    with tempfile.TemporaryDirectory(prefix="rohmu-") as local:
        config = {
            "directory": str(local),
            "storage_type": "local",
            "notification_url": url,
        }
        mock_enter = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_enter
        op = {"key": str(uuid.uuid4()), "op": "DELETE"}
        transfer = get_transfer(config)
        transfer._notify(op)  # pylint: disable=protected-access
        mock_enter.post.assert_called_once_with(url, json=op)
