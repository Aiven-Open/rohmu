from rohmu import Config, get_class_for_transfer, get_transfer
from unittest.mock import MagicMock, Mock, patch

import pytest
import sys


@pytest.mark.parametrize(
    "config",
    [
        {
            "storage_type": "s3",
            "region": "dummy",
            "bucket_name": "dummy",
            "notifier": {"notifier_type": "http", "url": "localhost"},
        }
    ],
)
@patch("rohmu.notifier.http.BackgroundHTTPNotifier")
@patch("rohmu.object_storage.s3.S3Transfer.from_model")
@patch("rohmu.object_storage.s3.S3Transfer.config_model")
def test_get_transfer(mock_config_model: Mock, mock_from_model: Mock, mock_notifier: Mock, config: Config) -> None:
    _transfer = get_transfer(config)
    expected_config_arg = dict(config)
    expected_config_arg.pop("storage_type")
    expected_config_arg.pop("notifier")
    mock_config_model.assert_called_once_with(**expected_config_arg, notifier=mock_notifier())
    mock_from_model.assert_called_once_with(mock_config_model())


@pytest.mark.parametrize("storage_type", ["s3", "local", "azure", "google", "swift", "s3"])
@patch.dict(sys.modules, {"swiftclient": MagicMock(), "azure.common": MagicMock()})
def test_config_model_defined(storage_type: str) -> None:
    assert get_class_for_transfer({"storage_type": storage_type}).config_model
