from rohmu.factory import Config, get_class_for_transfer, get_transfer
from rohmu.object_storage.config import S3ObjectStorageConfig
from rohmu.object_storage.s3 import S3Transfer
from typing import cast
from unittest.mock import ANY, MagicMock, Mock, patch

import pytest
import sys


@pytest.mark.parametrize(
    "config",
    [
        {
            "storage_type": "s3",
            "region": "dummy-region",
            "bucket_name": "dummy-bucket",
            "notifier": {"notifier_type": "http", "url": "localhost"},
            "proxy_info": {
                "host": "proxy.test",
                "port": "16666",
                "type": "socks5",
                "user": "bob",
                "pass": "secret",
            },
        }
    ],
)
@patch("rohmu.notifier.http.BackgroundHTTPNotifier")
@patch("botocore.config.Config")
@patch("rohmu.object_storage.s3.S3Transfer.check_or_create_bucket")
@patch("rohmu.object_storage.s3.create_s3_client")
@patch("rohmu.object_storage.s3.S3Transfer.from_model", wraps=S3Transfer.from_model)
@patch("rohmu.object_storage.s3.S3Transfer.config_model")
def test_get_transfer_s3(
    mock_config_model: Mock,
    mock_from_model: Mock,
    mock_s3_client: Mock,
    mock_check_or_create: Mock,
    mock_botocore_config: Mock,
    mock_notifier: Mock,
    config: Config,
) -> None:
    expected_config_arg = dict(config)
    expected_config_arg.pop("storage_type")
    expected_config_arg.pop("notifier")
    expected_botocore_config = {"proxies": {"https": "socks5://bob:secret@proxy.test:16666"}}
    mock_config_model.return_value = S3ObjectStorageConfig(**expected_config_arg, notifier=None)

    transfer_object = get_transfer(config)

    mock_config_model.assert_called_once_with(**expected_config_arg, notifier=mock_notifier())
    mock_from_model.assert_called_once_with(mock_config_model())
    assert isinstance(transfer_object, S3Transfer)
    # cast was the easiest way to convince mypy
    assert cast(S3Transfer, transfer_object).bucket_name == "dummy-bucket"
    mock_botocore_config.assert_called_once_with(**expected_botocore_config)
    mock_s3_client.assert_called_once_with(
        session=ANY,
        config=ANY,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        region_name="dummy-region",
    )
    assert mock_check_or_create.called


@pytest.mark.parametrize("storage_type", ["s3", "local", "azure", "google", "swift", "s3"])
@patch.dict(sys.modules, {"swiftclient": MagicMock(), "azure.common": MagicMock()})
def test_config_model_defined(storage_type: str) -> None:
    assert get_class_for_transfer({"storage_type": storage_type}).config_model
