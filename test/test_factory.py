from rohmu.factory import Config, get_class_for_transfer, get_transfer, get_transfer_from_model
from rohmu.object_storage.config import S3ObjectStorageConfig
from rohmu.object_storage.s3 import S3Transfer
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
    expected_config_arg.pop("notifier")
    expected_botocore_config = {"proxies": {"https": "socks5://bob:secret@proxy.test:16666"}}
    mock_config_model.return_value = S3ObjectStorageConfig(**expected_config_arg)

    transfer_object = get_transfer(config)

    mock_config_model.assert_called_once_with(**expected_config_arg)
    mock_from_model.assert_called_once_with(mock_config_model(), mock_notifier.return_value)
    mock_notifier.assert_called_once_with(url=config["notifier"]["url"])
    assert isinstance(transfer_object, S3Transfer)
    assert transfer_object.bucket_name == "dummy-bucket"
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


@patch("rohmu.object_storage.s3.create_s3_client")
def test_get_transfer_from_model(
    create_s3_client: Mock,
) -> None:
    config = S3ObjectStorageConfig(
        region="dummy-region",
        bucket_name="dummy-bucket",
        proxy_info={
            "host": "proxy.test",
            "port": "16666",
            "type": "socks5",
            "user": "bob",
            "pass": "secret",
        },
    )
    get_transfer_from_model(config)
    create_s3_client.assert_called_once_with(
        session=ANY,
        config=ANY,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        region_name="dummy-region",
    )


@patch("rohmu.object_storage.s3.create_s3_client")
def test_get_transfer_serialized_model(
    create_s3_client: Mock,
) -> None:
    config = S3ObjectStorageConfig(
        region="dummy-region",
        bucket_name="dummy-bucket",
        proxy_info={
            "host": "proxy.test",
            "port": "16666",
            "type": "socks5",
            "user": "bob",
            "pass": "secret",
        },
    )
    get_transfer(config.dict())
    create_s3_client.assert_called_once_with(
        session=ANY,
        config=ANY,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        region_name="dummy-region",
    )
