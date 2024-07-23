# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from datetime import datetime
from io import BytesIO
from pytest_mock import MockerFixture
from rohmu.common.strenum import StrEnum
from rohmu.errors import InvalidByteRangeError
from rohmu.object_storage.azure import AzureTransfer
from rohmu.object_storage.config import AzureObjectStorageConfig
from tempfile import NamedTemporaryFile
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import azure.storage.blob
import pytest
import rohmu.object_storage.azure
import sys


@pytest.fixture(name="mock_get_blob_client")
def fixture_mock_get_blob_client(mocker: MockerFixture) -> MagicMock:
    get_blob_client_mock = MagicMock()
    blob_client = MagicMock(get_blob_client=get_blob_client_mock)
    service_client = MagicMock(from_connection_string=MagicMock(return_value=blob_client))
    mocker.patch.object(rohmu.object_storage.azure, "BlobServiceClient", service_client)
    return get_blob_client_mock


def test_close(mock_get_blob_client: MagicMock) -> None:
    notifier = MagicMock()
    transfer = AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key1",
        notifier=notifier,
    )
    assert transfer._blob_service_client is not None
    blob_service_client = transfer._blob_service_client
    transfer.close()
    blob_service_client.close.assert_called_once()  # type: ignore[attr-defined]
    assert transfer._blob_service_client is None


def test_store_file_from_disk(mock_get_blob_client: MagicMock) -> None:
    notifier = MagicMock()
    transfer = AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key1",
        notifier=notifier,
    )
    test_data = b"test-data"
    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    upload_blob = MagicMock()
    mock_get_blob_client.return_value = MagicMock(upload_blob=upload_blob)

    with NamedTemporaryFile() as tmpfile:
        tmpfile.write(test_data)
        tmpfile.flush()
        transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name, metadata=metadata)

    upload_blob.assert_called_once()
    notifier.object_created.assert_called_once_with(
        key="test_key1", size=len(test_data), metadata={"Content_Length": "9", "some_date": "2022-11-15 18:30:58.486644"}
    )


def test_store_file_object(mock_get_blob_client: MagicMock) -> None:
    notifier = MagicMock()
    transfer = AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key2",
        notifier=notifier,
    )
    test_data = b"test-data"
    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    file_object = BytesIO(test_data)

    def upload_side_effect(*args: Any, **kwargs: Any) -> None:
        if kwargs.get("raw_response_hook"):
            kwargs["raw_response_hook"](MagicMock(context={"upload_stream_current": len(test_data)}))

    # Size reporting relies on the progress callback from azure client
    upload_blob = MagicMock(wraps=upload_side_effect)
    mock_get_blob_client.return_value = MagicMock(upload_blob=upload_blob)

    transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata)

    upload_blob.assert_called_once()
    notifier.object_created.assert_called_once_with(
        key="test_key2", size=len(test_data), metadata={"Content_Length": "9", "some_date": "2022-11-15 18:30:58.486644"}
    )


def test_get_contents_to_fileobj_raises_error_on_invalid_byte_range(mock_get_blob_client: MagicMock) -> None:
    notifier = MagicMock()
    transfer = AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key2",
        notifier=notifier,
    )
    with pytest.raises(InvalidByteRangeError):
        transfer.get_contents_to_fileobj(
            key="testkey",
            fileobj_to_store_to=BytesIO(),
            byte_range=(100, 10),
        )


def test_minimal_config() -> None:
    config = AzureObjectStorageConfig(account_name="test", bucket_name=None, account_key=None, sas_token=None)
    assert config.account_name == "test"


def test_azure_config_host_port_set_together() -> None:
    with pytest.raises(ValueError):
        AzureObjectStorageConfig(account_name="test", host="localhost", bucket_name=None, account_key=None, sas_token=None)
    with pytest.raises(ValueError):
        AzureObjectStorageConfig(account_name="test", port=10000, bucket_name=None, account_key=None, sas_token=None)
    config = AzureObjectStorageConfig(
        account_name="test", host="localhost", port=10000, bucket_name=None, account_key=None, sas_token=None
    )
    assert config.host == "localhost"
    assert config.port == 10000


def test_valid_azure_cloud_endpoint() -> None:
    with pytest.raises(ValueError):
        AzureObjectStorageConfig(
            account_name="test", azure_cloud="invalid", bucket_name=None, account_key=None, sas_token=None
        )
    config = AzureObjectStorageConfig(
        account_name="test", azure_cloud="public", bucket_name=None, account_key=None, sas_token=None
    )
    assert config.azure_cloud == "public"


@pytest.mark.parametrize(
    "host,port,is_secured,expected",
    [
        (
            None,
            None,
            True,
            ";".join(
                [
                    "DefaultEndpointsProtocol=https",
                    "AccountName=test_name",
                    "AccountKey=test_key",
                    "EndpointSuffix=core.windows.net",
                ]
            ),
        ),
        (
            None,
            None,
            False,
            ";".join(
                [
                    "DefaultEndpointsProtocol=http",
                    "AccountName=test_name",
                    "AccountKey=test_key",
                    "EndpointSuffix=core.windows.net",
                ]
            ),
        ),
        (
            "localhost",
            10000,
            True,
            ";".join(
                [
                    "DefaultEndpointsProtocol=https",
                    "AccountName=test_name",
                    "AccountKey=test_key",
                    "BlobEndpoint=https://localhost:10000/test_name",
                ]
            ),
        ),
        (
            "localhost",
            10000,
            False,
            ";".join(
                [
                    "DefaultEndpointsProtocol=http",
                    "AccountName=test_name",
                    "AccountKey=test_key",
                    "BlobEndpoint=http://localhost:10000/test_name",
                ]
            ),
        ),
    ],
)
def test_conn_string(host: Optional[str], port: Optional[int], is_secured: bool, expected: str) -> None:
    get_blob_client_mock = MagicMock()
    blob_client = MagicMock(get_blob_client=get_blob_client_mock)
    service_client = MagicMock(from_connection_string=MagicMock(return_value=blob_client))
    module_patches = {
        "azure.common": MagicMock(),
        "azure.core.exceptions": MagicMock(),
        "azure.storage.blob": MagicMock(BlobServiceClient=service_client),
    }
    with patch.dict(sys.modules, module_patches):
        from rohmu.object_storage.azure import AzureTransfer

    conn_string = AzureTransfer.conn_string(
        account_name="test_name", account_key="test_key", azure_cloud=None, host=host, port=port, is_secure=is_secured
    )
    assert expected == conn_string


class MockBucketName(StrEnum):
    bucket_enum_key = "bucket_enum_value"


def test_create_container_enum(mocker: MockerFixture) -> None:
    container_client_mock = MagicMock(spec=azure.storage.blob.ContainerClient)
    mocker.patch.object(azure.storage.blob._blob_service_client, "ContainerClient", container_client_mock)
    notifier = MagicMock()
    AzureTransfer(
        bucket_name=MockBucketName.bucket_enum_key,
        account_name="test_account",
        account_key="test_key",
        notifier=notifier,
    )
    container_name = container_client_mock.call_args.kwargs["container_name"]
    assert container_name == "bucket_enum_value"


def test_create_container_str(mocker: MockerFixture) -> None:
    container_client_mock = MagicMock(spec=azure.storage.blob.ContainerClient)
    mocker.patch.object(azure.storage.blob._blob_service_client, "ContainerClient", container_client_mock)
    notifier = MagicMock()
    AzureTransfer(
        bucket_name="bucket_name",
        account_name="test_account",
        account_key="test_key",
        notifier=notifier,
    )
    container_name = container_client_mock.call_args.kwargs["container_name"]
    assert container_name == "bucket_name"
