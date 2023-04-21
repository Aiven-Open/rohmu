"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from datetime import datetime
from io import BytesIO
from tempfile import NamedTemporaryFile
from types import ModuleType
from typing import Tuple
from unittest.mock import MagicMock, patch

import pytest
import sys


@pytest.fixture(scope="module", name="mock_azure_module")
def fixture_mock_azure_module() -> Tuple[ModuleType, MagicMock]:
    get_blob_client_mock = MagicMock()
    blob_client = MagicMock(get_blob_client=get_blob_client_mock)
    service_client = MagicMock(from_connection_string=MagicMock(return_value=blob_client))
    module_patches = {
        "azure.common": MagicMock(),
        "azure.core.exceptions": MagicMock(),
        "azure.storage.blob": MagicMock(BlobServiceClient=service_client),
    }
    with patch.dict(sys.modules, module_patches):
        import rohmu.object_storage.azure

    return rohmu.object_storage.azure, get_blob_client_mock


@pytest.fixture(name="azure_module")
def fixture_azure_module(mock_azure_module: Tuple[ModuleType, MagicMock]) -> ModuleType:
    return mock_azure_module[0]


@pytest.fixture(name="get_blob_client")
def fixture_get_blob_client(mock_azure_module: Tuple[ModuleType, MagicMock]) -> MagicMock:
    return mock_azure_module[1]


def test_store_file_from_disk(azure_module: ModuleType, get_blob_client: MagicMock) -> None:
    notifier = MagicMock()
    transfer = azure_module.AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key1",
        notifier=notifier,
    )
    test_data = b"test-data"
    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    upload_blob = MagicMock()
    get_blob_client.return_value = MagicMock(upload_blob=upload_blob)

    with NamedTemporaryFile() as tmpfile:
        tmpfile.write(test_data)
        tmpfile.flush()
        transfer.store_file_from_disk(key="test_key1", filepath=tmpfile.name, metadata=metadata)

    upload_blob.assert_called_once()
    notifier.object_created.assert_called_once_with(
        key="test_key1", size=len(test_data), metadata={"Content_Length": "9", "some_date": "2022-11-15 18:30:58.486644"}
    )


def test_store_file_object(azure_module: ModuleType, get_blob_client: MagicMock) -> None:
    notifier = MagicMock()
    transfer = azure_module.AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key2",
        notifier=notifier,
    )
    test_data = b"test-data"
    metadata = {"Content-Length": len(test_data), "some-date": datetime(2022, 11, 15, 18, 30, 58, 486644)}
    file_object = BytesIO(test_data)

    def upload_side_effect(*args, **kwargs):  # pylint: disable=unused-argument
        if kwargs.get("raw_response_hook"):
            kwargs["raw_response_hook"](MagicMock(context={"upload_stream_current": len(test_data)}))

    # Size reporting relies on the progress callback from azure client
    upload_blob = MagicMock(wraps=upload_side_effect)
    get_blob_client.return_value = MagicMock(upload_blob=upload_blob)

    transfer.store_file_object(key="test_key2", fd=file_object, metadata=metadata)

    upload_blob.assert_called_once()
    notifier.object_created.assert_called_once_with(
        key="test_key2", size=len(test_data), metadata={"Content_Length": "9", "some_date": "2022-11-15 18:30:58.486644"}
    )
