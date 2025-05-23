# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from contextlib import ExitStack
from datetime import datetime
from io import BytesIO
from pytest_mock import MockerFixture
from rohmu.common.strenum import StrEnum
from rohmu.errors import FileNotFoundFromStorageError, InvalidByteRangeError, StorageError
from rohmu.object_storage.azure import AzureTransfer
from rohmu.object_storage.config import AzureObjectStorageConfig
from tempfile import NamedTemporaryFile
from typing import Any, Optional, Union
from unittest.mock import call, MagicMock, Mock, patch

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


def test_get_contents_to_fileobj_not_found(mock_get_blob_client: MagicMock) -> None:
    notifier = MagicMock()
    transfer = AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key2",
        notifier=notifier,
    )

    download_blob = MagicMock(side_effect=azure.core.exceptions.ResourceNotFoundError)
    mock_get_blob_client.return_value = MagicMock(download_blob=download_blob)
    with pytest.raises(FileNotFoundFromStorageError):
        transfer.get_contents_to_fileobj(
            key="testkey",
            fileobj_to_store_to=BytesIO(),
        )


def test_get_contents_to_fileobj_empty_object(mock_get_blob_client: MagicMock) -> None:
    notifier = MagicMock()
    transfer = AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key2",
        notifier=notifier,
    )
    transfer._metadata_for_key = MagicMock(return_value={})  # type: ignore[method-assign]

    def download_blob(*args: Any, **kwargs: Any) -> Any:
        raise azure.core.exceptions.HttpResponseError(
            message="The range specified is invalid for the current size of the resource.",
            response=MagicMock(reason="Range Not Satisfiable", status_code=416),
        )

    def get_blob_properties(*args: Any, **kwargs: Any) -> Any:
        return MagicMock(size=0)

    mock_get_blob_client.return_value = MagicMock(download_blob=download_blob, get_blob_properties=get_blob_properties)
    fileobj = BytesIO()
    transfer.get_contents_to_fileobj(
        key="testkey",
        fileobj_to_store_to=fileobj,
    )
    assert fileobj.getvalue() == b""


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


@pytest.mark.parametrize(
    ("key", "preserve_trailing_slash", "expected_key"),
    [
        ("1", True, "test-prefix/1"),
        ("2/", True, "test-prefix/2/"),
        ("1", False, "test-prefix/1"),
        ("2/", False, "test-prefix/2"),
        ("1", None, "test-prefix/1"),
        ("2/", None, "test-prefix/2"),
    ],
)
def test_delete_key(
    mock_get_blob_client: MagicMock,
    key: str,
    preserve_trailing_slash: Union[bool, None],
    expected_key: str,
) -> None:
    notifier = MagicMock()
    transfer = AzureTransfer(
        bucket_name="test_bucket",
        account_name="test_account",
        account_key="test_key2",
        prefix="test-prefix/",
        notifier=notifier,
    )

    if preserve_trailing_slash is None:
        transfer.delete_key(key)
    else:
        transfer.delete_key(key, preserve_trailing_slash=preserve_trailing_slash)

    mock_get_blob_client.assert_has_calls(
        [
            call(container="test_bucket", blob=expected_key),
            call().delete_blob(),
        ]
    )


@pytest.mark.parametrize("preserve_trailing_slash", [True, False, None])
def test_delete_keys_trailing_slash(mock_get_blob_client: MagicMock, preserve_trailing_slash: Union[bool, None]) -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.azure.AzureTransfer._create_object_store_if_needed_unwrapped"))
        mock_container_client = MagicMock()
        mock_container_client.delete_blobs.return_value = [
            Mock(status_code=202),
            Mock(status_code=202),
            Mock(status_code=202),
        ]
        mock_service_client = MagicMock()
        mock_service_client.get_container_client.return_value = mock_container_client
        stack.enter_context(
            patch("rohmu.object_storage.azure.AzureTransfer.get_blob_service_client", return_value=mock_service_client)
        )
        transfer = AzureTransfer(
            bucket_name="test_bucket",
            account_name="test_account",
            account_key="test_key2",
            prefix="test-prefix/",
            notifier=notifier,
        )
        if preserve_trailing_slash is None:
            transfer.delete_keys(["2", "3", "4/"])
        else:
            transfer.delete_keys(["2", "3", "4/"], preserve_trailing_slash=preserve_trailing_slash)

        expected_keys = ["test-prefix/2", "test-prefix/3", "test-prefix/4/" if preserve_trailing_slash else "test-prefix/4"]
        expected_calls = [
            call.delete_blobs(*expected_keys, raise_on_any_failure=False),
        ]

        mock_container_client.assert_has_calls(expected_calls)


def test_delete_keys_notifier() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.azure.AzureTransfer._create_object_store_if_needed_unwrapped"))
        mock_container_client = MagicMock()
        mock_container_client.delete_blobs.return_value = [
            Mock(status_code=202),
            Mock(status_code=202),
            Mock(status_code=202),
        ]
        mock_service_client = MagicMock()
        mock_service_client.get_container_client.return_value = mock_container_client
        stack.enter_context(
            patch("rohmu.object_storage.azure.AzureTransfer.get_blob_service_client", return_value=mock_service_client)
        )

        transfer = AzureTransfer(
            bucket_name="test-bucket",
            account_name="test-account",
            account_key="test-key",
            prefix="test-prefix/",
            notifier=notifier,
        )

        test_keys = ["key1", "key2", "key3"]
        transfer.delete_keys(keys=test_keys)

        expected_paths = ["test-prefix/key1", "test-prefix/key2", "test-prefix/key3"]
        mock_container_client.delete_blobs.assert_called_once_with(*expected_paths, raise_on_any_failure=False)

        # Verify notifier was called for each successful deletion
        expected_calls = [call(key) for key in test_keys]
        notifier.object_deleted.assert_has_calls(expected_calls)


def test_delete_keys_with_404() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.azure.AzureTransfer._create_object_store_if_needed_unwrapped"))
        mock_container_client = MagicMock()
        mock_container_client.delete_blobs.return_value = [
            Mock(status_code=202),
            Mock(status_code=404),
            Mock(status_code=202),
        ]
        mock_service_client = MagicMock()
        mock_service_client.get_container_client.return_value = mock_container_client
        stack.enter_context(
            patch("rohmu.object_storage.azure.AzureTransfer.get_blob_service_client", return_value=mock_service_client)
        )

        transfer = AzureTransfer(
            bucket_name="test-bucket",
            account_name="test-account",
            account_key="test-key",
            notifier=notifier,
        )

        test_keys = ["key1", "key2", "key3"]
        with pytest.raises(FileNotFoundFromStorageError):
            transfer.delete_keys(keys=test_keys)

        # Verify notifier was only called for successful deletions
        expected_calls = [call("key1")]
        notifier.object_deleted.assert_has_calls(expected_calls)


def test_delete_keys_with_error_status() -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.azure.AzureTransfer._create_object_store_if_needed_unwrapped"))
        mock_container_client = MagicMock()
        mock_container_client.delete_blobs.return_value = [
            Mock(status_code=202),
            Mock(status_code=500, reason="Internal Server Error"),
            Mock(status_code=202),
        ]
        mock_service_client = MagicMock()
        mock_service_client.get_container_client.return_value = mock_container_client
        stack.enter_context(
            patch("rohmu.object_storage.azure.AzureTransfer.get_blob_service_client", return_value=mock_service_client)
        )

        transfer = AzureTransfer(
            bucket_name="test-bucket",
            account_name="test-account",
            account_key="test-key",
            notifier=notifier,
        )

        test_keys = ["key1", "key2", "key3"]
        with pytest.raises(StorageError, match="Failed to delete key: 500 Internal Server Error"):
            transfer.delete_keys(keys=test_keys)

        # Verify notifier was only called for successful deletions
        expected_calls = [call("key1")]
        notifier.object_deleted.assert_has_calls(expected_calls)


@pytest.mark.parametrize(
    ("total_keys,expected_batch_count"),
    (
        (0, 0),
        (1, 1),
        (255, 1),
        (256, 1),
        (257, 2),
        (511, 2),
        (512, 2),
        (513, 3),
    ),
)
def test_delete_keys_batching(total_keys: int, expected_batch_count: int) -> None:
    notifier = MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch("rohmu.object_storage.azure.AzureTransfer._create_object_store_if_needed_unwrapped"))
        mock_container_client = MagicMock()
        mock_container_client.delete_blobs.return_value = [Mock(status_code=202) for _ in range(total_keys)]
        mock_service_client = MagicMock()
        mock_service_client.get_container_client.return_value = mock_container_client
        stack.enter_context(
            patch("rohmu.object_storage.azure.AzureTransfer.get_blob_service_client", return_value=mock_service_client)
        )

        transfer = AzureTransfer(
            bucket_name="test-bucket",
            account_name="test-account",
            account_key="test-key",
            notifier=notifier,
        )

        test_keys = [f"test_key_{i+1}" for i in range(total_keys)]
        transfer.delete_keys(keys=test_keys)

        # Verify correct number of batch calls
        assert mock_container_client.delete_blobs.call_count == expected_batch_count

        # Verify all keys were processed
        assert notifier.object_deleted.call_count == total_keys
