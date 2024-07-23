# Copyright (c) 2016 Ohmu Ltd
# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""Rohmu - azure object store interface"""

from __future__ import annotations

from azure.core.exceptions import HttpResponseError, ResourceExistsError
from azure.storage.blob import BlobServiceClient, ContentSettings
from rohmu.common.statsd import StatsdConfig
from rohmu.errors import FileNotFoundFromStorageError, InvalidConfigurationError, StorageError
from rohmu.notifier.interface import Notifier
from rohmu.object_storage.base import (
    BaseTransfer,
    IncrementalProgressCallbackType,
    IterKeyItem,
    KEY_TYPE_OBJECT,
    KEY_TYPE_PREFIX,
    ProgressProportionCallbackType,
    SourceStorageModelT,
)
from rohmu.object_storage.config import (  # noqa: F401
    AZURE_ENDPOINT_SUFFIXES as ENDPOINT_SUFFIXES,
    AZURE_MAX_BLOCK_SIZE as MAX_BLOCK_SIZE,
    AzureObjectStorageConfig as Config,
    calculate_azure_max_block_size as calculate_max_block_size,
)
from rohmu.typing import Metadata
from typing import Any, BinaryIO, Collection, Iterator, Optional, Tuple, Union

import azure.common
import enum
import logging
import time

try:
    from azure.storage.blob import BlobPrefix, BlobType
except ImportError:
    # old versions of the azure blob storage library do not expose the classes publicly
    from azure.storage.blob._models import BlobPrefix, BlobType  # type: ignore


# Reduce Azure logging verbocity of http requests and responses
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)


class AzureTransfer(BaseTransfer[Config]):
    config_model = Config

    def __init__(
        self,
        bucket_name: str,
        account_name: str,
        account_key: Optional[str] = None,
        sas_token: Optional[str] = None,
        prefix: Optional[str] = None,
        is_secure: bool = True,
        host: Optional[str] = None,
        port: Optional[int] = None,
        azure_cloud: Optional[str] = None,
        proxy_info: Optional[dict[str, Union[str, int]]] = None,
        notifier: Optional[Notifier] = None,
        statsd_info: Optional[StatsdConfig] = None,
    ) -> None:
        prefix = prefix.lstrip("/") if prefix else ""
        super().__init__(prefix=prefix, notifier=notifier, statsd_info=statsd_info)
        if not account_key and not sas_token:
            raise InvalidConfigurationError("One of account_key or sas_token must be specified to authenticate")

        self.account_name = account_name
        self.account_key = account_key
        self.container_name = bucket_name
        self.sas_token = sas_token
        self._conn_str = self.conn_string(
            account_name=account_name,
            account_key=account_key,
            azure_cloud=azure_cloud,
            host=host,
            port=port,
            is_secure=is_secure,
        )
        self._config: dict[str, Any] = {"max_block_size": MAX_BLOCK_SIZE}
        if proxy_info:
            username = proxy_info.get("user")
            password = proxy_info.get("pass")
            if username and password:
                auth = f"{username}:{password}@"
            else:
                auth = ""
            proxy_host = proxy_info["host"]
            proxy_port = proxy_info["port"]
            if proxy_info.get("type") == "socks5":
                schema = "socks5"
            else:
                schema = "http"
            self._config["proxies"] = {"https": f"{schema}://{auth}{proxy_host}:{proxy_port}"}
        self._blob_service_client: Optional[BlobServiceClient] = None
        self.container = self.get_or_create_container(self.container_name)
        self.log.debug("AzureTransfer initialized, %r", self.container_name)

    def get_blob_service_client(self) -> BlobServiceClient:
        if self._blob_service_client is None:
            self._blob_service_client = BlobServiceClient.from_connection_string(
                conn_str=self._conn_str,
                credential=self.sas_token,
                **self._config,
            )
        return self._blob_service_client

    def close(self) -> None:
        if self._blob_service_client is not None:
            self._blob_service_client.close()
            self._blob_service_client = None

    @staticmethod
    def conn_string(
        account_name: str,
        account_key: Optional[str],
        azure_cloud: Optional[str],
        host: Optional[str],
        port: Optional[int],
        is_secure: bool,
    ) -> str:
        protocol = "https" if is_secure else "http"
        conn = [
            f"DefaultEndpointsProtocol={protocol}",
            f"AccountName={account_name}",
            f"AccountKey={account_key}",
        ]
        if not host and not port:
            endpoint_suffix = ENDPOINT_SUFFIXES[azure_cloud]
            conn.append(f"EndpointSuffix={endpoint_suffix}")
        else:
            conn.append(f"BlobEndpoint={protocol}://{host}:{port}/{account_name}")
        return ";".join(conn)

    def copy_file(
        self, *, source_key: str, destination_key: str, metadata: Optional[Metadata] = None, **kwargs: Any
    ) -> None:
        timeout = kwargs.get("timeout") or 15.0
        self._copy_file_from_bucket(
            source_bucket=self, source_key=source_key, destination_key=destination_key, metadata=metadata, timeout=timeout
        )

    def _copy_file_from_bucket(
        self,
        source_bucket: AzureTransfer,
        source_key: str,
        destination_key: str,
        metadata: Optional[Metadata] = None,
        timeout: float = 15.0,
    ) -> None:
        source_path = source_bucket.format_key_for_backend(source_key, remove_slash_prefix=True, trailing_slash=False)
        source_client = source_bucket.get_blob_service_client().get_blob_client(source_bucket.container_name, source_path)
        source_url = source_client.url

        destination_path = self.format_key_for_backend(destination_key, remove_slash_prefix=True, trailing_slash=False)
        destination_client = self.get_blob_service_client().get_blob_client(self.container_name, destination_path)
        start = time.monotonic()
        destination_client.start_copy_from_url(source_url, metadata=metadata, timeout=timeout)
        while True:
            blob_properties = destination_client.get_blob_properties(timeout=timeout)
            copy_props = blob_properties.copy
            if copy_props.status == "success":
                self.notifier.object_copied(destination_key, size=blob_properties["size"], metadata=metadata)
                return
            elif copy_props.status == "pending":
                if time.monotonic() - start < timeout:
                    time.sleep(0.1)
                else:
                    destination_client.abort_copy(copy_props.id, timeout=timeout)
                    raise StorageError(
                        f"Copying {repr(source_key)} to {repr(destination_key)} did not complete in {timeout} seconds"
                    )
            elif copy_props.status == "failed":
                raise StorageError(
                    f"Copying {repr(source_key)} to {repr(destination_key)} failed: {copy_props.status_description}"
                )
            else:
                raise StorageError(
                    f"Copying {repr(source_key)} to {repr(destination_key)} failed, unexpected status: {copy_props.status}"
                )

    def copy_files_from(self, *, source: BaseTransfer[SourceStorageModelT], keys: Collection[str]) -> None:
        if isinstance(source, AzureTransfer):
            for key in keys:
                self._copy_file_from_bucket(source_bucket=source, source_key=key, destination_key=key, timeout=15)
        else:
            raise NotImplementedError

    def get_metadata_for_key(self, key: str) -> Metadata:
        path = self.format_key_for_backend(key, remove_slash_prefix=True, trailing_slash=False)
        items = list(self._iter_key(path=path, with_metadata=True, deep=False))
        if not items:
            raise FileNotFoundFromStorageError(path)
        expected_name = path.rsplit("/", 1)[-1]
        item: IterKeyItem
        for item in items:
            # We expect single result but Azure listing is prefix match so we need to explicitly
            # look up the matching result
            item_name: str
            if item.type == KEY_TYPE_OBJECT:
                assert isinstance(item.value, dict)
                item_name = item.value["name"]
            else:
                assert isinstance(item.value, str)
                item_name = item.value
            if item_name.rstrip("/").rsplit("/", 1)[-1] == expected_name:
                break
        else:
            raise FileNotFoundFromStorageError(path)
        if item.type != KEY_TYPE_OBJECT:
            raise FileNotFoundFromStorageError(path)  # not found or prefix
        assert isinstance(item.value, dict)
        return item.value["metadata"]

    def _metadata_for_key(self, path: str) -> Metadata:
        result = list(self._iter_key(path=path, with_metadata=True, deep=False))[0].value
        assert isinstance(result, dict)
        return result["metadata"]

    def iter_key(
        self, key: str, *, with_metadata: bool = True, deep: bool = False, include_key: bool = False
    ) -> Iterator[IterKeyItem]:
        path = self.format_key_for_backend(key, remove_slash_prefix=True, trailing_slash=not include_key)
        self.log.debug("Listing path %r", path)
        yield from self._iter_key(path=path, with_metadata=with_metadata, deep=deep)

    def _iter_key(self, *, path: str, with_metadata: bool, deep: bool) -> Iterator[IterKeyItem]:
        include = "metadata" if with_metadata else None
        container_client = self.get_blob_service_client().get_container_client(self.container_name)
        name_starts_with = None
        delimiter = ""
        if path:
            # If you give Azure an empty path, it gives you an authentication error
            name_starts_with = path
        if not deep:
            delimiter = "/"
        items = container_client.walk_blobs(include=include, name_starts_with=name_starts_with, delimiter=delimiter)
        for item in items:
            if isinstance(item, BlobPrefix):
                yield IterKeyItem(type=KEY_TYPE_PREFIX, value=self.format_key_from_backend(item.name).rstrip("/"))
            else:
                if with_metadata:
                    metadata = {}
                    if item.metadata:
                        # Azure Storage cannot handle '-' so we turn them into underscores and back again
                        metadata = {k.replace("_", "-"): v for k, v in item.metadata.items()}
                else:
                    metadata = None
                yield IterKeyItem(
                    type=KEY_TYPE_OBJECT,
                    value={
                        "last_modified": item.last_modified,
                        "metadata": metadata,
                        "name": self.format_key_from_backend(item.name),
                        "size": item.size,
                        "md5": item.etag.strip('"'),
                    },
                )

    def delete_key(self, key: str) -> None:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        self.log.debug("Deleting key: %r", path)
        try:
            blob_client = self.get_blob_service_client().get_blob_client(container=self.container_name, blob=path)
            result = blob_client.delete_blob()
        except azure.core.exceptions.ResourceNotFoundError as ex:
            raise FileNotFoundFromStorageError(path) from ex

        self.notifier.object_deleted(key)

        return result

    @classmethod
    def _parse_length_from_content_range(cls, content_range: str) -> int:
        """Parses the blob length from the content range header: bytes 1-3/65537"""
        if not content_range:
            raise ValueError("File size unavailable")

        return int(content_range.split(" ", 1)[1].split("/", 1)[1])

    def _stream_blob(
        self,
        key: str,
        fileobj: BinaryIO,
        byte_range: Optional[tuple[int, int]],
        progress_callback: ProgressProportionCallbackType,
    ) -> None:
        """Streams contents of given key to given fileobj. Data is read sequentially in chunks
        without any seeks. This requires duplicating some functionality of the Azure SDK, which only
        allows reading entire blob into memory at once or returning data from random offsets"""
        file_size = None
        start_range = byte_range[0] if byte_range else 0
        chunk_size = self.get_blob_service_client()._config.max_chunk_get_size  # type: ignore[attr-defined]
        end_range = chunk_size - 1
        blob = self.get_blob_service_client().get_blob_client(self.container_name, key)
        while True:
            try:
                if byte_range:
                    length = min(byte_range[1] - start_range + 1, chunk_size)
                else:
                    length = chunk_size
                download_stream = blob.download_blob(offset=start_range, length=length)
                if file_size is None:
                    file_size = download_stream._file_size
                    if byte_range:
                        file_size = min(file_size, byte_range[1] + 1)
                download_stream.readinto(fileobj)
                start_range += download_stream.size
                if start_range >= file_size:
                    break
                if download_stream.size == 0:
                    raise StorageError(f"Empty response received for {key}, range {start_range}-{end_range}")
                end_range += download_stream.size
                if end_range >= file_size:
                    end_range = file_size - 1
                if progress_callback:
                    progress_callback(start_range, file_size)
            except azure.core.exceptions.ResourceNotFoundError as ex:
                if ex.status_code == 416:  # Empty file
                    return
                raise FileNotFoundFromStorageError(key) from ex

    def get_contents_to_fileobj(
        self,
        key: str,
        fileobj_to_store_to: BinaryIO,
        *,
        byte_range: Optional[Tuple[int, int]] = None,
        progress_callback: ProgressProportionCallbackType = None,
    ) -> Metadata:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        self._validate_byte_range(byte_range)

        self.log.debug("Starting to fetch the contents of: %r", path)
        try:
            self._stream_blob(path, fileobj_to_store_to, byte_range, progress_callback)
        except azure.core.exceptions.ResourceNotFoundError as ex:
            raise FileNotFoundFromStorageError(path) from ex

        if progress_callback:
            progress_callback(1, 1)
        return self._metadata_for_key(path)

    def get_file_size(self, key: str) -> int:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        try:
            blob_client = self.get_blob_service_client().get_blob_client(self.container_name, path)
            return blob_client.get_blob_properties().size
        except azure.core.exceptions.ResourceNotFoundError as ex:
            raise FileNotFoundFromStorageError(path) from ex

    def store_file_object(
        self,
        key: str,
        fd: BinaryIO,
        metadata: Optional[Metadata] = None,
        *,
        cache_control: Optional[str] = None,
        mimetype: Optional[str] = None,
        multipart: Optional[bool] = None,
        upload_progress_fn: IncrementalProgressCallbackType = None,
    ) -> None:
        if cache_control is not None:
            raise NotImplementedError("AzureTransfer: cache_control support not implemented")
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        content_settings = None
        if mimetype:
            content_settings = ContentSettings(content_type=mimetype)
        notify_size = [(metadata or {}).get("Content-Length", 0)]

        def progress_callback(pipeline_response: Any) -> None:
            bytes_sent = pipeline_response.context["upload_stream_current"]
            if bytes_sent:
                notify_size[0] = bytes_sent
                if upload_progress_fn:
                    upload_progress_fn(bytes_sent)

        # Azure _BlobChunkUploader calls `tell()` on the stream even though it doesn't use the result.
        # We expect the input stream not to support `tell()` so use dummy implementation for it
        seekable = hasattr(fd, "seekable") and fd.seekable()
        if not seekable:
            original_tell = getattr(fd, "tell", None)
            fd.tell = lambda: None  # type: ignore[assignment,method-assign,return-value]
        sanitized_metadata = self.sanitize_metadata(metadata, replace_hyphen_with="_")
        try:
            blob_client = self.get_blob_service_client().get_blob_client(self.container_name, path)
            blob_client.upload_blob(
                fd,
                blob_type=BlobType.BlockBlob,  # type: ignore[arg-type]
                content_settings=content_settings,
                metadata=sanitized_metadata,
                raw_response_hook=progress_callback,
                overwrite=True,
            )
            self.notifier.object_created(key=key, size=notify_size[0], metadata=sanitized_metadata)
        finally:
            if not seekable:
                if original_tell is not None:
                    fd.tell = original_tell  # type: ignore[method-assign]
                else:
                    delattr(fd, "tell")

    def get_or_create_container(self, container_name: str) -> str:
        if isinstance(container_name, enum.Enum):
            # ensure that the enum value is used rather than the enum name
            # https://github.com/Azure/azure-sdk-for-python/blob/azure-storage-blob_12.8.1/sdk/storage/azure-storage-blob/azure/storage/blob/_blob_service_client.py#L667
            container_name = container_name.value
        start_time = time.monotonic()
        try:
            self.get_blob_service_client().create_container(container_name)
        except ResourceExistsError:
            pass
        except HttpResponseError as e:
            if "request is not authorized" in e.exc_msg:
                self.log.debug("Container creation unauthorized. Assuming container %r already exists", container_name)
                return container_name
            else:
                raise e
        self.log.debug("Got/Created container: %r successfully, took: %.3fs", container_name, time.monotonic() - start_time)
        return container_name
