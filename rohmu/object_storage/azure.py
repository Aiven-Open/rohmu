"""
rohmu - azure object store interface

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""

from __future__ import annotations

from ..common.models import ProxyInfo, StorageModel
from ..common.statsd import StatsdConfig
from ..notifier.interface import Notifier
from ..typing import Metadata
from .base import IncrementalProgressCallbackType, ProgressProportionCallbackType

# pylint: disable=import-error, no-name-in-module
from azure.core.exceptions import HttpResponseError, ResourceExistsError
from azure.storage.blob import BlobServiceClient, ContentSettings
from typing import Any, BinaryIO, Iterator, Optional, Tuple, Union,

import azure.common
import logging
import time

try:
    from azure.storage.blob import BlobPrefix, BlobType
except ImportError:
    # old versions of the azure blob storage library do not expose the classes publicly
    from azure.storage.blob._models import BlobPrefix, BlobType  # type: ignore

from ..errors import FileNotFoundFromStorageError, InvalidConfigurationError, StorageError
from .base import BaseTransfer, get_total_memory, IterKeyItem, KEY_TYPE_OBJECT, KEY_TYPE_PREFIX

ENDPOINT_SUFFIXES = {
    None: "core.windows.net",
    "germany": "core.cloudapi.de",  # Azure Germany is a completely separate cloud from the regular Azure Public cloud
    "china": "core.chinacloudapi.cn",
    "public": "core.windows.net",
}


def calculate_max_block_size() -> int:
    total_mem_mib = get_total_memory() or 0
    # At least 4 MiB, at most 100 MiB. Max block size used for hosts with ~100+ GB of memory
    return max(min(int(total_mem_mib / 1000), 100), 4) * 1024 * 1024


# Increase block size based on host memory. Azure supports up to 50k blocks and up to 5 TiB individual
# files. Default block size is set to 4 MiB so only ~200 GB files can be uploaded. In order to get close
# to that 5 TiB increase the block size based on host memory; we don't want to use the max 100 for all
# hosts because the uploader will allocate (with default settings) 3 x block size of memory.
MAX_BLOCK_SIZE = calculate_max_block_size()

# Reduce Azure logging verbocity of http requests and responses
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)


class Config(StorageModel):
    bucket_name: str
    account_name: str
    account_key: Optional[str] = None
    sas_token: Optional[str] = None
    prefix: Optional[str] = None
    azure_cloud: Optional[str] = None
    proxy_info: Optional[ProxyInfo] = None


class AzureTransfer(BaseTransfer[Config]):
    config_model = Config

    def __init__(
        self,
        bucket_name: str,
        account_name: str,
        account_key: Optional[str] = None,
        sas_token: Optional[str] = None,
        prefix: Optional[str] = None,
        azure_cloud: Optional[str] = None,
        proxy_info: Optional[dict[str, Union[str, int]]] = None,
        notifier: Optional[Notifier] = None,
        statsd_info: Optional[StatsdConfig] = None,
    ) -> None:
        prefix = "{}".format(prefix.lstrip("/") if prefix else "")
        super().__init__(prefix=prefix, notifier=notifier, statsd_info=statsd_info)
        if not account_key and not sas_token:
            raise InvalidConfigurationError("One of account_key or sas_token must be specified to authenticate")

        self.account_name = account_name
        self.account_key = account_key
        self.container_name = bucket_name
        self.sas_token = sas_token
        try:
            endpoint_suffix = ENDPOINT_SUFFIXES[azure_cloud]
        except KeyError:
            raise InvalidConfigurationError("Unknown azure cloud {!r}".format(azure_cloud))

        conn_str = (
            "DefaultEndpointsProtocol=https;"
            f"AccountName={self.account_name};"
            f"AccountKey={self.account_key};"
            f"EndpointSuffix={endpoint_suffix}"
        )
        config: dict[str, Any] = {"max_block_size": MAX_BLOCK_SIZE}
        if proxy_info:
            username = proxy_info.get("user")
            password = proxy_info.get("pass")
            if username and password:
                auth = f"{username}:{password}@"
            else:
                auth = ""
            host = proxy_info["host"]
            port = proxy_info["port"]
            if proxy_info.get("type") == "socks5":
                schema = "socks5"
            else:
                schema = "http"
            config["proxies"] = {"https": f"{schema}://{auth}{host}:{port}"}

        self.conn: BlobServiceClient = BlobServiceClient.from_connection_string(
            conn_str=conn_str,
            credential=self.sas_token,
            **config,
        )
        self.container = self.get_or_create_container(self.container_name)
        self.log.debug("AzureTransfer initialized, %r", self.container_name)

    def copy_file(
        self, *, source_key: str, destination_key: str, metadata: Optional[Metadata] = None, **kwargs: Any
    ) -> None:
        timeout = kwargs.get("timeout") or 15
        source_path = self.format_key_for_backend(source_key, remove_slash_prefix=True, trailing_slash=False)
        destination_path = self.format_key_for_backend(destination_key, remove_slash_prefix=True, trailing_slash=False)
        source_client = self.conn.get_blob_client(self.container_name, source_path)
        destination_client = self.conn.get_blob_client(self.container_name, destination_path)
        source_url = source_client.url
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
                        "Copying {!r} to {!r} did not complete in {} seconds".format(source_key, destination_key, timeout)
                    )
            elif copy_props.status == "failed":
                raise StorageError(
                    "Copying {!r} to {!r} failed: {!r}".format(source_key, destination_key, copy_props.status_description)
                )
            else:
                raise StorageError(
                    "Copying {!r} to {!r} failed, unexpected status: {!r}".format(
                        source_key, destination_key, copy_props.status
                    )
                )

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
        container_client = self.conn.get_container_client(self.container_name)
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
            blob_client = self.conn.get_blob_client(container=self.container_name, blob=path)
            result = blob_client.delete_blob()
        except azure.core.exceptions.ResourceNotFoundError as ex:  # pylint: disable=no-member
            raise FileNotFoundFromStorageError(path) from ex

        self.notifier.object_deleted(key)

        return result

    @classmethod
    def _parse_length_from_content_range(cls, content_range: str) -> int:
        """Parses the blob length from the content range header: bytes 1-3/65537"""
        if not content_range:
            raise ValueError("File size unavailable")

        return int(content_range.split(" ", 1)[1].split("/", 1)[1])

    def _stream_blob(self, key: str, fileobj: BinaryIO, byte_range: Optional[tuple[int, int]], progress_callback: ProgressProportionCallbackType) -> None:
        """Streams contents of given key to given fileobj. Data is read sequentially in chunks
        without any seeks. This requires duplicating some functionality of the Azure SDK, which only
        allows reading entire blob into memory at once or returning data from random offsets"""
        file_size = None
        start_range = byte_range[0] if byte_range else 0
        chunk_size = self.conn._config.max_chunk_get_size  # type: ignore [attr-defined] # pylint: disable=protected-access
        end_range = chunk_size - 1
        blob = self.conn.get_blob_client(self.container_name, key)
        while True:
            try:
                # pylint: disable=protected-access
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
                    raise StorageError("Empty response received for {}, range {}-{}".format(key, start_range, end_range))
                end_range += download_stream.size
                if end_range >= file_size:
                    end_range = file_size - 1
                if progress_callback:
                    progress_callback(start_range, file_size)
            except azure.core.exceptions.ResourceNotFoundError as ex:  # pylint: disable=no-member
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

        self.log.debug("Starting to fetch the contents of: %r", path)
        try:
            self._stream_blob(path, fileobj_to_store_to, byte_range, progress_callback)
        except azure.core.exceptions.ResourceNotFoundError as ex:  # pylint: disable=no-member
            raise FileNotFoundFromStorageError(path) from ex

        if progress_callback:
            progress_callback(1, 1)
        return self._metadata_for_key(path)

    def get_file_size(self, key: str) -> int:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        try:
            blob_client = self.conn.get_blob_client(self.container_name, path)
            return blob_client.get_blob_properties().size
        except azure.core.exceptions.ResourceNotFoundError as ex:  # pylint: disable=no-member
            raise FileNotFoundFromStorageError(path) from ex

    def store_file_object(
        self,
        key: str,
        fd: BinaryIO,
        metadata: Optional[Metadata] = None,
        *,
        cache_control: Optional[str] = None,
        mimetype: Optional[str] = None,
        multipart: Optional[bool] = None,  # pylint: disable=unused-argument
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
            fd.tell = lambda: None  # type: ignore [assignment,method-assign,return-value]
        sanitized_metadata = self.sanitize_metadata(metadata, replace_hyphen_with="_")
        try:
            blob_client = self.conn.get_blob_client(self.container_name, path)
            blob_client.upload_blob(
                fd,
                blob_type=BlobType.BlockBlob,  # type: ignore [arg-type]
                content_settings=content_settings,
                metadata=sanitized_metadata,
                raw_response_hook=progress_callback,
                overwrite=True,
            )
            self.notifier.object_created(key=key, size=notify_size[0], metadata=sanitized_metadata)
        finally:
            if not seekable:
                if original_tell is not None:
                    fd.tell = original_tell  # type: ignore [method-assign]
                else:
                    delattr(fd, "tell")

    def get_or_create_container(self, container_name: str) -> str:
        start_time = time.monotonic()
        try:
            self.conn.create_container(container_name)
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
