# Copyright (c) 2016 Ohmu Ltd
# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""Rohmu - openstack swift object store interface"""

from __future__ import annotations

from contextlib import suppress
from rohmu.common.statsd import StatsdConfig
from rohmu.dates import parse_timestamp
from rohmu.errors import FileNotFoundFromStorageError
from rohmu.notifier.interface import Notifier
from rohmu.object_storage.base import (
    BaseTransfer,
    IncrementalProgressCallbackType,
    IterKeyItem,
    KEY_TYPE_OBJECT,
    KEY_TYPE_PREFIX,
    ProgressProportionCallbackType,
)
from rohmu.object_storage.config import (
    SWIFT_CHUNK_SIZE as CHUNK_SIZE,
    SWIFT_SEGMENT_SIZE as SEGMENT_SIZE,
    SwiftObjectStorageConfig as Config,
)
from rohmu.typing import Metadata
from swiftclient import client, exceptions
from typing import Any, BinaryIO, Iterator, Optional, Tuple

import logging
import os
import time


# Swift client logs excessively at INFO level, outputting things like a curl
# command line to recreate the request that failed with a simple 404 error.
# At WARNING level curl commands are not logged, but we get a full ugly
# traceback for all failures, including 404s.  Monkey-patch them away.
def swift_exception_logger(err: BaseException) -> Any:
    if not isinstance(err, exceptions.ClientException):
        return orig_swift_exception_logger(err)
    if getattr(err, "http_status", None) is None:
        return orig_swift_exception_logger(err)
    if err.http_status == 404 and err.msg.startswith("Object GET failed"):
        client.logger.debug("GET %r FAILED: %r", err.http_path, err.http_status)
    else:
        client.logger.error(str(err))
    return None


orig_swift_exception_logger = client.logger.exception
client.logger.exception = swift_exception_logger
logging.getLogger("swiftclient").setLevel(logging.WARNING)


class SwiftTransfer(BaseTransfer[Config]):
    config_model = Config

    def __init__(
        self,
        *,
        user: str,
        key: str,
        container_name: str,
        auth_url: str,
        auth_version: str = "2.0",
        tenant_name: Optional[str] = None,
        prefix: Optional[str] = None,
        segment_size: int = SEGMENT_SIZE,
        region_name: Optional[str] = None,
        user_id: Optional[str] = None,
        user_domain_id: Optional[str] = None,
        user_domain_name: Optional[str] = None,
        tenant_id: Optional[str] = None,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
        project_domain_id: Optional[str] = None,
        project_domain_name: Optional[str] = None,
        service_type: Optional[str] = None,
        endpoint_type: Optional[str] = None,
        notifier: Optional[Notifier] = None,
        statsd_info: Optional[StatsdConfig] = None,
    ) -> None:
        prefix = prefix.lstrip("/") if prefix else ""
        super().__init__(prefix=prefix, notifier=notifier, statsd_info=statsd_info)
        self.container_name = container_name

        if auth_version == "3.0":
            os_options = {
                "region_name": region_name,
                "user_id": user_id,
                "user_domain_id": user_domain_id,
                "user_domain_name": user_domain_name,
                "tenant_id": tenant_id,
                "project_id": project_id,
                "project_name": project_name,
                "project_domain_id": project_domain_id,
                "project_domain_name": project_domain_name,
                "service_type": service_type,
                "endpoint_type": endpoint_type,
            }
        else:  # noqa: PLR5501
            if region_name is not None:
                os_options = {"region_name": region_name}
            else:
                os_options = None

        self.conn = client.Connection(
            user=user, key=key, authurl=auth_url, tenant_name=tenant_name, auth_version=auth_version, os_options=os_options
        )
        self.container = self.get_or_create_container(self.container_name)
        self.segment_size = segment_size
        self.log.debug("SwiftTransfer initialized")

    @staticmethod
    def _headers_to_metadata(headers: dict[str, str]) -> Metadata:
        return {name[len("x-object-meta-") :]: value for name, value in headers.items() if name.startswith("x-object-meta-")}

    @staticmethod
    def _metadata_to_headers(metadata: Metadata) -> dict[str, str]:
        return {f"x-object-meta-{name}": str(value) for name, value in metadata.items()}

    def get_metadata_for_key(self, key: str) -> Metadata:
        path = self.format_key_for_backend(key)
        return self._metadata_for_key(path)

    def _metadata_for_key(self, key: str, *, resolve_manifest: bool = False) -> Metadata:
        try:
            headers = self.conn.head_object(self.container_name, key)
        except exceptions.ClientException as ex:
            if ex.http_status == 404:
                raise FileNotFoundFromStorageError(key)
            raise

        metadata = self._headers_to_metadata(headers)

        if resolve_manifest and "x-object-manifest" in headers:
            manifest = headers["x-object-manifest"]
            seg_container, seg_prefix = manifest.split("/", 1)
            _, segments = self.conn.get_container(seg_container, prefix=seg_prefix, delimiter="/")
            segments_size = sum(item["bytes"] for item in segments if "bytes" in item)
            metadata["_segments_size"] = segments_size

        return metadata

    def iter_key(
        self, key: str, *, with_metadata: bool = True, deep: bool = False, include_key: bool = False
    ) -> Iterator[IterKeyItem]:
        path = self.format_key_for_backend(key, remove_slash_prefix=True, trailing_slash=not include_key)
        self.log.debug("Listing path %r", path)
        if not deep:
            kwargs = {"delimiter": "/"}
        else:
            kwargs = {}
        _, results = self.conn.get_container(self.container_name, prefix=path, full_listing=True, **kwargs)
        for item in results:
            if "subdir" in item:
                yield IterKeyItem(type=KEY_TYPE_PREFIX, value=self.format_key_from_backend(item["subdir"]).rstrip("/"))
            else:
                if with_metadata:
                    metadata = self._metadata_for_key(item["name"], resolve_manifest=True)
                    segments_size = metadata.pop("_segments_size", 0)
                else:
                    metadata = None
                    segments_size = 0
                last_modified = parse_timestamp(item["last_modified"])

                # Response format is documented at:
                #
                #   https://docs.openstack.org/api-ref/object-store/?expanded=list-endpoints-detail,show-container-details-and-list-objects-detail # noqa: E501
                yield IterKeyItem(
                    type=KEY_TYPE_OBJECT,
                    value={
                        "name": self.format_key_from_backend(item["name"]),
                        "size": item["bytes"] + segments_size,
                        "last_modified": last_modified,
                        "metadata": metadata,
                        "hash": item["hash"],
                    },
                )

    def _delete_object_plain(self, key: str) -> None:
        try:
            return self.conn.delete_object(self.container_name, key)
        except exceptions.ClientException as ex:
            if ex.http_status == 404:
                raise FileNotFoundFromStorageError(key)
            raise

    def _delete_object_segments(self, key: str, manifest: str) -> None:
        self._delete_object_plain(key)
        seg_container, seg_prefix = manifest.split("/", 1)
        _, segments = self.conn.get_container(seg_container, prefix=seg_prefix, delimiter="/")
        for item in segments:
            if "name" in item:
                with suppress(FileNotFoundFromStorageError):
                    self._delete_object_plain(item["name"])

    def delete_key(self, key: str) -> None:
        path = self.format_key_for_backend(key)
        self.log.debug("Deleting key: %r", path)
        try:
            headers = self.conn.head_object(self.container_name, path)
        except exceptions.ClientException as ex:
            if ex.http_status == 404:
                raise FileNotFoundFromStorageError(path)
            raise
        if "x-object-manifest" in headers:
            self._delete_object_segments(path, headers["x-object-manifest"])
        else:
            self._delete_object_plain(path)
        self.notifier.object_deleted(key=key)

    def get_contents_to_fileobj(
        self,
        key: str,
        fileobj_to_store_to: BinaryIO,
        *,
        byte_range: Optional[Tuple[int, int]] = None,
        progress_callback: ProgressProportionCallbackType = None,
    ) -> Metadata:
        if byte_range:
            # TODO if someday relevant. swift API itself implements it,
            # c.f. https://docs.openstack.org/api-ref/object-store/
            raise NotImplementedError("byte range fetching not supported")
        path = self.format_key_for_backend(key)
        try:
            headers, data_gen = self.conn.get_object(self.container_name, path, resp_chunk_size=CHUNK_SIZE)
        except exceptions.ClientException as ex:
            if ex.http_status == 404:
                raise FileNotFoundFromStorageError(path)
            raise

        content_len = int(headers.get("content-length") or 0)
        current_pos = 0
        for chunk in data_gen:
            fileobj_to_store_to.write(chunk)
            if progress_callback:
                if not content_len:
                    # if content length is not known we'll always say we're half-way there
                    progress_callback(1, 2)
                else:
                    current_pos += len(chunk)
                    progress_callback(current_pos, content_len)

        return self._headers_to_metadata(headers)

    def get_file_size(self, key: str) -> int:
        # Not implemented due to lack of environment where to test this. This method is not required by
        # PGHoard itself, this is only called by external apps that utilize PGHoard's object storage abstraction.
        raise NotImplementedError

    def get_or_create_container(self, container_name: str) -> str:
        start_time = time.monotonic()
        try:
            self.conn.get_container(container_name, headers={}, limit=1)  # Limit 1 here to not traverse the entire folder
        except exceptions.ClientException as ex:
            if ex.http_status == 404:
                self.conn.put_container(container_name, headers={})
                self.log.debug(
                    "Created container: %r successfully, took: %.3fs",
                    container_name,
                    time.monotonic() - start_time,
                )
                return container_name
            raise
        return container_name

    def copy_file(
        self, *, source_key: str, destination_key: str, metadata: Optional[Metadata] = None, **_kwargs: Any
    ) -> None:
        source_key = self.format_key_for_backend(source_key)
        destination_key = "/".join((self.container_name, self.format_key_for_backend(destination_key)))
        sanitized_metadata = self.sanitize_metadata(metadata)
        headers: Metadata = self._metadata_to_headers(sanitized_metadata)
        if metadata:
            headers["X-Fresh-Metadata"] = True
        self.conn.copy_object(self.container_name, source_key, destination=destination_key, headers=headers)
        self.notifier.object_copied(key=destination_key, size=None, metadata=sanitized_metadata)

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
        metadata = metadata or {}
        content_length = metadata.get("Content-Length")
        multipart = self._should_multipart(
            fd=fd, chunk_size=self.segment_size, default=True, metadata=metadata, multipart=multipart
        )
        self._store_file_contents(
            key,
            fd,
            cache_control=cache_control,
            metadata=metadata,
            mimetype=mimetype,
            upload_progress_fn=upload_progress_fn,
            multipart=multipart,
            content_length=content_length,
        )
        self.notifier.object_created(key=key, size=content_length, metadata=self.sanitize_metadata(metadata))

    def _store_file_contents(
        self,
        key: str,
        fp: BinaryIO,
        cache_control: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        mimetype: Optional[str] = None,
        upload_progress_fn: IncrementalProgressCallbackType = None,
        multipart: Optional[bool] = None,
        content_length: Optional[int] = None,
    ) -> None:
        if cache_control is not None:
            raise NotImplementedError("SwiftTransfer: cache_control support not implemented")

        if multipart:
            # Start by trying to delete the file - if it's a potential multipart file we need to manually
            # delete it, otherwise old segments won't be cleaned up by anything.
            # chunks.
            with suppress(FileNotFoundFromStorageError):
                self.delete_key(key)
        path = self.format_key_for_backend(key)
        headers = self._metadata_to_headers(self.sanitize_metadata(metadata))
        # Fall back to the "one segment" if possible
        if (not multipart) or (not content_length) or content_length <= self.segment_size:
            self.log.debug("Uploading %r to %r (%r bytes)", fp, path, content_length)
            self.conn.put_object(self.container_name, path, contents=fp, content_length=content_length, headers=headers)
            if upload_progress_fn and content_length is not None:
                upload_progress_fn(content_length)
            return

        # Segmented transfer
        # upload segments of a file like `backup-bucket/site-name/basebackup/2016-03-22_0`
        # to as `backup-bucket/site-name/basebackup_segments/2016-03-22_0/{:08x}`
        segment_no = 0
        dirname = os.path.dirname(path)
        basename = os.path.basename(path)
        segment_path = f"{dirname}_segments/{basename}/"
        remaining = content_length
        while remaining > 0:
            this_segment_size = min(self.segment_size, remaining)
            remaining -= this_segment_size
            segment_no += 1
            self.log.debug("Uploading segment %r of %r to %r (%r bytes)", segment_no, fp, path, this_segment_size)
            segment_key = f"{segment_path}{segment_no:08x}"
            self.conn.put_object(
                self.container_name, segment_key, contents=fp, content_length=this_segment_size, content_type=mimetype
            )
            if upload_progress_fn:
                upload_progress_fn(content_length - remaining)
        self.log.info("Uploaded %r segments of %r to %r", segment_no, path, segment_path)
        segment_path_stripped = segment_path.lstrip("/")
        headers["x-object-manifest"] = f"{self.container_name}/{segment_path_stripped}"
        self.conn.put_object(self.container_name, path, contents="", headers=headers, content_length=0)
