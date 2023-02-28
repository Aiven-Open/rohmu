"""
rohmu - openstack swift object store interface

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""
from ..common.models import StorageModel
from ..dates import parse_timestamp
from ..errors import FileNotFoundFromStorageError
from ..notifier.interface import Notifier
from .base import (
    BaseTransfer,
    IncrementalProgressCallbackType,
    IterKeyItem,
    KEY_TYPE_OBJECT,
    KEY_TYPE_PREFIX,
    ProgressProportionCallbackType,
)
from contextlib import suppress
from swiftclient import client, exceptions  # pylint: disable=import-error
from typing import Optional

import logging
import os
import time

CHUNK_SIZE = 1024 * 1024 * 5  # 5 Mi
SEGMENT_SIZE = 1024 * 1024 * 1024 * 3  # 3 Gi


# Swift client logs excessively at INFO level, outputting things like a curl
# command line to recreate the request that failed with a simple 404 error.
# At WARNING level curl commands are not logged, but we get a full ugly
# traceback for all failures, including 404s.  Monkey-patch them away.
def swift_exception_logger(err):
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


class Config(StorageModel):
    user: str
    key: str
    container_name: str
    auth_url: str
    auth_version: str = "2.0"
    tenant_name: Optional[str] = None
    segment_size: int = SEGMENT_SIZE
    region_name: Optional[str] = None
    user_id: Optional[str] = None
    user_domain_id: Optional[str] = None
    user_domain_name: Optional[str] = None
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    project_domain_id: Optional[str] = None
    project_domain_name: Optional[str] = None
    service_type: Optional[str] = None
    endpoint_type: Optional[str] = None


class SwiftTransfer(BaseTransfer[Config]):
    config_model = Config

    def __init__(
        self,
        *,
        user,
        key,
        container_name,
        auth_url,
        auth_version="2.0",
        tenant_name=None,
        prefix=None,
        segment_size=SEGMENT_SIZE,
        region_name=None,
        user_id=None,
        user_domain_id=None,
        user_domain_name=None,
        tenant_id=None,
        project_id=None,
        project_name=None,
        project_domain_id=None,
        project_domain_name=None,
        service_type=None,
        endpoint_type=None,
        notifier: Optional[Notifier] = None,
    ) -> None:
        prefix = prefix.lstrip("/") if prefix else ""
        super().__init__(prefix=prefix, notifier=notifier)
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
        else:
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
    def _headers_to_metadata(headers):
        return {name[len("x-object-meta-") :]: value for name, value in headers.items() if name.startswith("x-object-meta-")}

    @staticmethod
    def _metadata_to_headers(metadata):
        return {"x-object-meta-{}".format(name): str(value) for name, value in metadata.items()}

    def get_metadata_for_key(self, key):
        path = self.format_key_for_backend(key)
        return self._metadata_for_key(path)

    def _metadata_for_key(self, key, *, resolve_manifest=False):
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

    def iter_key(self, key, *, with_metadata=True, deep=False, include_key=False):
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
                #   https://docs.openstack.org/api-ref/object-store/?expanded=list-endpoints-detail,show-container-details-and-list-objects-detail # pylint: disable=line-too-long
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

    def _delete_object_plain(self, key):
        try:
            return self.conn.delete_object(self.container_name, key)
        except exceptions.ClientException as ex:
            if ex.http_status == 404:
                raise FileNotFoundFromStorageError(key)
            raise

    def _delete_object_segments(self, key, manifest):
        self._delete_object_plain(key)
        seg_container, seg_prefix = manifest.split("/", 1)
        _, segments = self.conn.get_container(seg_container, prefix=seg_prefix, delimiter="/")
        for item in segments:
            if "name" in item:
                with suppress(FileNotFoundFromStorageError):
                    self._delete_object_plain(item["name"])

    def delete_key(self, key):
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

    def get_contents_to_file(self, key, filepath_to_store_to, *, progress_callback: ProgressProportionCallbackType = None):
        temp_filepath = "{}~".format(filepath_to_store_to)
        try:
            with open(temp_filepath, "wb") as fp:
                metadata = self.get_contents_to_fileobj(key, fp, progress_callback=progress_callback)
                os.rename(temp_filepath, filepath_to_store_to)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temp_filepath)
        return metadata

    def get_contents_to_fileobj(self, key, fileobj_to_store_to, *, progress_callback: ProgressProportionCallbackType = None):
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

    def get_contents_to_string(self, key):
        path = self.format_key_for_backend(key)
        self.log.debug("Starting to fetch the contents of: %r", path)
        try:
            headers, data = self.conn.get_object(self.container_name, path)
        except exceptions.ClientException as ex:
            if ex.http_status == 404:
                raise FileNotFoundFromStorageError(path)
            raise

        metadata = self._headers_to_metadata(headers)
        return data, metadata

    def get_file_size(self, key):
        # Not implemented due to lack of environment where to test this. This method is not required by
        # PGHoard itself, this is only called by external apps that utilize PGHoard's object storage abstraction.
        raise NotImplementedError

    def store_file_from_memory(self, key, memstring, metadata=None, cache_control=None, mimetype=None):
        if cache_control is not None:
            raise NotImplementedError("SwiftTransfer: cache_control support not implemented")

        path = self.format_key_for_backend(key)
        sanitized_metadata = self.sanitize_metadata(metadata)
        metadata_to_send = self._metadata_to_headers(sanitized_metadata)
        data = bytes(memstring)
        self.conn.put_object(self.container_name, path, contents=data, content_type=mimetype, headers=metadata_to_send)
        self.notifier.object_created(key=key, size=len(data), metadata=sanitized_metadata)

    def store_file_from_disk(
        self,
        key,
        filepath,
        metadata=None,
        multipart=None,
        cache_control=None,
        mimetype=None,
        progress_fn: ProgressProportionCallbackType = None,
    ):
        obsz = os.path.getsize(filepath)
        with open(filepath, "rb") as fp:
            self._store_file_contents(
                key,
                fp,
                metadata=metadata,
                multipart=multipart,
                cache_control=cache_control,
                mimetype=mimetype,
                content_length=obsz,
                upload_progress_fn=self._incremental_to_proportional_progress(cb=progress_fn, size=obsz),
            )
        self.notifier.object_created(key=key, size=obsz, metadata=self.sanitize_metadata(metadata))

    def get_or_create_container(self, container_name):
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

    def copy_file(self, *, source_key, destination_key, metadata=None, **_kwargs):
        source_key = self.format_key_for_backend(source_key)
        destination_key = "/".join((self.container_name, self.format_key_for_backend(destination_key)))
        sanitized_metadata = self.sanitize_metadata(metadata)
        headers = self._metadata_to_headers(sanitized_metadata)
        if metadata:
            headers["X-Fresh-Metadata"] = True
        self.conn.copy_object(self.container_name, source_key, destination=destination_key, headers=headers)
        self.notifier.object_copied(key=destination_key, size=None, metadata=sanitized_metadata)

    def store_file_object(
        self,
        key,
        fd,
        *,
        cache_control=None,
        metadata=None,
        mimetype=None,
        upload_progress_fn: IncrementalProgressCallbackType = None,
    ):
        metadata = metadata or {}
        content_length = metadata.get("Content-Length")

        self._store_file_contents(
            key,
            fd,
            cache_control=cache_control,
            metadata=metadata,
            mimetype=mimetype,
            upload_progress_fn=upload_progress_fn,
            multipart=True,
            content_length=content_length,
        )
        self.notifier.object_created(key=key, size=content_length, metadata=self.sanitize_metadata(metadata))

    def _store_file_contents(
        self,
        key,
        fp,
        cache_control=None,
        metadata=None,
        mimetype=None,
        upload_progress_fn: IncrementalProgressCallbackType = None,
        multipart=None,
        content_length=None,
    ):
        if cache_control is not None:
            raise NotImplementedError("SwiftTransfer: cache_control support not implemented")

        if multipart:
            # Start by trying to delete the file - if it's a potential multipart file we need to manually
            # delete it, otherwise old segments won't be cleaned up by anything.  Note that we only issue
            # deletes with the store_file_from_disk functions, store_file_from_memory is used to upload smaller
            # chunks.
            with suppress(FileNotFoundFromStorageError):
                self.delete_key(key)
        path = self.format_key_for_backend(key)
        headers = self._metadata_to_headers(self.sanitize_metadata(metadata))
        # Fall back to the "one segment" if possible
        if (not multipart) or (not content_length) or content_length <= self.segment_size:
            self.log.debug("Uploading %r to %r (%r bytes)", fp, path, content_length)
            self.conn.put_object(self.container_name, path, contents=fp, content_length=content_length, headers=headers)
            if upload_progress_fn:
                upload_progress_fn(content_length)
            return

        # Segmented transfer
        # upload segments of a file like `backup-bucket/site-name/basebackup/2016-03-22_0`
        # to as `backup-bucket/site-name/basebackup_segments/2016-03-22_0/{:08x}`
        segment_no = 0
        segment_path = "{}_segments/{}/".format(os.path.dirname(path), os.path.basename(path))
        segment_key_format = "{}{{:08x}}".format(segment_path).format
        remaining = content_length
        while remaining > 0:
            this_segment_size = min(self.segment_size, remaining)
            remaining -= this_segment_size
            segment_no += 1
            self.log.debug("Uploading segment %r of %r to %r (%r bytes)", segment_no, fp, path, this_segment_size)
            segment_key = segment_key_format(segment_no)  # pylint: disable=too-many-format-args
            self.conn.put_object(
                self.container_name, segment_key, contents=fp, content_length=this_segment_size, content_type=mimetype
            )
            if upload_progress_fn:
                upload_progress_fn(content_length - remaining)
        self.log.info("Uploaded %r segments of %r to %r", segment_no, path, segment_path)
        headers["x-object-manifest"] = "{}/{}".format(self.container_name, segment_path.lstrip("/"))
        self.conn.put_object(self.container_name, path, contents="", headers=headers, content_length=0)
