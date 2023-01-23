"""
rohmu - aws s3 object store interface

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""
from ..errors import FileNotFoundFromStorageError, InvalidConfigurationError, StorageError
from ..notifier.interface import Notifier
from .base import (
    BaseTransfer,
    get_total_memory,
    IncrementalProgressCallbackType,
    IterKeyItem,
    KEY_TYPE_OBJECT,
    KEY_TYPE_PREFIX,
    ProgressProportionCallbackType,
)
from mypy_boto3_s3.client import S3Client
from mypy_boto3_s3.type_defs import CompletedPartTypeDef
from typing import Dict, Optional

import boto3
import botocore.client
import botocore.config
import botocore.exceptions
import botocore.session
import math
import os
import time


def calculate_chunk_size():
    total_mem_mib = get_total_memory() or 0
    # At least 5 MiB, at most 524 MiB. Max block size used for hosts with ~210+ GB of memory
    return max(min(int(total_mem_mib / 400), 524), 5) * 1024 * 1024


def get_proxy_url(proxy_info):
    username = proxy_info.get("user")
    password = proxy_info.get("pass")
    if username and password:
        auth = f"{username}:{password}@"
    else:
        auth = ""
    host = proxy_info["host"]
    port = proxy_info["port"]
    if proxy_info.get("type") in {"socks5", "socks5h"}:
        schema = proxy_info.get("type")
    else:
        schema = "http"
    proxy_url = f"{schema}://{auth}{host}:{port}"
    return proxy_url


# Set chunk size based on host memory. S3 supports up to 10k chunks and up to 5 TiB individual
# files. Minimum chunk size is 5 MiB, which means max ~50 GB files can be uploaded. In order to get
# to that 5 TiB increase the block size based on host memory; we don't want to use the max for all
# hosts to avoid allocating too large portion of all available memory.
MULTIPART_CHUNK_SIZE = calculate_chunk_size()
READ_BLOCK_SIZE = 1024 * 1024 * 1


class S3Transfer(BaseTransfer):
    s3_client: S3Client

    def __init__(
        self,
        region,
        bucket_name,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        prefix=None,
        host=None,
        port=None,
        is_secure=False,
        is_verify_tls=False,
        segment_size=MULTIPART_CHUNK_SIZE,
        encrypted=False,
        proxy_info=None,
        connect_timeout=None,
        read_timeout=None,
        notifier: Optional[Notifier] = None,
        aws_session_token: Optional[str] = None,
    ) -> None:
        super().__init__(prefix=prefix, notifier=notifier)
        session = boto3.Session()
        self.bucket_name = bucket_name
        self.location = ""
        self.region = region
        timeouts = {}
        if connect_timeout:
            timeouts["connect_timeout"] = connect_timeout
        if read_timeout:
            timeouts["read_timeout"] = read_timeout
        if not host or not port:
            custom_config = {**timeouts}
            if proxy_info:
                proxy_url = get_proxy_url(proxy_info)
                custom_config["proxies"] = {"https": proxy_url}
            self.s3_client = session.client(
                "s3",
                config=botocore.config.Config(**custom_config),
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                region_name=region,
            )
            if self.region and self.region != "us-east-1":
                self.location = self.region
        else:
            scheme = "https" if is_secure else "http"
            custom_url = "{scheme}://{host}:{port}".format(scheme=scheme, host=host, port=port)
            if self.region:
                signature_version = "s3v4"
                self.location = self.region
            else:
                signature_version = "s3"
            proxies: Optional[Dict[str, str]] = None
            if proxy_info:
                proxies = {"https": get_proxy_url(proxy_info)}
            boto_config = botocore.client.Config(
                s3={"addressing_style": "path"},
                signature_version=signature_version,
                proxies=proxies,
                **timeouts,
            )
            self.s3_client = session.client(
                "s3",
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                config=boto_config,
                endpoint_url=custom_url,
                region_name=region,
                verify=is_verify_tls,
            )

        self.check_or_create_bucket()

        self.multipart_chunk_size = segment_size
        self.encrypted = encrypted
        self.log.debug("S3Transfer initialized")

    def copy_file(self, *, source_key, destination_key, metadata=None, **_kwargs):
        source_path = self.bucket_name + "/" + self.format_key_for_backend(source_key, remove_slash_prefix=True)
        destination_path = self.format_key_for_backend(destination_key, remove_slash_prefix=True)
        try:
            self.s3_client.copy_object(
                Bucket=self.bucket_name,
                CopySource=source_path,
                Key=destination_path,
                Metadata=metadata or {},
                MetadataDirective="COPY" if metadata is None else "REPLACE",
            )
            self.notifier.object_copied(key=destination_key, size=None, metadata=metadata)
        except botocore.exceptions.ClientError as ex:
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 404:
                raise FileNotFoundFromStorageError(source_key)
            else:
                raise StorageError("Copying {!r} to {!r} failed: {!r}".format(source_key, destination_key, ex)) from ex

    def get_metadata_for_key(self, key):
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        return self._metadata_for_key(path)

    def _metadata_for_key(self, key):
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=key)
        except botocore.exceptions.ClientError as ex:
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 404:
                raise FileNotFoundFromStorageError(key)
            else:
                raise StorageError("Metadata lookup failed for {}".format(key)) from ex

        return response["Metadata"]

    def delete_key(self, key):
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        self.log.debug("Deleting key: %r", path)
        self._metadata_for_key(path)  # check that key exists
        self.s3_client.delete_object(Bucket=self.bucket_name, Key=path)
        self.notifier.object_deleted(key=key)

    def delete_tree(self, key):
        path = self.format_key_for_backend(key, remove_slash_prefix=True, trailing_slash=True)
        self.log.debug("Deleting tree: %r", path)
        objects_to_delete = self.s3_client.list_objects(Bucket=self.bucket_name, Prefix=path)
        delete_keys = [{"Key": key} for key in [obj["Key"] for obj in objects_to_delete.get("Contents", [])]]
        if delete_keys:
            self.s3_client.delete_objects(Bucket=self.bucket_name, Delete={"Objects": delete_keys})
            # Note: `tree_deleted` is not used here because the operation on S3 is not atomic, i.e.
            # it is possible for a new object to be created after `list_objects` above
            for obj in delete_keys:
                self.notifier.object_deleted(key=obj["Key"])

    def iter_key(self, key, *, with_metadata=True, deep=False, include_key=False):
        path = self.format_key_for_backend(key, remove_slash_prefix=True, trailing_slash=not include_key)
        self.log.debug("Listing path %r", path)
        continuation_token = None
        while True:
            args = {
                "Bucket": self.bucket_name,
                "Prefix": path,
            }
            if not deep:
                args["Delimiter"] = "/"
            if continuation_token:
                args["ContinuationToken"] = continuation_token
            response = self.s3_client.list_objects_v2(**args)

            for item in response.get("Contents", []):
                if with_metadata:
                    metadata = {k.lower(): v for k, v in self._metadata_for_key(item["Key"]).items()}
                else:
                    metadata = None
                name = self.format_key_from_backend(item["Key"])
                yield IterKeyItem(
                    type=KEY_TYPE_OBJECT,
                    value={
                        "last_modified": item["LastModified"],
                        "md5": item["ETag"].strip('"'),
                        "metadata": metadata,
                        "name": name,
                        "size": item["Size"],
                    },
                )

            for common_prefix in response.get("CommonPrefixes", []):
                yield IterKeyItem(
                    type=KEY_TYPE_PREFIX,
                    value=self.format_key_from_backend(common_prefix["Prefix"]).rstrip("/"),
                )

            if "NextContinuationToken" in response:
                continuation_token = response["NextContinuationToken"]
            else:
                break

    def _get_object_stream(self, key):
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=path,
            )
        except botocore.exceptions.ClientError as ex:
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 404:
                raise FileNotFoundFromStorageError(path)
            else:
                raise StorageError("Fetching the remote object {} failed".format(path)) from ex
        return response["Body"], response["ContentLength"], response["Metadata"]

    def _read_object_to_fileobj(self, fileobj, streaming_body, body_length, cb: ProgressProportionCallbackType = None):
        data_read = 0
        while data_read < body_length:
            read_amount = body_length - data_read
            if read_amount > READ_BLOCK_SIZE:
                read_amount = READ_BLOCK_SIZE
            data = streaming_body.read(amt=read_amount)
            fileobj.write(data)
            data_read += len(data)
            if cb:
                cb(data_read, body_length)
        if cb:
            cb(data_read, body_length)

    def get_contents_to_file(self, key, filepath_to_store_to, *, progress_callback: ProgressProportionCallbackType = None):
        with open(filepath_to_store_to, "wb") as fh:
            stream, length, metadata = self._get_object_stream(key)
            self._read_object_to_fileobj(fh, stream, length, cb=progress_callback)
        return metadata

    def get_contents_to_fileobj(self, key, fileobj_to_store_to, *, progress_callback: ProgressProportionCallbackType = None):
        stream, length, metadata = self._get_object_stream(key)
        self._read_object_to_fileobj(fileobj_to_store_to, stream, length, cb=progress_callback)
        return metadata

    def get_contents_to_string(self, key):
        stream, _, metadata = self._get_object_stream(key)
        data = stream.read()
        return data, metadata

    def get_file_size(self, key):
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=path)
            return int(response["ContentLength"])
        except botocore.exceptions.ClientError as ex:
            if ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
                raise FileNotFoundFromStorageError(path)
            else:
                raise StorageError("File size lookup failed for {}".format(path)) from ex

    def store_file_from_memory(self, key, memstring, metadata=None, cache_control=None, mimetype=None):
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        data = bytes(memstring)  # make sure Body is of type bytes as memoryview's not allowed, only bytes/bytearrays
        args = {
            "Bucket": self.bucket_name,
            "Body": data,
            "Key": path,
        }
        sanitized_metadata = metadata
        if metadata:
            sanitized_metadata = args["Metadata"] = self.sanitize_metadata(metadata)
        if self.encrypted:
            args["ServerSideEncryption"] = "AES256"
        if cache_control is not None:
            args["CacheControl"] = cache_control
        if mimetype is not None:
            args["ContentType"] = mimetype
        self.s3_client.put_object(**args)
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
        size = os.path.getsize(filepath)
        if not multipart or size <= self.multipart_chunk_size:
            with open(filepath, "rb") as fh:
                data = fh.read()
                self.store_file_from_memory(key, data, metadata, cache_control=cache_control)
            if progress_fn:
                progress_fn(size, size)
            return

        with open(filepath, "rb") as fp:
            self.multipart_upload_file_object(
                cache_control=cache_control,
                fp=fp,
                key=key,
                metadata=metadata,
                mimetype=mimetype,
                size=size,
                progress_fn=progress_fn,
            )
            sanitized_metadata = self.sanitize_metadata(metadata)
            self.notifier.object_created(key=key, size=size, metadata=sanitized_metadata)
        if progress_fn:
            progress_fn(size, size)

    def multipart_upload_file_object(
        self, *, cache_control, fp, key, metadata, mimetype, progress_fn: ProgressProportionCallbackType = None, size=None
    ):
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        start_of_multipart_upload = time.monotonic()
        bytes_sent = 0

        chunks: int = 1
        if size is not None:
            chunks = math.ceil(size / self.multipart_chunk_size)
        self.log.debug("Starting to upload multipart file: %r, size: %s, chunks: %s", path, size, chunks)

        parts: list[CompletedPartTypeDef] = []
        part_number = 1

        args = {
            "Bucket": self.bucket_name,
            "Key": path,
        }
        sanitized_metadata = metadata
        if metadata:
            sanitized_metadata = args["Metadata"] = self.sanitize_metadata(metadata)
        if self.encrypted:
            args["ServerSideEncryption"] = "AES256"
        if cache_control is not None:
            args["CacheControl"] = cache_control
        if mimetype is not None:
            args["ContentType"] = mimetype
        try:
            cmu_response = self.s3_client.create_multipart_upload(**args)
        except botocore.exceptions.ClientError as ex:
            raise StorageError("Failed to initiate multipart upload for {}".format(path)) from ex

        mp_id = cmu_response["UploadId"]

        while True:
            data = self._read_bytes(fp, self.multipart_chunk_size)
            if not data:
                break

            attempts = 10
            start_of_part_upload = time.monotonic()
            while True:
                attempts -= 1
                try:
                    cup_response = self.s3_client.upload_part(
                        Body=data,
                        Bucket=self.bucket_name,
                        Key=path,
                        PartNumber=part_number,
                        UploadId=mp_id,
                    )
                except botocore.exceptions.ClientError as ex:
                    self.log.exception("Uploading part %d for %s failed, attempts left: %d", part_number, path, attempts)
                    if attempts <= 0:
                        try:
                            self.s3_client.abort_multipart_upload(
                                Bucket=self.bucket_name,
                                Key=path,
                                UploadId=mp_id,
                            )
                        finally:
                            err = "Multipart upload of {0} failed: {1.__class__.__name__}: {1}".format(path, ex)
                            raise StorageError(err) from ex
                    else:
                        time.sleep(1.0)
                else:
                    self.log.info(
                        "Uploaded part %s of %s, size %s in %.2fs",
                        part_number,
                        chunks,
                        len(data),
                        time.monotonic() - start_of_part_upload,
                    )
                    parts.append(
                        {
                            "ETag": cup_response["ETag"],
                            "PartNumber": part_number,
                        }
                    )
                    part_number += 1
                    bytes_sent += len(data)
                    if progress_fn:
                        progress_fn(bytes_sent, size)
                    break

        try:
            self.s3_client.complete_multipart_upload(
                Bucket=self.bucket_name,
                Key=path,
                MultipartUpload={"Parts": parts},
                UploadId=mp_id,
            )
        except botocore.exceptions.ClientError as ex:
            try:
                self.s3_client.abort_multipart_upload(
                    Bucket=self.bucket_name,
                    Key=path,
                    UploadId=mp_id,
                )
            finally:
                raise StorageError("Failed to complete multipart upload for {}".format(path)) from ex

        self.notifier.object_created(key=key, size=bytes_sent, metadata=sanitized_metadata)
        self.log.info(
            "Multipart upload of %r complete, size: %r, took: %.2fs",
            path,
            size,
            time.monotonic() - start_of_multipart_upload,
        )

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
        self.multipart_upload_file_object(
            cache_control=cache_control,
            fp=fd,
            key=key,
            metadata=metadata,
            mimetype=mimetype,
            progress_fn=self._proportional_to_incremental_progress(upload_progress_fn),
        )

    def check_or_create_bucket(self):
        create_bucket = False
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
        except botocore.exceptions.ClientError as ex:
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 301:
                raise InvalidConfigurationError("Wrong region for bucket {}, check configuration".format(self.bucket_name))
            elif status_code == 403:
                self.log.warning("Access denied on bucket check, assuming write permissions")
            elif status_code == 404:
                create_bucket = True
            else:
                raise

        if create_bucket:
            self.log.debug("Creating bucket: %r in location: %r", self.bucket_name, self.region)
            args = {
                "Bucket": self.bucket_name,
            }
            if self.location:
                args["CreateBucketConfiguration"] = {
                    "LocationConstraint": self.location,
                }

            self.s3_client.create_bucket(**args)

    @classmethod
    def _read_bytes(cls, stream, length):
        bytes_remaining = length
        read_results = []
        while bytes_remaining > 0:
            data = stream.read(bytes_remaining)
            if data:
                read_results.append(data)
                bytes_remaining -= len(data)
            else:
                break

        if not read_results:
            return None
        elif len(read_results) == 1:
            return read_results[0]
        else:
            return b"".join(read_results)
