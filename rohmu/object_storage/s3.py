"""
rohmu - aws s3 object store interface

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""

from __future__ import annotations

from botocore.response import StreamingBody
from functools import partial
from http import HTTPStatus
from pathlib import Path
from rohmu.common.models import StorageOperation
from rohmu.common.statsd import StatsdConfig
from rohmu.errors import ConcurrentUploadError, FileNotFoundFromStorageError, InvalidConfigurationError, StorageError
from rohmu.notifier.interface import Notifier
from rohmu.object_storage.base import (
    BaseTransfer,
    ConcurrentUpload,
    IncrementalProgressCallbackType,
    IterKeyItem,
    KEY_TYPE_OBJECT,
    KEY_TYPE_PREFIX,
    ProgressProportionCallbackType,
    SourceStorageModelT,
)
from rohmu.object_storage.config import (  # pylint: disable=unused-import
    calculate_s3_chunk_size as calculate_chunk_size,
    S3_MULTIPART_CHUNK_SIZE as MULTIPART_CHUNK_SIZE,
    S3_READ_BLOCK_SIZE as READ_BLOCK_SIZE,
    S3AddressingStyle,
    S3ObjectStorageConfig as Config,
)
from rohmu.typing import Metadata
from rohmu.util import batched, ProgressStream
from typing import Any, BinaryIO, cast, Collection, Iterator, Optional, Tuple, TYPE_CHECKING, Union

import botocore.client
import botocore.config
import botocore.exceptions
import botocore.session
import math
import time

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_s3.type_defs import CompletedPartTypeDef


# botocore typing stubs are incomplete. We either have to write all the stubs we need
# or work around the problem a bit by importing the typing library only for type checking purposes.
def create_s3_client(
    *,
    session: botocore.session.Session,
    config: botocore.config.Config,
    aws_access_key_id: Optional[str],
    aws_secret_access_key: Optional[str],
    aws_session_token: Optional[str],
    region_name: str,
    verify: Optional[bool | str] = None,
    endpoint_url: Optional[str] = None,
) -> S3Client:
    s3_client = session.create_client(
        "s3",
        config=config,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=region_name,
        verify=verify,
        endpoint_url=endpoint_url,
    )

    if TYPE_CHECKING:
        return cast(S3Client, s3_client)
    else:
        return s3_client


def get_proxy_url(proxy_info: dict[str, Union[str, int]]) -> str:
    username = proxy_info.get("user")
    password = proxy_info.get("pass")
    if username and password:
        auth = f"{username}:{password}@"
    else:
        auth = ""
    host = proxy_info["host"]
    port = proxy_info["port"]

    # Socks5h support is experimental
    if proxy_info.get("type") in {"socks5", "socks5h"}:
        schema = proxy_info.get("type")
    else:
        schema = "http"
    proxy_url = f"{schema}://{auth}{host}:{port}"
    return proxy_url


class S3Transfer(BaseTransfer[Config]):
    config_model = Config

    supports_concurrent_upload = True

    def __init__(
        self,
        region: str,
        bucket_name: str,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        prefix: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        addressing_style: S3AddressingStyle = S3AddressingStyle.path,
        is_secure: bool = False,
        is_verify_tls: bool = False,
        cert_path: Optional[Path] = None,
        segment_size: int = MULTIPART_CHUNK_SIZE,
        encrypted: bool = False,
        proxy_info: Optional[dict[str, Union[str, int]]] = None,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        notifier: Optional[Notifier] = None,
        aws_session_token: Optional[str] = None,
        statsd_info: Optional[StatsdConfig] = None,
    ) -> None:
        super().__init__(prefix=prefix, notifier=notifier, statsd_info=statsd_info)
        session = botocore.session.get_session()
        self.bucket_name = bucket_name
        self.location = ""
        self.region = region
        timeouts: dict[str, Any] = {}
        if connect_timeout:
            timeouts["connect_timeout"] = connect_timeout
        if read_timeout:
            timeouts["read_timeout"] = read_timeout
        if not host or not port:
            custom_config: dict[str, Any] = {**timeouts}
            if proxy_info:
                proxy_url = get_proxy_url(proxy_info)
                custom_config["proxies"] = {"https": proxy_url}
            self.s3_client = create_s3_client(
                session=session,
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
            custom_url = f"{scheme}://{host}:{port}"
            if self.region:
                signature_version = "s3v4"
                self.location = self.region
            else:
                signature_version = "s3"
            proxies: Optional[dict[str, str]] = None
            if proxy_info:
                proxies = {"https": get_proxy_url(proxy_info)}
            boto_config = botocore.client.Config(
                s3={"addressing_style": S3AddressingStyle(addressing_style).value},
                signature_version=signature_version,
                proxies=proxies,
                **timeouts,
            )
            if not is_verify_tls and cert_path is not None:
                raise ValueError("cert_path is set but is_verify_tls is False")
            self.s3_client = create_s3_client(
                session=session,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                config=boto_config,
                endpoint_url=custom_url,
                region_name=region,
                verify=str(cert_path) if cert_path is not None and is_verify_tls else is_verify_tls,
            )

        self.check_or_create_bucket()

        self.multipart_chunk_size = segment_size
        self.encrypted = encrypted
        self.log.debug("S3Transfer initialized")

    def copy_file(
        self, *, source_key: str, destination_key: str, metadata: Optional[Metadata] = None, **_kwargs: Any
    ) -> None:
        self._copy_file_from_bucket(
            source_bucket=self, source_key=source_key, destination_key=destination_key, metadata=metadata
        )

    def _copy_file_from_bucket(
        self, *, source_bucket: S3Transfer, source_key: str, destination_key: str, metadata: Optional[Metadata] = None
    ) -> None:
        source_path = (
            source_bucket.bucket_name + "/" + source_bucket.format_key_for_backend(source_key, remove_slash_prefix=True)
        )
        destination_path = self.format_key_for_backend(destination_key, remove_slash_prefix=True)
        self.stats.operation(StorageOperation.copy_file)
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
                raise StorageError(f"Copying {source_key!r} to {destination_key!r} failed: {ex!r}") from ex

    def copy_files_from(self, *, source: BaseTransfer[SourceStorageModelT], keys: Collection[str]) -> None:
        if isinstance(source, S3Transfer):
            for key in keys:
                self._copy_file_from_bucket(source_bucket=source, source_key=key, destination_key=key)
        else:
            raise NotImplementedError

    def get_metadata_for_key(self, key: str) -> Metadata:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        return self._metadata_for_key(path)

    def _metadata_for_key(self, key: str) -> Metadata:
        self.stats.operation(StorageOperation.metadata_for_key)
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=key)
        except botocore.exceptions.ClientError as ex:
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 404:
                raise FileNotFoundFromStorageError(key)
            else:
                raise StorageError(f"Metadata lookup failed for {key}") from ex

        return response["Metadata"]

    def delete_key(self, key: str) -> None:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        self.log.debug("Deleting key: %r", path)
        self._metadata_for_key(path)  # check that key exists
        self.stats.operation(StorageOperation.delete_key)
        self.s3_client.delete_object(Bucket=self.bucket_name, Key=path)
        self.notifier.object_deleted(key=key)

    def delete_keys(self, keys: Collection[str]) -> None:
        self.stats.operation(StorageOperation.delete_key, count=len(keys))
        for batch in batched(keys, 1000):  # Cannot delete more than 1000 objects at a time
            self.s3_client.delete_objects(
                Bucket=self.bucket_name,
                Delete={"Objects": [{"Key": self.format_key_for_backend(key, remove_slash_prefix=True)} for key in batch]},
            )
            # Note: `tree_deleted` is not used here because the operation on S3 is not atomic, i.e.
            # it is possible for a new object to be created after `list_objects` above
            for key in batch:
                self.notifier.object_deleted(key=key)

    def iter_key(
        self, key: str, *, with_metadata: bool = True, deep: bool = False, include_key: bool = False
    ) -> Iterator[IterKeyItem]:
        path = self.format_key_for_backend(key, remove_slash_prefix=True, trailing_slash=not include_key)
        self.log.debug("Listing path %r", path)
        continuation_token = None
        while True:
            args: dict[str, Any] = {
                "Bucket": self.bucket_name,
                "Prefix": path,
            }
            if not deep:
                args["Delimiter"] = "/"
            if continuation_token:
                args["ContinuationToken"] = continuation_token
            self.stats.operation(StorageOperation.iter_key)
            response = self.s3_client.list_objects_v2(**args)

            for item in response.get("Contents", []):
                if with_metadata:
                    try:
                        metadata = {k.lower(): v for k, v in self._metadata_for_key(item["Key"]).items()}
                    except FileNotFoundFromStorageError:
                        continue
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

    def _get_object_stream(self, key: str, byte_range: Optional[tuple[int, int]]) -> tuple[StreamingBody, int, Metadata]:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        kwargs: dict[str, Any] = {}
        if byte_range:
            kwargs["Range"] = f"bytes={byte_range[0]}-{byte_range[1]}"
        try:
            # Actual usage is accounted for in
            # _read_object_to_fileobj, although that omits the initial
            # get_object call if it fails.
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=path, **kwargs)
        except botocore.exceptions.ClientError as ex:
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 404:
                raise FileNotFoundFromStorageError(path)
            else:
                raise StorageError(f"Fetching the remote object {path} failed") from ex
        return response["Body"], response["ContentLength"], response["Metadata"]

    def _read_object_to_fileobj(
        self, fileobj: BinaryIO, streaming_body: StreamingBody, body_length: int, cb: ProgressProportionCallbackType = None
    ) -> None:
        data_read = 0
        while data_read < body_length:
            read_amount = body_length - data_read
            read_amount = min(read_amount, READ_BLOCK_SIZE)
            data = streaming_body.read(amt=read_amount)
            fileobj.write(data)
            data_read += len(data)
            if cb:
                cb(data_read, body_length)
            self.stats.operation(operation=StorageOperation.get_file, size=len(data))
        if cb:
            cb(data_read, body_length)

    def get_contents_to_fileobj(
        self,
        key: str,
        fileobj_to_store_to: BinaryIO,
        *,
        byte_range: Optional[Tuple[int, int]] = None,
        progress_callback: ProgressProportionCallbackType = None,
    ) -> Metadata:
        self._validate_byte_range(byte_range)
        stream, length, metadata = self._get_object_stream(key, byte_range)
        self._read_object_to_fileobj(fileobj_to_store_to, stream, length, cb=progress_callback)
        return metadata

    def get_file_size(self, key: str) -> int:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        self.stats.operation(StorageOperation.get_file_size)
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=path)
            return int(response["ContentLength"])
        except botocore.exceptions.ClientError as ex:
            if ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
                raise FileNotFoundFromStorageError(path)
            else:
                raise StorageError(f"File size lookup failed for {path}") from ex

    def multipart_upload_file_object(
        self,
        *,
        cache_control: Optional[str],
        fp: BinaryIO,
        key: str,
        metadata: Optional[Metadata],
        mimetype: Optional[str],
        progress_fn: ProgressProportionCallbackType = None,
        size: Optional[int] = None,
    ) -> None:
        start_of_multipart_upload = time.monotonic()
        bytes_sent = 0

        chunks: int = 1
        if size is not None:
            chunks = math.ceil(size / self.multipart_chunk_size)
        args, sanitized_metadata, path = self._init_args_for_multipart(key, metadata, mimetype, cache_control)
        self.log.debug("Starting to upload multipart file: %r, size: %s, chunks: %s", path, size, chunks)

        parts: list[CompletedPartTypeDef] = []
        part_number = 1

        self.stats.operation(StorageOperation.create_multipart_upload)
        try:
            cmu_response = self.s3_client.create_multipart_upload(**args)
        except botocore.exceptions.ClientError as ex:
            raise StorageError(f"Failed to initiate multipart upload for {path}") from ex

        mp_id = cmu_response["UploadId"]

        while True:
            data = self._read_bytes(fp, self.multipart_chunk_size)
            if not data:
                break

            attempts = 10
            start_of_part_upload = time.monotonic()
            while True:
                attempts -= 1
                self.stats.operation(StorageOperation.store_file, size=len(data))
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
                        self.stats.operation(StorageOperation.multipart_aborted)
                        try:
                            self.s3_client.abort_multipart_upload(
                                Bucket=self.bucket_name,
                                Key=path,
                                UploadId=mp_id,
                            )
                        finally:
                            err = f"Multipart upload of {path} failed: {ex.__class__.__name__}: {ex}"
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
                        # TODO: change this to incremental progress. Size parameter is currently unused.
                        progress_fn(bytes_sent, size)  # type: ignore [arg-type]
                    break

        self.stats.operation(StorageOperation.multipart_complete)
        try:
            self.s3_client.complete_multipart_upload(
                Bucket=self.bucket_name,
                Key=path,
                MultipartUpload={"Parts": parts},
                UploadId=mp_id,
            )
        except botocore.exceptions.ClientError as ex:
            try:
                self.stats.operation(StorageOperation.multipart_aborted)
                self.s3_client.abort_multipart_upload(
                    Bucket=self.bucket_name,
                    Key=path,
                    UploadId=mp_id,
                )
            finally:
                raise StorageError(f"Failed to complete multipart upload for {path}") from ex

        self.notifier.object_created(key=key, size=bytes_sent, metadata=sanitized_metadata)
        self.log.info(
            "Multipart upload of %r complete, size: %r, took: %.2fs",
            path,
            size,
            time.monotonic() - start_of_multipart_upload,
        )

    def store_file_from_memory(
        self,
        key: str,
        memstring: bytes,
        metadata: Optional[Metadata] = None,
        *,
        cache_control: Optional[str] = None,
        mimetype: Optional[str] = None,
        multipart: Optional[bool] = None,  # pylint: disable=unused-argument
        progress_fn: ProgressProportionCallbackType = None,  # pylint: disable=unused-argument
    ) -> None:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        data = bytes(memstring)  # make sure Body is of type bytes as memoryview's not allowed, only bytes/bytearrays
        args: dict[str, Any] = {
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
        self.stats.operation(StorageOperation.store_file, size=len(data))
        self.s3_client.put_object(**args)
        self.notifier.object_created(key=key, size=len(data), metadata=sanitized_metadata)

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
    ) -> None:  # pylint: disable=unused-argument
        if not self._should_multipart(
            chunk_size=self.multipart_chunk_size, default=True, metadata=metadata, multipart=multipart
        ):
            data = fd.read()
            self.store_file_from_memory(key, data, metadata, cache_control=cache_control, mimetype=mimetype)
            if upload_progress_fn:
                upload_progress_fn(len(data))
            return

        self.multipart_upload_file_object(
            cache_control=cache_control,
            fp=fd,
            key=key,
            metadata=metadata,
            mimetype=mimetype,
            progress_fn=self._proportional_to_incremental_progress(upload_progress_fn),
        )

    def check_or_create_bucket(self) -> None:
        create_bucket = False
        self.stats.operation(StorageOperation.head_request)
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
        except botocore.exceptions.ClientError as ex:
            # https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == HTTPStatus.MOVED_PERMANENTLY:
                raise InvalidConfigurationError(f"Wrong region for bucket {self.bucket_name}, check configuration")
            elif status_code == HTTPStatus.FORBIDDEN:
                self.log.warning("Access denied on bucket check, assuming write permissions")
            elif status_code in {HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND}:
                create_bucket = True
            else:
                raise

        if create_bucket:
            self.log.debug("Creating bucket: %r in location: %r", self.bucket_name, self.region)
            args: dict[str, Any] = {
                "Bucket": self.bucket_name,
            }
            if self.location:
                args["CreateBucketConfiguration"] = {
                    "LocationConstraint": self.location,
                }

            self.stats.operation(StorageOperation.create_bucket)
            self.s3_client.create_bucket(**args)

    def create_concurrent_upload(
        self,
        key: str,
        metadata: Optional[Metadata] = None,
        mimetype: Optional[str] = None,
        cache_control: Optional[str] = None,
    ) -> ConcurrentUpload:
        args, metadata, path = self._init_args_for_multipart(key, metadata, mimetype, cache_control)

        self.stats.operation(StorageOperation.create_multipart_upload)
        try:
            cmu_response = self.s3_client.create_multipart_upload(**args)
        except botocore.exceptions.ClientError as ex:
            raise ConcurrentUploadError(f"Failed to initiate multipart upload for {path}") from ex

        return ConcurrentUpload("aws", cmu_response["UploadId"], key, metadata, {})

    def complete_concurrent_upload(self, upload: ConcurrentUpload) -> None:
        backend_key = self.format_key_for_backend(upload.key, remove_slash_prefix=True)
        sorted_chunks: list[CompletedPartTypeDef] = sorted(
            ({"ETag": etag, "PartNumber": number} for number, etag in upload.chunks_to_etags.items()),
            key=lambda part: part["PartNumber"],
        )
        try:
            self.stats.operation(StorageOperation.multipart_complete)
            self.s3_client.complete_multipart_upload(
                Bucket=self.bucket_name,
                Key=backend_key,
                MultipartUpload={"Parts": sorted_chunks},
                UploadId=upload.backend_id,
                RequestPayer="requester",
            )
        except botocore.exceptions.ClientError as ex:
            raise ConcurrentUploadError(f"Failed to complete multipart upload for {upload.key}") from ex

    def abort_concurrent_upload(self, upload: ConcurrentUpload) -> None:
        backend_key = self.format_key_for_backend(upload.key, remove_slash_prefix=True)
        try:
            self.stats.operation(StorageOperation.multipart_aborted)
            self.s3_client.abort_multipart_upload(
                Bucket=self.bucket_name,
                Key=backend_key,
                UploadId=upload.backend_id,
                RequestPayer="requester",
            )
        except botocore.exceptions.ClientError as ex:
            raise ConcurrentUploadError(f"Failed to abort multipart upload for {upload.key}") from ex

    def upload_concurrent_chunk(
        self,
        upload: ConcurrentUpload,
        chunk_number: int,
        fd: BinaryIO,
        upload_progress_fn: IncrementalProgressCallbackType = None,
    ) -> None:
        """Synchronously uploads a chunk. Returns an ETag for the uploaded chunk.
        This method is thread-safe, so you can call it concurrently from multiple threads to upload different chunks.
        What happens if multiple threads try to upload the same chunk_number concurrently is unspecified.
        """
        backend_key = self.format_key_for_backend(upload.key, remove_slash_prefix=True)
        try:
            upload_func = partial(
                self.s3_client.upload_part,
                Bucket=self.bucket_name,
                Key=backend_key,
                UploadId=upload.backend_id,
                PartNumber=chunk_number,
            )
            body = ProgressStream(fd)
            response = upload_func(Body=body)
            if upload_progress_fn:
                upload_progress_fn(body.bytes_read)
            self.stats.operation(StorageOperation.store_file, size=body.bytes_read)
            upload.chunks_to_etags[chunk_number] = response["ETag"]
        except botocore.exceptions.ClientError as ex:
            raise ConcurrentUploadError(
                f"Failed to upload chunk {chunk_number} of multipart upload for {upload.key}"
            ) from ex

    def _init_args_for_multipart(
        self, key: str, metadata: Optional[Metadata], mimetype: Optional[str], cache_control: Optional[str]
    ) -> tuple[dict[str, Any], Optional[dict[str, str]], str]:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        args: dict[str, Any] = {
            "Bucket": self.bucket_name,
            "Key": path,
        }
        if metadata:
            metadata = self.sanitize_metadata(metadata)
            args["Metadata"] = metadata
        if self.encrypted:
            args["ServerSideEncryption"] = "AES256"
        if mimetype:
            args["ContentType"] = mimetype
        if cache_control:
            args["CacheControl"] = cache_control
        return args, metadata, path

    @classmethod
    def _read_bytes(cls, stream: BinaryIO, length: int) -> Optional[bytes]:
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
