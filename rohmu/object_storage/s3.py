# Copyright (c) 2016 Ohmu Ltd
# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""Rohmu - aws s3 object store interface"""

from __future__ import annotations

from botocore.response import StreamingBody
from functools import partial
from http import HTTPStatus
from pathlib import Path
from rohmu.common.models import StorageOperation
from rohmu.common.statsd import StatsdConfig
from rohmu.errors import (
    ConcurrentUploadError,
    FileNotFoundFromStorageError,
    InvalidConfigurationError,
    MaybeRecoverableError,
    StorageError,
    TransferObjectStoreInitializationError,
    TransferObjectStoreMissingError,
    TransferObjectStorePermissionError,
)
from rohmu.notifier.interface import Notifier
from rohmu.object_storage.base import (
    BaseTransfer,
    ConcurrentUpload,
    IncrementalProgressCallbackType,
    IterKeyItem,
    KEY_TYPE_OBJECT,
    KEY_TYPE_PREFIX,
    ProgressProportionCallbackType,
)
from rohmu.object_storage.config import (  # noqa: F401
    calculate_s3_chunk_size as calculate_chunk_size,
    S3_DEFAULT_MULTIPART_CHUNK_SIZE as MULTIPART_CHUNK_SIZE,
    S3_MAX_NUM_PARTS_PER_UPLOAD,
    S3_MAX_PART_SIZE_BYTES,
    S3_READ_BLOCK_SIZE as READ_BLOCK_SIZE,
    S3AddressingStyle,
    S3ObjectStorageConfig as Config,
)
from rohmu.typing import Metadata
from rohmu.util import batched, ProgressStream
from threading import RLock
from typing import Any, BinaryIO, cast, Collection, Iterator, Optional, Tuple, TYPE_CHECKING, Union
from typing_extensions import Self

import botocore.client
import botocore.config
import botocore.exceptions
import botocore.session
import contextlib
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
    verify: Optional[Union[bool, str]] = None,
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
        use_dualstack_endpoint: Optional[bool] = True,
        statsd_info: Optional[StatsdConfig] = None,
        ensure_object_store_available: bool = True,
        min_multipart_chunk_size: Optional[int] = None,
    ) -> None:
        super().__init__(
            prefix=prefix,
            notifier=notifier,
            statsd_info=statsd_info,
            ensure_object_store_available=ensure_object_store_available,
        )
        self.bucket_name = bucket_name
        self.region = region
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.host = host
        self.port = port
        self.addressing_style = addressing_style
        self.is_secure = is_secure
        self.is_verify_tls = is_verify_tls
        self.cert_path = cert_path
        self.proxy_info = proxy_info
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.aws_session_token = aws_session_token
        self.use_dualstack_endpoint = use_dualstack_endpoint
        self.default_multipart_chunk_size = max(segment_size, min_multipart_chunk_size or 0)
        self.encrypted = encrypted
        self.s3_client: Optional[S3Client] = None
        self.location = ""
        if not self.host or not self.port:
            if self.region and self.region != "us-east-1":
                self.location = self.region
        else:
            if self.region:
                self.location = self.region
            if not self.is_verify_tls and self.cert_path is not None:
                raise ValueError("cert_path is set but is_verify_tls is False")
        if ensure_object_store_available:
            self._create_object_store_if_needed_unwrapped()
        self.log.debug("S3Transfer initialized")

    def _verify_object_storage_unwrapped(self) -> None:
        self.check_or_create_bucket(create_if_needed=False)

    def verify_object_storage(self) -> None:
        try:
            self._verify_object_storage_unwrapped()
        except botocore.exceptions.ClientError as ex:
            if ex.response.get("Error", {}).get("Code") == "AccessDenied":
                raise TransferObjectStorePermissionError() from ex
            else:
                raise TransferObjectStoreInitializationError() from ex

    def _create_object_store_if_needed_unwrapped(self) -> None:
        self.check_or_create_bucket(create_if_needed=True)

    def create_object_store_if_needed(self) -> None:
        try:
            self._create_object_store_if_needed_unwrapped()
        except botocore.exceptions.ClientError as ex:
            if ex.response.get("Error", {}).get("Code") == "AccessDenied":
                raise TransferObjectStorePermissionError() from ex
            else:
                raise TransferObjectStoreInitializationError() from ex

    def get_client(self) -> S3Client:
        if self.s3_client is None:
            timeouts: dict[str, Any] = {}
            if self.connect_timeout:
                timeouts["connect_timeout"] = self.connect_timeout
            if self.read_timeout:
                timeouts["read_timeout"] = self.read_timeout
            if not self.host or not self.port:
                custom_config: dict[str, Any] = {**timeouts}
                if self.proxy_info:
                    proxy_url = get_proxy_url(self.proxy_info)
                    custom_config["proxies"] = {"https": proxy_url}
                if self.use_dualstack_endpoint is True:
                    custom_config["use_dualstack_endpoint"] = True
                with self._get_session() as session:
                    self.s3_client = create_s3_client(
                        session=session,
                        config=botocore.config.Config(**custom_config),
                        aws_access_key_id=self.aws_access_key_id,
                        aws_secret_access_key=self.aws_secret_access_key,
                        aws_session_token=self.aws_session_token,
                        region_name=self.region,
                    )
            else:
                scheme = "https" if self.is_secure else "http"
                custom_url = f"{scheme}://{self.host}:{self.port}"
                if self.region:
                    signature_version = "s3v4"
                else:
                    signature_version = "s3"
                proxies: Optional[dict[str, str]] = None
                if self.proxy_info:
                    proxies = {"https": get_proxy_url(self.proxy_info)}
                boto_config = botocore.client.Config(
                    s3={"addressing_style": S3AddressingStyle(self.addressing_style).value},
                    signature_version=signature_version,
                    proxies=proxies,
                    retries={
                        "max_attempts": 10,
                        "mode": "standard",
                    },
                    **timeouts,
                )
                with self._get_session() as session:
                    self.s3_client = create_s3_client(
                        session=session,
                        aws_access_key_id=self.aws_access_key_id,
                        aws_secret_access_key=self.aws_secret_access_key,
                        aws_session_token=self.aws_session_token,
                        config=boto_config,
                        endpoint_url=custom_url,
                        region_name=self.region,
                        verify=str(self.cert_path)
                        if self.cert_path is not None and self.is_verify_tls
                        else self.is_verify_tls,
                    )
        return self.s3_client

    def close(self) -> None:
        if self.s3_client is not None:
            self.s3_client.close()
            self.s3_client = None

    # It is advantageous to share the Session as much as possible since the very
    # large service model files (eg botocore/data/ec2/2016-11-15/service-2.json)
    # are cached on the Session, otherwise they will need to be loaded for every
    # Client - which takes a lot of time and memory.
    # Sessions are not threadsafe.  We use a lock to ensure that only one thread
    # is creating a client at a time.  Clients are threadsafe, so it is okay for
    # the Client to "escape" the lock with any state it shares with the Session.
    _botocore_session_lock = RLock()
    _botocore_session: botocore.session.Session | None = None

    @classmethod
    @contextlib.contextmanager
    def _get_session(cls) -> Iterator[botocore.session.Session]:
        with cls._botocore_session_lock:
            if cls._botocore_session is None:
                cls._botocore_session = botocore.session.get_session()
            yield cls._botocore_session

    def copy_file(
        self, *, source_key: str, destination_key: str, metadata: Optional[Metadata] = None, **_kwargs: Any
    ) -> None:
        self._copy_file_from_bucket(
            source_bucket=self, source_key=source_key, destination_key=destination_key, metadata=metadata
        )

    def _copy_file_from_bucket(
        self,
        *,
        source_bucket: Self,
        source_key: str,
        destination_key: str,
        metadata: Optional[Metadata] = None,
        timeout: float = 15.0,
    ) -> None:
        source_path = (
            source_bucket.bucket_name + "/" + source_bucket.format_key_for_backend(source_key, remove_slash_prefix=True)
        )
        destination_path = self.format_key_for_backend(destination_key, remove_slash_prefix=True)
        self.stats.operation(StorageOperation.copy_file)
        try:
            self.get_client().copy_object(
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

    def get_metadata_for_key(self, key: str) -> Metadata:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        return self._metadata_for_key(path)

    def _metadata_for_key(self, key: str) -> Metadata:
        self.stats.operation(StorageOperation.metadata_for_key)
        try:
            response = self.get_client().head_object(Bucket=self.bucket_name, Key=key)
        except botocore.exceptions.ClientError as ex:
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 404:
                raise FileNotFoundFromStorageError(key)
            else:
                raise StorageError(f"Metadata lookup failed for {key}") from ex

        return response["Metadata"]

    def delete_key(self, key: str, preserve_trailing_slash: bool = False) -> None:
        path = self.format_key_for_backend(
            key, remove_slash_prefix=True, trailing_slash=preserve_trailing_slash and key.endswith("/")
        )
        self.log.debug("Deleting key: %r", path)
        self._metadata_for_key(path)  # check that key exists
        self.stats.operation(StorageOperation.delete_key)
        self.get_client().delete_object(Bucket=self.bucket_name, Key=path)
        self.notifier.object_deleted(key=key)

    def delete_keys(self, keys: Collection[str], preserve_trailing_slash: bool = False) -> None:
        self.stats.operation(StorageOperation.delete_key, count=len(keys))
        for batch in batched(keys, 1000):  # Cannot delete more than 1000 objects at a time
            formatted_keys = [
                self.format_key_for_backend(
                    k,
                    remove_slash_prefix=True,
                    trailing_slash=preserve_trailing_slash and k.endswith("/"),
                )
                for k in batch
            ]
            self.get_client().delete_objects(
                Bucket=self.bucket_name,
                Delete={"Objects": [{"Key": key} for key in formatted_keys]},
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
            response = self.get_client().list_objects_v2(**args)

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
            response = self.get_client().get_object(Bucket=self.bucket_name, Key=path, **kwargs)
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
            try:
                data = streaming_body.read(amt=read_amount)
            except (botocore.exceptions.IncompleteReadError, botocore.exceptions.ReadTimeoutError) as ex:
                raise MaybeRecoverableError("botocore.exceptions.IncompleteReadError", position=data_read) from ex

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
        try:
            self._read_object_to_fileobj(fileobj_to_store_to, stream, length, cb=progress_callback)
        except MaybeRecoverableError as e:
            if e.position is None:
                raise
            start_position = 0 if byte_range is None else byte_range[0]
            retry_byte_range = (start_position + e.position, start_position + length - 1)
            self.log.warning("Got recoverable error %r while reading %r, restarting with range %r", e, key, retry_byte_range)
            self.get_contents_to_fileobj(
                key,
                fileobj_to_store_to,
                byte_range=retry_byte_range,
                progress_callback=progress_callback,
            )
        return metadata

    def get_file_size(self, key: str) -> int:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        self.stats.operation(StorageOperation.get_file_size)
        try:
            response = self.get_client().head_object(Bucket=self.bucket_name, Key=path)
            return int(response["ContentLength"])
        except botocore.exceptions.ClientError as ex:
            if ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
                raise FileNotFoundFromStorageError(path)
            else:
                raise StorageError(f"File size lookup failed for {path}") from ex

    def calculate_chunks_and_chunk_size(self, size: Optional[int]) -> tuple[int, int]:
        """Calculate the number of chunks and chunk size for multipart upload.

        If sizes provided self.default_multipart_chunk_size wil be used as first attempt,
        if number of chunks is greater than S3_MAX_NUM_PARTS_PER_UPLOAD, we will try
        to fit the file into S3_MAX_NUM_PARTS_PER_UPLOAD parts by increasing the chunk size.
        """
        if size is None:
            return 1, self.default_multipart_chunk_size
        chunks = math.ceil(size / self.default_multipart_chunk_size)
        chunk_size = self.default_multipart_chunk_size

        if chunks > S3_MAX_NUM_PARTS_PER_UPLOAD:
            chunk_size = math.ceil(size / S3_MAX_NUM_PARTS_PER_UPLOAD)
            if chunk_size > S3_MAX_PART_SIZE_BYTES:
                raise StorageError(
                    f"Cannot upload a file of size {size}. "
                    f"Chunk size {chunk_size} is too big for each part of multipart upload."
                )
            chunks = math.ceil(size / chunk_size)
            self.log.info(
                "default chunk size %d was too small for file size %d, increasing it to %d",
                self.default_multipart_chunk_size,
                size,
                chunk_size,
            )

        return chunks, chunk_size

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

        chunks, chunk_size = self.calculate_chunks_and_chunk_size(size)
        args, sanitized_metadata, path = self._init_args_for_multipart(key, metadata, mimetype, cache_control)
        self.log.debug(
            "Starting to upload multipart file: %r, size: %s, chunks: %d (chunk size: %d)", path, size, chunks, chunk_size
        )

        parts: list[CompletedPartTypeDef] = []
        part_number = 1

        self.stats.operation(StorageOperation.create_multipart_upload)
        try:
            cmu_response = self.get_client().create_multipart_upload(**args)
        except botocore.exceptions.ClientError as ex:
            raise StorageError(f"Failed to initiate multipart upload for {path}") from ex

        mp_id = cmu_response["UploadId"]

        while True:
            data = self._read_bytes(fp, chunk_size)
            if not data:
                break

            start_of_part_upload = time.monotonic()
            self.stats.operation(StorageOperation.store_file, size=len(data))
            try:
                cup_response = self.get_client().upload_part(
                    Body=data,
                    Bucket=self.bucket_name,
                    Key=path,
                    PartNumber=part_number,
                    UploadId=mp_id,
                )
            except botocore.exceptions.ClientError as ex:
                self.log.exception("Uploading part %d for %s failed", part_number, path)
                self.stats.operation(StorageOperation.multipart_aborted)
                try:
                    self.get_client().abort_multipart_upload(
                        Bucket=self.bucket_name,
                        Key=path,
                        UploadId=mp_id,
                    )
                finally:
                    err = f"Multipart upload of {path} failed: {ex.__class__.__name__}: {ex}"
                    raise StorageError(err) from ex
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
                    progress_fn(bytes_sent, size)  # type: ignore[arg-type]

        self.stats.operation(StorageOperation.multipart_complete)
        try:
            self.get_client().complete_multipart_upload(
                Bucket=self.bucket_name,
                Key=path,
                MultipartUpload={"Parts": parts},
                UploadId=mp_id,
            )
        except botocore.exceptions.ClientError as ex:
            try:
                self.stats.operation(StorageOperation.multipart_aborted)
                self.get_client().abort_multipart_upload(
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
        multipart: Optional[bool] = None,
        progress_fn: ProgressProportionCallbackType = None,
    ) -> None:
        path = self.format_key_for_backend(key, remove_slash_prefix=True)
        # make sure Body is of type bytes as memoryview's not allowed, only bytes/bytearrays
        data = bytes(memstring) if len(memstring) else b""
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
        self.get_client().put_object(**args)
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
    ) -> None:
        if not self._should_multipart(
            fd=fd, chunk_size=self.default_multipart_chunk_size, default=True, metadata=metadata, multipart=multipart
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

    def check_or_create_bucket(self, create_if_needed: bool = True) -> None:
        self.stats.operation(StorageOperation.head_request)
        try:
            self.get_client().head_bucket(Bucket=self.bucket_name)
        except botocore.exceptions.ClientError as ex:
            # https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
            status_code = ex.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == HTTPStatus.MOVED_PERMANENTLY:
                raise InvalidConfigurationError(f"Wrong region for bucket {self.bucket_name}, check configuration")
            elif status_code == HTTPStatus.FORBIDDEN:
                # Access denied on bucket check, most likely due to missing s3:ListBucket, assuming write permissions
                return
            elif status_code in {HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND}:
                if not create_if_needed:
                    raise TransferObjectStoreMissingError()
            else:
                raise
        else:
            # Bucket exists - bail out
            return

        self.log.debug("Creating bucket: %r in location: %r", self.bucket_name, self.region)
        args: dict[str, Any] = {
            "Bucket": self.bucket_name,
        }
        if self.location:
            args["CreateBucketConfiguration"] = {
                "LocationConstraint": self.location,
            }

        self.stats.operation(StorageOperation.create_bucket)
        self.get_client().create_bucket(**args)

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
            cmu_response = self.get_client().create_multipart_upload(**args)
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
            self.get_client().complete_multipart_upload(
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
            self.get_client().abort_multipart_upload(
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
                self.get_client().upload_part,
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
