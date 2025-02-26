# Copyright (c) 2016 Ohmu Ltd
# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""Rohmu - google cloud object store interface"""

from __future__ import annotations

from contextlib import contextmanager
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import (
    build_http,
    HttpRequest,
    MediaDownloadProgress,
    MediaIoBaseDownload,
    MediaUpload,
    MediaUploadProgress,
)
from http.client import IncompleteRead
from io import IOBase
from oauth2client import GOOGLE_TOKEN_URI
from oauth2client.client import GoogleCredentials
from rohmu.common.models import StorageOperation
from rohmu.common.statsd import StatsClient, StatsdConfig
from rohmu.errors import (
    FileNotFoundFromStorageError,
    InvalidByteRangeError,
    InvalidConfigurationError,
    TransferObjectStoreInitializationError,
    TransferObjectStoreMissingError,
    TransferObjectStorePermissionError,
)
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
    GOOGLE_DOWNLOAD_CHUNK_SIZE as DOWNLOAD_CHUNK_SIZE,
    GOOGLE_UPLOAD_CHUNK_SIZE as UPLOAD_CHUNK_SIZE,
    GoogleObjectStorageConfig as Config,
)
from rohmu.typing import AnyPath, Metadata
from rohmu.util import get_total_size_from_content_range
from typing import (
    Any,
    BinaryIO,
    Callable,
    cast,
    Iterable,
    Iterator,
    Optional,
    TextIO,
    Tuple,
    TYPE_CHECKING,
    TypeVar,
    Union,
)
from typing_extensions import Protocol, Self

import codecs
import dataclasses
import datetime
import errno

# NOTE: this import is not needed per-se, but it's imported here first to point the
# user to the most important possible missing dependency
import googleapiclient  # noqa: F401
import httplib2
import json
import logging
import os
import random
import socket
import ssl
import time

try:
    from oauth2client.service_account import ServiceAccountCredentials

    ServiceAccountCredentials_from_dict = ServiceAccountCredentials.from_json_keyfile_dict
except ImportError:
    from oauth2client.service_account import _ServiceAccountCredentials

    def ServiceAccountCredentials_from_dict(
        credentials: dict[str, Any], scopes: Optional[list[str]] = None
    ) -> GoogleCredentials:
        if scopes is None:
            scopes = []
        return _ServiceAccountCredentials(
            service_account_id=credentials["client_id"],
            service_account_email=credentials["client_email"],
            private_key_id=credentials["private_key_id"],
            private_key_pkcs8_text=credentials["private_key"],
            scopes=scopes,
        )


if TYPE_CHECKING:
    from googleapiclient._apis.storage.v1 import StorageResource

# Silence Google API client verbose spamming
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.ERROR)
logging.getLogger("googleapiclient").setLevel(logging.WARNING)
logging.getLogger("oauth2client").setLevel(logging.WARNING)


def get_credentials(
    credential_file: Optional[TextIO] = None, credentials: Optional[dict[str, Any]] = None
) -> GoogleCredentials:
    if credential_file:
        return GoogleCredentials.from_stream(credential_file)

    if credentials and credentials["type"] == "service_account":
        return ServiceAccountCredentials_from_dict(
            credentials,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

    if credentials and credentials["type"] == "authorized_user":
        return GoogleCredentials(
            access_token=None,
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
            refresh_token=credentials["refresh_token"],
            token_expiry=None,
            token_uri=GOOGLE_TOKEN_URI,
            user_agent="pghoard",
        )

    return GoogleCredentials.get_application_default()


def base64_to_hex(b64val: Union[str, bytes]) -> str:
    if isinstance(b64val, str):
        b64val = b64val.encode("ascii")
    rawval = codecs.decode(b64val, "base64")
    hexval = codecs.encode(rawval, "hex")
    return hexval.decode("ascii")


@dataclasses.dataclass
class Reporter:
    """Used for storing default and also reporting them accordingly.

    The whole point of this class is to handle different cases:

    - When file size is too small, reporting ``*_CHUNK_SIZE`` is wrong as 1000's of
      small files over a long period (may be a month) is a lot of error;
    - Same is the case of _retry_on_reset;
    - This error extrapolates when replication is being used.

    Size should ideally be min(real_size, ``*_CHUNK_SIZE``). real_size is avaiable
    when download or upload (from string or file), but when using FD, size is
    not known so assuming something too big for small files is almost wrong and
    in case it is bigger than CHUNKED then status reporting (from the
    googleclient lib) should help get the correct sizes

    """

    operation: StorageOperation
    size: Optional[int] = None
    progress_prev: int = 0

    def report(self, stats: StatsClient) -> None:
        # reports the default.
        # for sized operation, reporting after the operation is fine as _retry_on_reset will
        # have reported the something already
        # and if the operation eventually succeeds then report_status() or this will take care
        # of it.
        SIZED_OPERATIONS = {
            StorageOperation.store_file: UPLOAD_CHUNK_SIZE,
            StorageOperation.get_file: DOWNLOAD_CHUNK_SIZE,
        }

        if self.operation in SIZED_OPERATIONS:
            size = self.size if self.size is not None else SIZED_OPERATIONS[self.operation]
            stats.operation(operation=self.operation, size=size)
        else:
            stats.operation(operation=self.operation)

    def report_status(self, stats: StatsClient, status: Union[MediaUploadProgress, MediaDownloadProgress]) -> None:
        stats.operation(operation=self.operation, size=status.resumable_progress - self.progress_prev)
        self.progress_prev = status.resumable_progress


ResType = TypeVar("ResType")


class GoogleTransfer(BaseTransfer[Config]):
    config_model = Config

    def __init__(
        self,
        project_id: str,
        bucket_name: str,
        credential_file: Optional[TextIO] = None,
        credentials: Optional[dict[str, Any]] = None,
        prefix: Optional[str] = None,
        proxy_info: Optional[dict[str, Union[str, int]]] = None,
        notifier: Optional[Notifier] = None,
        statsd_info: Optional[StatsdConfig] = None,
        ensure_object_store_available: bool = True,
    ) -> None:
        super().__init__(
            prefix=prefix,
            notifier=notifier,
            statsd_info=statsd_info,
            ensure_object_store_available=ensure_object_store_available,
        )
        self.project_id = project_id
        self.proxy_info = proxy_info
        self.google_creds = get_credentials(credential_file=credential_file, credentials=credentials)
        self.gs: Optional[StorageResource] = self._init_google_client()
        self.gs_object_client: Optional[StorageResource.ObjectsResource] = None
        self.gs_bucket_client: Optional[StorageResource.BucketsResource] = None
        self.bucket_name = bucket_name
        if ensure_object_store_available:
            self._create_object_store_if_needed_unwrapped()
        self.log.debug("GoogleTransfer initialized")

    def close(self) -> None:
        if self.gs_object_client is not None:
            self.gs_object_client.close()
            self.gs_object_client = None
        if self.gs_bucket_client is not None:
            self.gs_bucket_client.close()
            self.gs_bucket_client = None
        if self.gs is not None:
            self.gs.close()
            self.gs = None

    def _init_google_client(self) -> StorageResource:
        start_time = time.monotonic()
        delay = 2
        while True:
            http = build_http()
            if self.proxy_info:
                if self.proxy_info.get("type") == "socks5":
                    proxy_type = httplib2.socks.PROXY_TYPE_SOCKS5  # type: ignore[attr-defined]
                else:
                    proxy_type = httplib2.socks.PROXY_TYPE_HTTP  # type: ignore[attr-defined]

                http.proxy_info = httplib2.ProxyInfo(
                    proxy_type,
                    self.proxy_info["host"],
                    self.proxy_info["port"],
                    proxy_user=self.proxy_info.get("user"),
                    proxy_pass=self.proxy_info.get("pass"),
                )

            http = self.google_creds.authorize(http)

            try:
                # sometimes fails: httplib2.ServerNotFoundError: Unable to find the server at www.googleapis.com
                # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.html
                return build("storage", "v1", http=http)
            except (httplib2.ServerNotFoundError, socket.timeout):
                if time.monotonic() - start_time > 600:
                    raise

            # retry on DNS issues
            time.sleep(delay)
            delay = delay * 2

    @contextmanager
    def _object_client(self, *, not_found: Optional[str] = None) -> Iterator[Any]:
        """(Re-)initialize object client if required, handle 404 errors gracefully and reset the client on
        server errors.  Server errors have been shown to be caused by invalid state in the client and do not
        seem to be resolved without resetting."""
        if self.gs_object_client is None:
            if self.gs is None:
                self.gs = self._init_google_client()
            # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html
            self.gs_object_client = self.gs.objects()
        try:
            yield self.gs_object_client
        except HttpError as ex:
            if ex.resp["status"] == "404" and not_found is not None:
                raise FileNotFoundFromStorageError(not_found)
            if ex.resp["status"] >= "500" and ex.resp["status"] <= "599":
                self.log.error("Received server error %r, resetting Google API client", ex.resp["status"])
                self.gs = None
                self.gs_object_client = None
            raise

    @contextmanager
    def _bucket_client(self) -> Iterator[Any]:
        """
        (Re-)initialize object client lazily if required.
        There is no reset logic for the buckets client (as opposed to the object client) as that's not strictly needed
        since it's only used once at setup.
        """
        if self.gs_bucket_client is None:
            if self.gs is None:
                self.gs = self._init_google_client()
            # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html
            self.gs_bucket_client = self.gs.buckets()
        yield self.gs_bucket_client

    def _retry_on_reset(self, request: HttpRequest, action: Callable[[], ResType], retry_reporter: Reporter) -> ResType:
        retries = 60
        retry_wait = 2.0
        while True:
            try:
                return action()
            except (
                IncompleteRead,
                HttpError,
                ssl.SSLEOFError,
                socket.timeout,
                OSError,
                socket.gaierror,
                httplib2.ServerNotFoundError,
            ) as ex:
                # Note that socket.timeout and ssl.SSLEOFError inherit from OSError
                # and the order of handling the errors here needs to be correct
                if not retries:
                    raise
                elif isinstance(
                    ex, (IncompleteRead, socket.timeout, ssl.SSLEOFError, BrokenPipeError, httplib2.ServerNotFoundError)
                ):
                    pass  # just retry with the same sleep amount
                elif isinstance(ex, HttpError):
                    # https://cloud.google.com/storage/docs/json_api/v1/status-codes
                    # https://cloud.google.com/storage/docs/exponential-backoff
                    if ex.resp["status"] not in ("429", "500", "502", "503", "504"):
                        raise
                    retry_wait = min(10.0, max(1.0, retry_wait * 2) + random.random())
                # httplib2 commonly fails with Bad File Descriptor and Connection Reset
                elif isinstance(ex, OSError) and ex.errno not in [errno.EAGAIN, errno.EBADF, errno.ECONNRESET]:
                    raise
                # getaddrinfo sometimes fails with "Name or service not known"
                elif isinstance(ex, socket.gaierror) and ex.errno != socket.EAI_NONAME:
                    raise

                self.log.warning("%s failed: %s (%s), retrying in %.2fs", action, ex.__class__.__name__, ex, retry_wait)

            retry_reporter.report(self.stats)

            # we want to reset the http connection state in case of error
            if request and hasattr(request, "http") and hasattr(request.http, "connections"):
                request.http.connections.clear()  # reset connection cache

            retries -= 1
            time.sleep(retry_wait)

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
        source_object = source_bucket.format_key_for_backend(source_key)
        destination_object = self.format_key_for_backend(destination_key)
        body = {}
        if metadata is not None:
            body["metadata"] = metadata

        reporter = Reporter(StorageOperation.copy_file)
        with self._object_client(not_found=source_key) as clob:
            # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html#copy
            request = clob.copy(
                body=body,
                destinationBucket=self.bucket_name,
                destinationObject=destination_object,
                sourceBucket=source_bucket.bucket_name,
                sourceObject=source_object,
            )
            result = self._retry_on_reset(request, request.execute, retry_reporter=reporter)
            if result.get("size", None) is not None:
                size = int(result["size"])
                reporter.size = size
                self.notifier.object_copied(key=destination_key, size=size, metadata=metadata)
            reporter.report(self.stats)

    def get_metadata_for_key(self, key: str) -> Metadata:
        path = self.format_key_for_backend(key)
        with self._object_client(not_found=path) as clob:
            return self._metadata_for_key(clob, path)[0]

    def _metadata_for_key(self, clob: Any, key: str) -> tuple[dict[str, Any], int]:
        # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html#get
        req = clob.get(bucket=self.bucket_name, object=key)

        reporter = Reporter(StorageOperation.get_metadata_for_key)
        obj = self._retry_on_reset(req, req.execute, retry_reporter=reporter)
        reporter.report(self.stats)
        return obj.get("metadata", {}), int(obj["size"])

    def _unpaginate(
        self, domain: Any, initial_op: Callable[[Any], Optional[HttpRequest]], *, on_properties: Iterable[str]
    ) -> Iterator[tuple[str, Any]]:
        """Iterate thru the request pages until all items have been processed"""
        request = initial_op(domain)
        while request is not None:
            reporter = Reporter(StorageOperation.iter_key)
            result = self._retry_on_reset(request, request.execute, retry_reporter=reporter)
            reporter.report(self.stats)
            for on_property in on_properties:
                items = result.get(on_property)
                if items is not None:
                    yield on_property, items
            request = domain.list_next(request, result)

    def iter_key(
        self,
        key: str,
        *,
        with_metadata: bool = True,
        deep: bool = False,
        include_key: bool = False,
    ) -> Iterator[IterKeyItem]:
        path = self.format_key_for_backend(key, trailing_slash=not include_key)
        self.log.debug("Listing path %r", path)
        with self._object_client() as clob:

            def initial_op(domain: Any) -> HttpRequest:
                if deep:
                    kwargs = {}
                else:
                    kwargs = {"delimiter": "/"}
                # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html#list
                return domain.list(bucket=self.bucket_name, prefix=path, **kwargs)

            for property_name, items in self._unpaginate(clob, initial_op, on_properties=["items", "prefixes"]):
                if property_name == "items":
                    for item in items:
                        if item["name"].endswith("/"):
                            self.log.warning("list_iter: directory entry %r", item)
                            continue  # skip directory level objects

                        value = {
                            "name": self.format_key_from_backend(item["name"]),
                            "metadata": item.get("metadata", {}),
                        }
                        # in very rare circumstances size, updated and md5Hash can be missing. Omit the keys if that happens
                        if (size := item.get("size")) is not None:
                            value["size"] = int(size)
                        if (updated := item.get("updated")) is not None:
                            value["last_modified"] = datetime.datetime.fromisoformat(updated)
                        if (md5 := item.get("md5Hash")) is not None:
                            value["md5"] = base64_to_hex(md5)
                        yield IterKeyItem(type=KEY_TYPE_OBJECT, value=value)
                elif property_name == "prefixes":
                    for prefix in items:
                        yield IterKeyItem(type=KEY_TYPE_PREFIX, value=self.format_key_from_backend(prefix).rstrip("/"))
                else:
                    raise NotImplementedError(property_name)

    def delete_key(self, key: str, preserve_trailing_slash: bool = False) -> None:
        path = self.format_key_for_backend(key, trailing_slash=preserve_trailing_slash and key.endswith("/"))
        self.log.debug("Deleting key: %r", path)
        with self._object_client(not_found=path) as clob:
            # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html#delete
            req = clob.delete(bucket=self.bucket_name, object=path)
            reporter = Reporter(StorageOperation.delete_key)
            self._retry_on_reset(req, req.execute, retry_reporter=reporter)
            reporter.report(self.stats)
            self.notifier.object_deleted(key)

    def get_contents_to_fileobj(
        self,
        key: str,
        fileobj_to_store_to: BinaryIO,
        *,
        byte_range: Optional[Tuple[int, int]] = None,
        progress_callback: ProgressProportionCallbackType = None,
    ) -> Metadata:
        path = self.format_key_for_backend(key)
        self.log.debug("Starting to fetch the contents of: %r to %r", path, fileobj_to_store_to)
        next_prog_report = 0.0
        last_log_output = 0.0
        self._validate_byte_range(byte_range)
        with self._object_client(not_found=path) as clob:
            metadata, obj_size = self._metadata_for_key(clob, path)
            if byte_range is None:
                size_to_download = obj_size
            else:
                size_to_download = min(obj_size - byte_range[0], byte_range[1] - byte_range[0] + 1)
            reporter = Reporter(
                StorageOperation.get_file,
                size=min(size_to_download, DOWNLOAD_CHUNK_SIZE),
            )
            # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html#get_media
            req: HttpRequest = clob.get_media(bucket=self.bucket_name, object=path)
            download: MediaDownloadProtocol
            if byte_range is None:
                # MediaIoBaseDownload only calls .write(bytes) method, so BinaryIO works fine even if mypy complains
                download = MediaIoBaseDownload(cast(IOBase, fileobj_to_store_to), req, chunksize=DOWNLOAD_CHUNK_SIZE)
            else:
                download = MediaIoBaseDownloadWithByteRange(
                    fileobj_to_store_to, req, chunksize=DOWNLOAD_CHUNK_SIZE, byte_range=byte_range
                )

            done = False
            while not done:
                status, done = self._retry_on_reset(req, download.next_chunk, retry_reporter=reporter)
                if status:
                    reporter.report_status(self.stats, status)
                    progress_pct = status.progress() * 100
                    now = time.monotonic()
                    if (now - last_log_output) >= 5.0:
                        self.log.debug("Download of %r: %d%%", path, progress_pct)
                        last_log_output = now

                    if progress_callback and progress_pct > next_prog_report:
                        progress_callback(int(progress_pct), 100)
                        next_prog_report = progress_pct + 0.1
                elif done:
                    reporter.report_status(self.stats, MediaDownloadProgress(size_to_download, size_to_download))
                else:
                    reporter.report(self.stats)
            if progress_callback:
                progress_callback(100, 100)
            return metadata

    def get_file_size(self, key: str) -> int:
        path = self.format_key_for_backend(key)
        reporter = Reporter(StorageOperation.get_file_size)
        with self._object_client(not_found=path) as clob:
            # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html#get
            req = clob.get(bucket=self.bucket_name, object=path)
            obj = self._retry_on_reset(req, req.execute, retry_reporter=reporter)
            reporter.report(self.stats)
            return int(obj["size"])

    def _upload(
        self,
        upload: MediaUpload,
        key: str,
        metadata: Metadata,
        extra_props: Optional[dict[str, Any]],
        cache_control: Optional[str],
        reporter: Reporter,
        upload_progress_fn: IncrementalProgressCallbackType = None,
    ) -> dict[str, str]:
        path = self.format_key_for_backend(key)
        self.log.debug("Starting to upload %r", path)
        body: dict[str, Any] = {"metadata": metadata}
        if extra_props:
            body.update(extra_props)
        if cache_control is not None:
            body["cacheControl"] = cache_control

        last_log_output = 0.0
        with self._object_client() as clob:
            # https://googleapis.github.io/google-api-python-client/docs/dyn/storage_v1.objects.html#insert
            req = clob.insert(bucket=self.bucket_name, name=path, media_body=upload, body=body)
            response = None
            while response is None:
                status, response = self._retry_on_reset(req, req.next_chunk, retry_reporter=reporter)
                if status:
                    reporter.report_status(self.stats, status)
                    now = time.monotonic()
                    if (now - last_log_output) >= 5.0:
                        self.log.debug(
                            "Upload of %r to %r: %d%%, %s bytes",
                            upload,
                            path,
                            status.progress() * 100,
                            status.resumable_progress,
                        )
                        last_log_output = now

                    if upload_progress_fn:
                        upload_progress_fn(status.resumable_progress)
                elif response is not None:
                    reporter.report_status(self.stats, MediaUploadProgress(int(response["size"]), int(response["size"])))
                else:
                    reporter.report(self.stats)
        return response

    def store_file_from_disk(
        self,
        key: str,
        filepath: AnyPath,
        metadata: Optional[Metadata] = None,
        *,
        cache_control: Optional[str] = None,
        mimetype: Optional[str] = None,
        multipart: Optional[bool] = None,
        progress_fn: ProgressProportionCallbackType = None,
        extra_props: Optional[dict[str, Any]] = None,
    ) -> None:
        # TODO: extra_props seems to be used only to set cacheControl in pghoard tests.
        #
        # When that is gone (.. long enough ..), we could get rid of
        # this whole function and use the superclass default which
        # falls back to store_file_object.
        size = os.path.getsize(filepath)
        with open(filepath, "rb") as fd:
            metadata = metadata or {}
            metadata.setdefault("Content-Length", size)
            self.store_file_object(
                key,
                fd,
                cache_control=cache_control,
                metadata=metadata,
                mimetype=mimetype,
                multipart=multipart,
                upload_progress_fn=self._incremental_to_proportional_progress(cb=progress_fn, size=size),
                extra_props=extra_props,
            )

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
        extra_props: Optional[dict[str, Any]] = None,
    ) -> None:
        mimetype = mimetype or "application/octet-stream"
        sanitized_metadata = self.sanitize_metadata(metadata)
        reporter = Reporter(StorageOperation.store_file)
        result = self._upload(
            MediaStreamUpload(fd, chunk_size=UPLOAD_CHUNK_SIZE, mime_type=mimetype, name=key),
            key,
            sanitized_metadata,
            extra_props,
            cache_control=cache_control,
            upload_progress_fn=upload_progress_fn,
            reporter=reporter,
        )
        self.notifier.object_created(key=key, size=int(result["size"]), metadata=sanitized_metadata)

    def _verify_object_storage_unwrapped(self) -> None:
        """Look up the bucket to see if it already exists or raise TransferObjectStoreMissingError if not."""
        start_time = time.time()
        with self._bucket_client() as gs_buckets:
            try:
                self._try_get_bucket(gs_buckets)
                self.log.debug("Bucket: %r already exists, took: %.3fs", self.bucket_name, time.time() - start_time)
            except HttpError as ex:
                if ex.resp["status"] == "404":
                    raise TransferObjectStoreMissingError()
                elif ex.resp["status"] == "403":
                    raise InvalidConfigurationError(f"Bucket {repr(self.bucket_name)} exists but isn't accessible")
                else:
                    raise

    def _try_get_bucket(self, gs_buckets: StorageResource.BucketsResource) -> None:
        """Useful for mocking in tests"""
        request = gs_buckets.get(bucket=self.bucket_name)
        reporter = Reporter(StorageOperation.head_request)
        self._retry_on_reset(request, request.execute, retry_reporter=reporter)
        reporter.report(self.stats)

    def verify_object_storage(self) -> None:
        try:
            self._verify_object_storage_unwrapped()
        except InvalidConfigurationError as ex:
            # The only reason we'd raise this exception is if we caught a 403 and raised this exception for the older apps
            # In this method, we can raise a "proper" exception for permission errors
            raise TransferObjectStorePermissionError() from ex
        except HttpError as ex:
            # Wrap implementation-specific exceptions with rohmu's
            raise TransferObjectStoreInitializationError() from ex

    def _create_object_store_if_needed_unwrapped(self) -> None:
        """Look up the bucket if it already exists and try to create the
        bucket in case it doesn't.  Note that we can't just always try to
        unconditionally create the bucket as Google imposes a strict rate
        limit on bucket creation operations, even if it doesn't result in a
        new bucket.

        Quietly handle the case where the bucket already exists to avoid
        race conditions.  Note that we'll get a 400 Bad Request response for
        invalid bucket names ("Invalid bucket name") as well as for invalid
        project ("Invalid argument"), try to handle both gracefully."""
        start_time = time.time()
        try:
            self._verify_object_storage_unwrapped()
        except TransferObjectStoreMissingError:
            pass  # We only continue with creation in case the bucket does not exist
        else:
            return
        with self._bucket_client() as gs_buckets:
            try:
                self._try_create_bucket(gs_buckets)
                self.log.debug("Created bucket: %r successfully, took: %.3fs", self.bucket_name, time.time() - start_time)
            except HttpError as ex:
                error = json.loads(ex.content.decode("utf-8"))["error"]
                if error["message"].startswith("You already own this bucket"):
                    self.log.debug("Bucket: %r already exists, took: %.3fs", self.bucket_name, time.time() - start_time)
                elif error["message"] == "Invalid argument.":
                    raise InvalidConfigurationError(f"Invalid project id {repr(self.project_id)}")
                elif error["message"].startswith("Invalid bucket name"):
                    raise InvalidConfigurationError(f"Invalid bucket name {repr(self.bucket_name)}")
                else:
                    raise

    def _try_create_bucket(self, gs_buckets: StorageResource.BucketsResource) -> None:
        """Useful for mocking in tests"""
        req = gs_buckets.insert(project=self.project_id, body={"name": self.bucket_name})
        reporter = Reporter(StorageOperation.create_bucket)
        self._retry_on_reset(req, req.execute, retry_reporter=reporter)
        reporter.report(self.stats)

    def create_object_store_if_needed(self) -> None:
        try:
            self._create_object_store_if_needed_unwrapped()
        except HttpError as ex:
            if ex.resp["status"] == "403":
                # Translate 403 errors to the proper exception
                raise TransferObjectStorePermissionError() from ex
            else:
                # Other special cases involving invalid input are already handled
                # Wrap implementation-specific exceptions with rohmu's
                raise TransferObjectStoreInitializationError() from ex

    def get_or_create_bucket(self, bucket_name: str) -> str:
        """Deprecated: use create_object_store_if_needed() instead"""
        if self.bucket_name != bucket_name:
            raise ValueError("This method is not meant to be used with a different bucket name than the one configured")
        self._verify_object_storage_unwrapped()
        return self.bucket_name


class MediaStreamUpload(MediaUpload):
    """Support streaming arbitrary amount of data from non-seekable object supporting read method."""

    def __init__(self, fd: BinaryIO, *, chunk_size: int, mime_type: str, name: str) -> None:
        self._data = b""
        self._next_chunk = b""
        self._chunk_size = chunk_size
        self._fd = fd
        self._mime_type = mime_type
        self._name = name
        self._position: Optional[int] = None

    def chunksize(self) -> int:  # type: ignore[override]
        return self._chunk_size

    def mimetype(self) -> str:
        return self._mime_type

    def size(self) -> Optional[int]:  # type: ignore[override]
        self.peek()
        if len(self._next_chunk) < self.peeksize:
            # The total file size should be returned if we have hit the final chunk.
            return (self._position or 0) + len(self._data) + len(self._next_chunk)
        return None

    def resumable(self) -> bool:
        return True

    @property
    def peeksize(self) -> int:
        # Using 1 extra byte to avoid perfectly aligned file
        return self._chunk_size + 1

    def peek(self) -> None:
        """try to top up some data into _next_chunk"""
        if len(self._next_chunk) < self.peeksize:
            # top-up the _next_chunk
            self._next_chunk = self._read_bytes(self.peeksize - len(self._next_chunk), initial_data=self._next_chunk)

    # second parameter is length but baseclass incorrectly names it end
    def getbytes(self, begin: int, length: int) -> bytes:  # type: ignore[override]
        if begin < (self._position or 0):
            msg = f"Requested position {begin} for {repr(self._name)} precedes already fulfilled position {self._position}"
            raise IndexError(msg)
        elif begin > (self._position or 0) + len(self._data):
            num_bytes = len(self._data)
            msg = (
                f"Requested position {begin} for {repr(self._name)} has gap from previous position {self._position} "
                f"and {num_bytes} byte chunk"
            )
            raise IndexError(msg)

        if self._position is None or begin == self._position + len(self._data):
            if length <= len(self._next_chunk):
                self._data = self._next_chunk[:length]
                self._next_chunk = self._next_chunk[length:]
            else:
                self._data = self._read_bytes(length - len(self._next_chunk), initial_data=self._next_chunk)
                self._next_chunk = b""
        elif begin != self._position or length > len(self._data):
            retain_chunk = self._data[begin - self._position :]
            bytes_remaining = length - len(retain_chunk)
            if 0 < bytes_remaining <= len(self._next_chunk):
                self._data = retain_chunk + self._next_chunk[:bytes_remaining]
                self._next_chunk = self._next_chunk[bytes_remaining:]
            elif bytes_remaining > len(self._next_chunk):
                retain_chunk += self._next_chunk
                self._next_chunk = b""
                self._data = self._read_bytes(length - len(retain_chunk), initial_data=retain_chunk)

        self.peek()
        self._position = begin
        return self._data

    def has_stream(self) -> bool:
        return False

    def stream(self) -> BinaryIO:  # type: ignore[override]
        raise NotImplementedError

    def _read_bytes(self, length: int, *, initial_data: Optional[bytes] = None) -> bytes:
        bytes_remaining = length
        read_results = []
        if initial_data:
            read_results.append(initial_data)
        while bytes_remaining > 0:
            data = self._fd.read(bytes_remaining)
            if data:
                read_results.append(data)
                bytes_remaining -= len(data)
            else:
                break

        if not read_results:
            return b""
        elif len(read_results) == 1:
            return read_results[0]
        else:
            return b"".join(read_results)


class MediaDownloadProtocol(Protocol):
    def next_chunk(self) -> tuple[MediaDownloadProgress, bool]: ...


class MediaIoBaseDownloadWithByteRange:
    """This class is mostly a copy of the googleapiclient's MediaIOBaseDownload class,
    but with the addition of the support for fetching a specific byte_range.

    """

    def __init__(
        self,
        fd: BinaryIO,
        request: HttpRequest,
        chunksize: int = DOWNLOAD_CHUNK_SIZE,
        *,
        byte_range: tuple[int, int],
    ) -> None:
        """Constructor.

        Args:
          fd: io.Base or file object, The stream in which to write the downloaded
            bytes.
          request: googleapiclient.http.HttpRequest, the media request to perform in
            chunks.
          chunksize: int, File will be downloaded in chunks of this many bytes.
          byte_range: tuple[int, int], The byterange to fetch
        """
        self._fd = fd
        self._http = request.http
        self._uri = request.uri
        self._chunksize = chunksize
        self._start_position, self._end_position = byte_range
        self._num_bytes_downloaded = 0
        self._range_size = self._end_position - self._start_position + 1
        if self._range_size < 0:
            raise InvalidByteRangeError(f"Invalid byte_range: {byte_range}. Start must be < end.")
        self._done = False

        self._headers = {}
        req_headers = request.headers or {}
        for k, v in req_headers.items():
            # allow users to supply custom headers by setting them on the request
            # but strip out the ones that are set by default on requests generated by
            # API methods like Drive's files().get(fileId=...)
            if k.lower() not in ("accept", "accept-encoding", "user-agent"):
                self._headers[k] = v

    def next_chunk(self) -> tuple[MediaDownloadProgress, bool]:
        """Get the next chunk of the download.

        Returns:
          (status, done): The value of done will be True when the media has been fully
             downloaded or the total size of the media is unknown.

        Raises:
          googleapiclient.errors.HttpError if the response was not a 2xx (or a 416 is received and the file is empty)
          httplib2.HttpLib2Error if a transport error has occurred.
        """
        headers = self._headers.copy()
        chunk_start = self._num_bytes_downloaded + self._start_position
        chunk_end = chunk_start + self._chunksize - 1
        chunk_end = min(self._end_position, chunk_end)
        headers["range"] = f"bytes={chunk_start}-{chunk_end}"
        resp, content = self._http.request(self._uri, "GET", headers=headers)

        total_size: Optional[int] = None
        if resp.status in (200, 206):
            if "content-location" in resp and resp["content-location"] != self._uri:
                self._uri = resp["content-location"]
            self._num_bytes_downloaded += len(content)
            self._fd.write(content)

            if "content-range" in resp:
                total_size = get_total_size_from_content_range(resp["content-range"])
            elif "content-length" in resp:
                # By RFC 9110 if we end up here this is a 200 OK response and this is the total size of the object
                total_size = int(resp["content-length"])

            size_to_download = (
                self._range_size if total_size is None else min(self._range_size, total_size - self._start_position)
            )
            if self._num_bytes_downloaded == size_to_download:
                self._done = True
            return MediaDownloadProgress(self._num_bytes_downloaded, size_to_download), self._done
        elif resp.status == 416:
            # 416 is Range Not Satisfiable
            # This typically occurs with a zero byte file
            total_size = get_total_size_from_content_range(resp["content-range"])
            if total_size == 0:
                self._done = True
                return MediaDownloadProgress(self._num_bytes_downloaded, total_size), self._done
        raise HttpError(resp, content, uri=self._uri)
