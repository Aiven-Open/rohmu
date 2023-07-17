"""
rohmu - object_storage.base

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""
from __future__ import annotations

from ..common.models import StorageModel
from ..common.statsd import StatsClient, StatsdConfig
from ..errors import FileNotFoundFromStorageError, InvalidByteRangeError, StorageError
from ..notifier.interface import Notifier
from ..notifier.null import NullNotifier
from ..typing import AnyPath, Metadata
from contextlib import suppress
from io import BytesIO
from typing import (
    Any,
    BinaryIO,
    Callable,
    Collection,
    Generic,
    Iterable,
    Iterator,
    NamedTuple,
    Optional,
    Protocol,
    Tuple,
    Type,
    TypeVar,
    Union,
)

import logging
import os
import platform

KEY_TYPE_OBJECT = "object"
KEY_TYPE_PREFIX = "prefix"


class IterKeyItem(NamedTuple):
    type: str
    value: Union[str, dict[str, Any]]


# Percent complete is the ratio of the first argument to the second
ProgressProportionCallbackType = Optional[Callable[[int, int], None]]

# Argument is the additional number of bytes transferred
IncrementalProgressCallbackType = Optional[Callable[[int], None]]


class Config(StorageModel):
    prefix: str
    notifier: Optional[Notifier] = None

    class Config:
        arbitrary_types_allowed = True


StorageModelT = TypeVar("StorageModelT", bound=StorageModel)


class BaseTransfer(Generic[StorageModelT]):
    config_model: Type[StorageModelT]

    is_thread_safe: bool = False
    supports_concurrent_upload: bool = False

    def __init__(
        self, prefix: Optional[str], notifier: Optional[Notifier] = None, statsd_info: Optional[StatsdConfig] = None
    ) -> None:
        self.log = logging.getLogger(self.__class__.__name__)
        if not prefix:
            prefix = ""
        elif prefix[-1] != "/":
            prefix += "/"
        self.prefix = prefix
        self.notifier = notifier or NullNotifier()
        self.stats = StatsClient(statsd_info)

    @staticmethod
    def _incremental_to_proportional_progress(
        *, size: int, cb: ProgressProportionCallbackType
    ) -> IncrementalProgressCallbackType:
        if cb is None:
            return None

        progress_so_far: int = 0

        def wrapper(progress: int) -> None:
            nonlocal progress_so_far
            progress_so_far += progress
            if cb is not None:
                cb(progress_so_far, size)

        return wrapper

    @staticmethod
    def _proportional_to_incremental_progress(cb: IncrementalProgressCallbackType) -> ProgressProportionCallbackType:
        if cb is None:
            return cb
        last_progress: int = 0

        def wrapper(progress: int, _: int) -> None:
            nonlocal last_progress
            if progress > last_progress:
                if cb is not None:
                    cb(progress - last_progress)
                last_progress = progress

        return wrapper

    @staticmethod
    def _should_multipart(
        *, metadata: Optional[Metadata], chunk_size: int, multipart: Union[bool, None] = None, default: bool
    ) -> bool:
        if multipart is not None:
            return multipart

        # multipart = None; up to us
        size = (metadata or {}).get("Content-Length")
        if size is None:
            # We could actually sniff from fd if it is seekable; left TODO for now.
            return default

        return int(size) > chunk_size

    @classmethod
    def from_model(cls, model: StorageModelT) -> BaseTransfer[StorageModelT]:
        return cls(**model.dict(by_alias=True))

    def copy_file(
        self, *, source_key: str, destination_key: str, metadata: Optional[Metadata] = None, **_kwargs: Any
    ) -> None:
        """Performs remote copy from source key name to destination key name. Key must identify a file, trees
        cannot be copied with this method. If no metadata is given copies the existing metadata."""
        raise NotImplementedError

    def format_key_for_backend(self, key: str, remove_slash_prefix: bool = False, trailing_slash: bool = False) -> str:
        """Add a possible prefix to the key before sending it to the backend"""
        path = self.prefix + key
        if trailing_slash:
            if not path or path[-1] != "/":
                path += "/"
        else:
            path = path.rstrip("/")
        if remove_slash_prefix:  # Azure defines slashes in the beginning as "dirs" for listing purposes
            path = path.lstrip("/")
        return path

    def format_key_from_backend(self, key: str) -> str:
        """Strip the configured prefix from a key retrieved from the backend
        before passing it on to other pghoard code and presenting it to the
        user."""
        if not self.prefix:
            return key
        if not key.startswith(self.prefix):
            raise StorageError("Key {!r} does not start with expected prefix {!r}".format(key, self.prefix))
        return key[len(self.prefix) :]

    def delete_key(self, key: str) -> None:
        raise NotImplementedError

    def delete_keys(self, keys: Collection[str]) -> None:
        """Delete specified keys"""
        for key in keys:
            self.delete_key(key)

    def delete_tree(self, key: str) -> None:
        """Delete all keys under given root key. Basic implementation works by just listing all available
        keys and deleting them individually but storage providers can implement more efficient logic."""
        self.log.debug("Deleting tree: %r", key)
        names = [item["name"] for item in self.list_path(key, with_metadata=False, deep=True)]
        self.delete_keys(names)

    def get_contents_to_file(
        self, key: str, filepath_to_store_to: AnyPath, *, progress_callback: ProgressProportionCallbackType = None
    ) -> Metadata:
        """Write key contents to file pointed by `path` and return metadata.  If `progress_callback` is
        provided it must be a function which accepts two numeric arguments: current state of progress and the
        expected maximum value.  The actual values and value ranges differ per storage provider, some (S3)
        reporting the number of bytes transmitted as the first argument and the total number of expected bytes
        as the second argument, while others (Google) report the progress in percentage as the first value and
        100 as the second value."""
        try:
            with open(filepath_to_store_to, "wb") as fd:
                metadata = self.get_contents_to_fileobj(key, fd, progress_callback=progress_callback)
                return metadata
        except FileNotFoundError as ex:
            raise FileNotFoundFromStorageError from ex
        except:
            with suppress(FileNotFoundError):
                os.unlink(filepath_to_store_to)
            raise

    def get_contents_to_fileobj(
        self,
        key: str,
        fileobj_to_store_to: BinaryIO,
        *,
        byte_range: Optional[Tuple[int, int]] = None,
        progress_callback: ProgressProportionCallbackType = None,
    ) -> Metadata:
        """Like `get_contents_to_file()` but writes to an open file-like object."""
        raise NotImplementedError

    def _validate_byte_range(self, byte_range: Optional[Tuple[int, int]]) -> None:
        if byte_range is not None and byte_range[0] > byte_range[1]:
            raise InvalidByteRangeError(f"Invalid byte_range: {byte_range}. Start must be <= end.")

    def get_contents_to_string(self, key: str, *, byte_range: Optional[Tuple[int, int]] = None) -> tuple[bytes, Metadata]:
        """Returns a tuple (content-byte-string, metadata).

        byte_range can be used to limit the content requested (as per RFC9110 section 14.1.2):
        it defines range of bytes to fetch (inclusive), so e.g. [0, 499] means first 500 bytes.
        If it is not supported for specific storage backend, NotImplementedError will be raised.
        """
        with BytesIO() as buf:
            metadata = self.get_contents_to_fileobj(key, buf, byte_range=byte_range)
            return buf.getvalue(), metadata

    def get_file_size(self, key: str) -> int:
        """Returns an int indicating the size of the file in bytes"""
        # This method isn't currently used by PGHoard itself, it is merely provided
        # for applications that use PGHoard's object storage abstraction layer.
        raise NotImplementedError

    def get_metadata_for_key(self, key: str) -> Metadata:
        raise NotImplementedError

    def list_path(self, key: str, *, with_metadata: bool = True, deep: bool = False) -> list[dict[str, Any]]:
        return list(self.list_iter(key, with_metadata=with_metadata, deep=deep))

    def list_iter(self, key: str, *, with_metadata: bool = True, deep: bool = False) -> Iterator[dict[str, Any]]:
        for item in self.iter_key(key, with_metadata=with_metadata, deep=deep):
            if item.type == KEY_TYPE_OBJECT:
                assert isinstance(item.value, dict)
                yield item.value

    def list_prefixes(self, key: str) -> list[str]:
        return list(self.iter_prefixes(key))

    def iter_prefixes(self, key: str) -> Iterator[str]:
        for item in self.iter_key(key, with_metadata=False):
            if item.type == KEY_TYPE_PREFIX:
                assert isinstance(item.value, str)
                yield item.value

    def iter_key(
        self, key: str, *, with_metadata: bool = True, deep: bool = False, include_key: bool = False
    ) -> Iterator[IterKeyItem]:
        raise NotImplementedError

    def sanitize_metadata(self, metadata: Optional[Metadata], replace_hyphen_with: str = "-") -> dict[str, str]:
        """Convert non-string metadata values to strings and drop null values"""
        return {str(k).replace("-", replace_hyphen_with): str(v) for k, v in (metadata or {}).items() if v is not None}

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
        with BytesIO(memstring) as buf:
            size = len(memstring)
            if metadata is None:
                metadata = {"Content-Length": size}
            elif metadata.get("Content-Length") is None:
                metadata = metadata.copy()
                metadata["Content-Length"] = size
            self.store_file_object(
                key,
                buf,
                cache_control=cache_control,
                metadata=metadata,
                mimetype=mimetype,
                multipart=multipart,
                upload_progress_fn=self._incremental_to_proportional_progress(cb=progress_fn, size=size),
            )

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
    ) -> None:
        size = os.path.getsize(filepath)
        with open(filepath, "rb") as fd:
            if metadata is None:
                metadata = {"Content-Length": size}
            elif metadata.get("Content-Length") is None:
                metadata = metadata.copy()
                metadata["Content-Length"] = size
            self.store_file_object(
                key,
                fd,
                cache_control=cache_control,
                metadata=metadata,
                mimetype=mimetype,
                multipart=multipart,
                upload_progress_fn=self._incremental_to_proportional_progress(cb=progress_fn, size=size),
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
    ) -> None:
        raise NotImplementedError

    def create_concurrent_upload(self, key: str, metadata: Optional[Metadata] = None) -> ConcurrentUpload:
        """Starts a concurrent upload to the object storage.

        :param key: the key of the object to upload
        :param metadata: metadata to be associated with the object


        Returns a ConcurrentUpload instance that can be used to upload multiple chunks in parallel.

        This method will raise a NotImplementedError if supports_concurrent_upload is False.
        """
        raise NotImplementedError

    # We may want to exclude this API endpoint for the first implementation and add support for resuming later on
    def get_concurrent_upload(self, upload_id: str) -> ConcurrentUpload:
        """Returns the concurrent upload instance with the given id.

        :param upload_id: id of the upload to resume

        Retrieve the state of the given upload object and returns it. May cache return value.

        This call can be used to continue an upload even after restarts.

        This method will raise a NotImplementedError if supports_concurrent_upload is False.
        """
        raise NotImplementedError


class ConcurrentUpload(Protocol):
    """A ConcurrentUpload is a thread-safe object that lets up upload multiple chunks of data concurrently.

    Chunks can be uploaded concurrently in non-monotonic order.

    After finishing uploading all the chunks you can complete the upload in order to create the object by calling
    the `complete` method. You can also `abort` the upload.

    """

    @property
    def upload_id(self) -> str:
        """The identifier for this concurrent upload.

        The users should treat this as an opaque identifier. The exact format depends on the transfer class.
        """
        raise NotImplementedError

    def list_uploaded_chunks(self) -> Iterable[int]:
        """List the chunks uploaded successfully in order.

        A user can use this method to understand where they should start re-sending chunks after resuming an upload."""
        raise NotImplementedError

    def upload_chunk(self, chunk_number: int, fd: BinaryIO) -> None:
        """Synchronously uploads a chunk. Returns an ETag for the uploaded chunk.

        This method is thread-safe, so you can call it concurrently from multiple threads to upload different chunks.

        What happens if multiple threads try to upload the same chunk_number concurrently is unspecified.
        """
        raise NotImplementedError

    # NOTE: we do not support the UploadPartCopy of S3 for now... not all backends allow a good implementation for that
    #       however in that case we would have something like upload_chunk_from(bucket, key, byte_range) or similar

    def complete(self) -> None:
        """Completes the upload. After this method returns successfully the object will be present in the object storage.

        All operations on this concurrent upload will fail afterwards.
        """
        raise NotImplementedError

    def abort(self) -> None:
        """Aborts the upload.

        This clears all uploaded data and terminates the upload.

        All operations on this concurrent upload will fail afterwards.
        """
        raise NotImplementedError


def get_total_memory() -> Optional[int]:
    """return total system memory in mebibytes (or None if parsing meminfo fails)"""
    if platform.system() != "Linux":
        return None

    with open("/proc/meminfo", "r") as in_file:
        for line in in_file:
            info = line.split()
            if info[0] == "MemTotal:" and info[-1] == "kB":
                memory_mb = int(int(info[1]) / 1024)
                return memory_mb

    return None
