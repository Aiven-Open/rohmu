"""
rohmu - object_storage.base

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""
from ..common.models import StorageModel
from ..errors import StorageError
from ..notifier.interface import Notifier
from ..notifier.null import NullNotifier
from collections import namedtuple
from typing import Callable, Generic, Optional, Type, TypeVar

import logging
import platform

KEY_TYPE_OBJECT = "object"
KEY_TYPE_PREFIX = "prefix"

IterKeyItem = namedtuple("IterKeyItem", ["type", "value"])

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

    def __init__(self, prefix, notifier: Optional[Notifier] = None) -> None:
        self.log = logging.getLogger(self.__class__.__name__)
        if not prefix:
            prefix = ""
        elif prefix[-1] != "/":
            prefix += "/"
        self.prefix = prefix
        self.notifier = notifier or NullNotifier()

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

    @classmethod
    def from_model(cls, model: StorageModelT):
        return cls(**model.dict(by_alias=True))

    def copy_file(self, *, source_key, destination_key, metadata=None, **_kwargs):
        """Performs remote copy from source key name to destination key name. Key must identify a file, trees
        cannot be copied with this method. If no metadata is given copies the existing metadata."""
        raise NotImplementedError

    def format_key_for_backend(self, key, remove_slash_prefix=False, trailing_slash=False):
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

    def format_key_from_backend(self, key):
        """Strip the configured prefix from a key retrieved from the backend
        before passing it on to other pghoard code and presenting it to the
        user."""
        if not self.prefix:
            return key
        if not key.startswith(self.prefix):
            raise StorageError("Key {!r} does not start with expected prefix {!r}".format(key, self.prefix))
        return key[len(self.prefix) :]

    def delete_key(self, key):
        raise NotImplementedError

    def delete_tree(self, key):
        """Delete all keys under given root key. Basic implementation works by just listing all available
        keys and deleting them individually but storage providers can implement more efficient logic."""
        self.log.debug("Deleting tree: %r", key)
        names = [item["name"] for item in self.list_path(key, with_metadata=False, deep=True)]
        for name in names:
            self.delete_key(name)

    def get_contents_to_file(self, key, filepath_to_store_to, *, progress_callback: ProgressProportionCallbackType = None):
        """Write key contents to file pointed by `path` and return metadata.  If `progress_callback` is
        provided it must be a function which accepts two numeric arguments: current state of progress and the
        expected maximum value.  The actual values and value ranges differ per storage provider, some (S3)
        reporting the number of bytes transmitted as the first argument and the total number of expected bytes
        as the second argument, while others (Google) report the progress in percentage as the first value and
        100 as the second value."""
        raise NotImplementedError

    def get_contents_to_fileobj(self, key, fileobj_to_store_to, *, progress_callback: ProgressProportionCallbackType = None):
        """Like `get_contents_to_file()` but writes to an open file-like object."""
        raise NotImplementedError

    def get_contents_to_string(self, key):
        """Returns a tuple (content-byte-string, metadata)"""
        raise NotImplementedError

    def get_file_size(self, key):
        """Returns an int indicating the size of the file in bytes"""
        # This method isn't currently used by PGHoard itself, it is merely provided
        # for applications that use PGHoard's object storage abstraction layer.
        raise NotImplementedError

    def get_metadata_for_key(self, key):
        raise NotImplementedError

    def list_path(self, key, *, with_metadata=True, deep=False):
        return list(self.list_iter(key, with_metadata=with_metadata, deep=deep))

    def list_iter(self, key, *, with_metadata=True, deep=False):
        for item in self.iter_key(key, with_metadata=with_metadata, deep=deep):
            if item.type == KEY_TYPE_OBJECT:
                yield item.value

    def list_prefixes(self, key):
        return list(self.iter_prefixes(key))

    def iter_prefixes(self, key):
        for item in self.iter_key(key, with_metadata=False):
            if item.type == KEY_TYPE_PREFIX:
                yield item.value

    def iter_key(self, key, *, with_metadata=True, deep=False, include_key=False):
        raise NotImplementedError

    def sanitize_metadata(self, metadata, replace_hyphen_with="-"):
        """Convert non-string metadata values to strings and drop null values"""
        return {str(k).replace("-", replace_hyphen_with): str(v) for k, v in (metadata or {}).items() if v is not None}

    def store_file_from_memory(self, key, memstring, metadata=None, cache_control=None, mimetype=None):
        raise NotImplementedError

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
        raise NotImplementedError

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
        raise NotImplementedError


def get_total_memory():
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
