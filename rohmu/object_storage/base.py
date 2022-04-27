"""
rohmu - object_storage.base

Copyright (c) 2016 Ohmu Ltd
See LICENSE for details
"""
from ..errors import StorageError
import logging


class BaseTransfer:
    def __init__(self, prefix):
        self.log = logging.getLogger(self.__class__.__name__)
        if not prefix:
            prefix = ""
        elif prefix[-1] != "/":
            prefix += "/"
        self.prefix = prefix

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
        return key[len(self.prefix):]

    def delete_key(self, key):
        raise NotImplementedError

    def get_contents_to_file(self, key, filepath_to_store_to, *, progress_callback=None):
        """Write key contents to file pointed by `path` and return metadata.  If `progress_callback` is
        provided it must be a function which accepts two numeric arguments: current state of progress and the
        expected maximum value.  The actual values and value ranges differ per storage provider, some (S3)
        reporting the number of bytes transmitted as the first argument and the total number of expected bytes
        as the second argument, while others (Google) report the progress in percentage as the first value and
        100 as the second value."""
        raise NotImplementedError

    def get_contents_to_fileobj(self, key, fileobj_to_store_to, *, progress_callback=None):
        """Like `get_contents_to_file()` but writes to an open file-like object."""
        raise NotImplementedError

    def get_contents_to_string(self, key):
        """Returns a tuple (content-byte-string, metadata)"""
        raise NotImplementedError

    def get_metadata_for_key(self, key):
        raise NotImplementedError

    def list_path(self, key, *, with_metadata=True):
        return list(self.list_iter(key, with_metadata=with_metadata))

    def list_iter(self, key, *, with_metadata=True):
        raise NotImplementedError

    def sanitize_metadata(self, metadata, replace_hyphen_with="-"):
        """Convert non-string metadata values to strings and drop null values"""
        return {str(k).replace("-", replace_hyphen_with): str(v)
                for k, v in (metadata or {}).items() if v is not None}

    def store_file_from_memory(self, key, memstring, metadata=None):
        raise NotImplementedError

    def store_file_from_disk(self, key, filepath, metadata=None, multipart=None):
        raise NotImplementedError
