"""
rohmu - local filesystem interface

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""
from ..common.models import StorageModel
from ..common.statsd import StatsdConfig
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
from typing import Optional, Tuple, Union

import contextlib
import datetime
import hashlib
import json
import os
import shutil
import tempfile

CHUNK_SIZE = 1024 * 1024
INTERNAL_METADATA_KEY_HASH = "_hash"
INTERNAL_METADATA_KEYS = {INTERNAL_METADATA_KEY_HASH}


class Config(StorageModel):
    directory: str
    prefix: Optional[str] = None


class LocalTransfer(BaseTransfer[Config]):
    config_model = Config

    def __init__(
        self,
        directory,
        prefix=None,
        notifier: Optional[Notifier] = None,
        statsd_info: Optional[StatsdConfig] = None,
    ) -> None:
        prefix = os.path.join(directory, (prefix or "").strip("/"))
        super().__init__(prefix=prefix, notifier=notifier, statsd_info=statsd_info)
        self.log.debug("LocalTransfer initialized")

    def copy_file(self, *, source_key, destination_key, metadata=None, **_kwargs):
        source_path = self.format_key_for_backend(source_key.strip("/"))
        destination_path = self.format_key_for_backend(destination_key.strip("/"))
        if not os.path.isfile(source_path):
            raise FileNotFoundFromStorageError(source_key)
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        shutil.copy(source_path, destination_path)
        if metadata is None:
            shutil.copy(source_path + ".metadata", destination_path + ".metadata")
        else:
            new_metadata = self._filter_internal_metadata(self._get_metadata_for_key(source_key))
            new_metadata.update(metadata)
            self._save_metadata(destination_path, new_metadata)
        self.notifier.object_copied(key=destination_key, size=os.path.getsize(destination_path), metadata=metadata)

    def _get_metadata_for_key(self, key):
        source_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.exists(source_path):
            raise FileNotFoundFromStorageError(key)
        metadata_path = source_path + ".metadata"
        try:
            with open(metadata_path, "r") as fp:
                return json.load(fp)
        except FileNotFoundError:
            raise FileNotFoundFromStorageError(key)

    def _filter_internal_metadata(self, metadata):
        return {key: value for key, value in metadata.items() if key in INTERNAL_METADATA_KEYS}

    def _filter_metadata(self, metadata):
        return {key: value for key, value in metadata.items() if key not in INTERNAL_METADATA_KEYS}

    def get_metadata_for_key(self, key):
        return self._filter_metadata(self._get_metadata_for_key(key))

    def delete_key(self, key: str) -> None:
        self.log.debug("Deleting key: %r", key)
        target_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.exists(target_path):
            raise FileNotFoundFromStorageError(key)
        os.unlink(target_path)
        metadata_tmp_path = target_path + ".metadata_tmp"
        with contextlib.suppress(FileNotFoundError):
            os.unlink(metadata_tmp_path)
        metadata_path = target_path + ".metadata"
        with contextlib.suppress(FileNotFoundError):
            os.unlink(metadata_path)
        self.notifier.object_deleted(key=key)

    def delete_tree(self, key):
        self.log.debug("Deleting tree: %r", key)
        target_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.isdir(target_path):
            raise FileNotFoundFromStorageError(key)
        shutil.rmtree(target_path)
        self.notifier.tree_deleted(key=key)

    @staticmethod
    def _skip_file_name(file_name):
        return file_name.startswith(".") or file_name.endswith(".metadata") or ".metadata_tmp" in file_name

    def _yield_object(self, key, full_path, with_metadata):
        try:
            metadata = self._get_metadata_for_key(key)
        except FileNotFoundFromStorageError:
            return
        st = os.stat(full_path)
        last_modified = datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc)
        yield IterKeyItem(
            type=KEY_TYPE_OBJECT,
            value={
                "name": key,
                "size": st.st_size,
                "last_modified": last_modified,
                "md5": metadata[INTERNAL_METADATA_KEY_HASH],
                "metadata": self._filter_metadata(metadata) if with_metadata else None,
            },
        )

    def iter_key(self, key, *, with_metadata=True, deep=False, include_key=False):
        target_path = self.format_key_for_backend(key.strip("/"))
        try:
            input_files = os.listdir(target_path)
        except FileNotFoundError:
            return
        except NotADirectoryError:
            if include_key:
                file_name = os.path.basename(target_path)
                if self._skip_file_name(file_name):
                    return
                yield from self._yield_object(key.strip("/"), target_path, with_metadata=with_metadata)
            return

        for file_name in input_files:
            if self._skip_file_name(file_name):
                continue
            full_path = os.path.join(target_path, file_name)
            if os.path.isdir(full_path):
                file_key = os.path.join(key.strip("/"), file_name)
                if deep:
                    yield from self.iter_key(file_key, with_metadata=with_metadata, deep=True)
                else:
                    yield IterKeyItem(type=KEY_TYPE_PREFIX, value=file_key)
            else:
                yield from self._yield_object(
                    key=os.path.join(key.strip("/"), file_name),
                    full_path=full_path,
                    with_metadata=with_metadata,
                )

    def get_contents_to_fileobj(
        self,
        key,
        fileobj_to_store_to,
        *,
        byte_range: Optional[Tuple[int, int]] = None,
        progress_callback: ProgressProportionCallbackType = None,
    ):
        source_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.exists(source_path):
            raise FileNotFoundFromStorageError(key)

        input_size = os.stat(source_path).st_size
        bytes_written = 0
        with open(source_path, "rb") as fp:
            if byte_range:
                fp.seek(byte_range[0])
                input_size = byte_range[1] - byte_range[0] + 1
            while bytes_written <= input_size:
                left = min(input_size - bytes_written, CHUNK_SIZE)
                buf = fp.read(left)
                if not buf:
                    break
                fileobj_to_store_to.write(buf)
                bytes_written += len(buf)
                if progress_callback:
                    progress_callback(bytes_written, input_size)

        return self.get_metadata_for_key(key)

    def get_file_size(self, key):
        source_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.exists(source_path):
            raise FileNotFoundFromStorageError(key)
        return os.stat(source_path).st_size

    def _save_metadata(self, target_path, metadata):
        metadata_path = target_path + ".metadata"
        with atomic_create_file(metadata_path) as fp:
            json.dump(self.sanitize_metadata(metadata), fp)

    def store_file_object(
        self,
        key,
        fd,
        metadata=None,
        *,
        cache_control=None,
        mimetype=None,
        multipart: Union[bool, None] = None,
        upload_progress_fn: IncrementalProgressCallbackType = None,
    ):  # pylint: disable=unused-argument
        target_path = self.format_key_for_backend(key.strip("/"))
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        bytes_written = 0
        m = hashlib.sha256()
        with open(target_path, "wb") as output_fp:
            while True:
                data = fd.read(1024 * 1024)
                if not data:
                    break
                m.update(data)
                output_fp.write(data)
                bytes_written += len(data)
                if upload_progress_fn:
                    upload_progress_fn(bytes_written)
        metadata = metadata.copy() if metadata is not None else {}
        metadata[INTERNAL_METADATA_KEY_HASH] = m.hexdigest()
        self._save_metadata(target_path, metadata)
        self.notifier.object_created(
            key=key, size=os.path.getsize(target_path), metadata=self.sanitize_metadata(self._filter_metadata(metadata))
        )


@contextlib.contextmanager
def atomic_create_file(file_path):
    """Open a temporary file for writing, rename to final name when done"""
    fd, tmp_file_path = tempfile.mkstemp(
        prefix=os.path.basename(file_path), dir=os.path.dirname(file_path), suffix=".metadata_tmp"
    )
    try:
        with os.fdopen(fd, "w") as out_file:
            yield out_file

        os.rename(tmp_file_path, file_path)
    except Exception:  # pytest: disable=broad-except
        with contextlib.suppress(Exception):
            os.unlink(tmp_file_path)
        raise
