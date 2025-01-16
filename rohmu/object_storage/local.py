# Copyright (c) 2016 Ohmu Ltd
# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""Rohmu - local filesystem interface"""

from __future__ import annotations

from pathlib import Path
from rohmu.common.models import StorageOperation
from rohmu.common.statsd import StatsdConfig
from rohmu.errors import ConcurrentUploadError, Error, FileNotFoundFromStorageError
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
from rohmu.object_storage.config import LOCAL_CHUNK_SIZE as CHUNK_SIZE, LocalObjectStorageConfig as Config
from rohmu.typing import Metadata
from rohmu.util import BinaryStreamsConcatenation, ProgressStream
from typing import Any, BinaryIO, Iterator, Optional, TextIO, Tuple, Union
from typing_extensions import Self

import contextlib
import datetime
import hashlib
import json
import os
import shutil
import tempfile
import uuid

INTERNAL_METADATA_KEY_HASH = "_hash"
INTERNAL_METADATA_KEYS = {INTERNAL_METADATA_KEY_HASH}


class LocalTransfer(BaseTransfer[Config]):
    config_model = Config

    is_thread_safe = True
    supports_concurrent_upload = True

    def __init__(
        self,
        directory: Union[str, Path],
        prefix: Optional[str] = None,
        notifier: Optional[Notifier] = None,
        statsd_info: Optional[StatsdConfig] = None,
        ensure_object_store_available: bool = True,
    ) -> None:
        prefix = os.path.join(directory, (prefix or "").strip("/"))
        super().__init__(
            prefix=prefix,
            notifier=notifier,
            statsd_info=statsd_info,
            ensure_object_store_available=ensure_object_store_available,
        )
        self.log.debug("LocalTransfer initialized")

    def _verify_object_storage_unwrapped(self) -> None:
        """No-op as there's no need to check for the existence of the directory at setup time."""

    def verify_object_storage(self) -> None:
        """No-op as there's no need to check for the existence of the directory at setup time."""

    def _create_object_store_if_needed_unwrapped(self) -> None:
        """No-op as there's no need to create the directory ahead of time."""

    def create_object_store_if_needed(self) -> None:
        """No-op as there's no need to create the directory ahead of time."""

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
        source_path = source_bucket.format_key_for_backend(source_key.strip("/"))
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

    def _get_metadata_for_key(self, key: str) -> Metadata:
        source_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.exists(source_path):
            raise FileNotFoundFromStorageError(key)
        metadata_path = source_path + ".metadata"
        try:
            with open(metadata_path, encoding="utf-8") as fp:
                return json.load(fp)
        except FileNotFoundError:
            raise FileNotFoundFromStorageError(key)

    def _filter_internal_metadata(self, metadata: Metadata) -> Metadata:
        return {key: value for key, value in metadata.items() if key in INTERNAL_METADATA_KEYS}

    def _filter_metadata(self, metadata: Metadata) -> Metadata:
        return {key: value for key, value in metadata.items() if key not in INTERNAL_METADATA_KEYS}

    def get_metadata_for_key(self, key: str) -> Metadata:
        return self._filter_metadata(self._get_metadata_for_key(key))

    def delete_key(self, key: str, preserve_trailing_slash: bool = False) -> None:
        self.log.debug("Deleting key: %r", key)
        if preserve_trailing_slash:
            raise Error("LocalTransfer does not support preserving trailing slashes")
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

    def delete_tree(self, key: str, preserve_trailing_slash: bool = False) -> None:
        self.log.debug("Deleting tree: %r", key)
        if preserve_trailing_slash:
            raise Error("LocalTransfer does not support preserving trailing slashes")
        target_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.isdir(target_path):
            raise FileNotFoundFromStorageError(key)
        shutil.rmtree(target_path)
        self.notifier.tree_deleted(key=key)

    @staticmethod
    def _skip_file_name(file_name: str) -> bool:
        return file_name.startswith(".") or file_name.endswith(".metadata") or ".metadata_tmp" in file_name

    def _yield_object(self, key: str, full_path: str, with_metadata: bool) -> Iterator[IterKeyItem]:
        try:
            metadata = self._get_metadata_for_key(key)
        except FileNotFoundFromStorageError:
            return
        st = os.stat(full_path)
        last_modified = datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc)
        md5 = metadata.get(INTERNAL_METADATA_KEY_HASH)
        yield IterKeyItem(
            type=KEY_TYPE_OBJECT,
            value={
                "name": key,
                "size": st.st_size,
                "last_modified": last_modified,
                "metadata": self._filter_metadata(metadata) if with_metadata else None,
                **({"md5": md5} if md5 else {}),
            },
        )

    def iter_key(
        self, key: str, *, with_metadata: bool = True, deep: bool = False, include_key: bool = False
    ) -> Iterator[IterKeyItem]:
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
        key: str,
        fileobj_to_store_to: BinaryIO,
        *,
        byte_range: Optional[Tuple[int, int]] = None,
        progress_callback: ProgressProportionCallbackType = None,
    ) -> Metadata:
        self._validate_byte_range(byte_range)
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

    def get_file_size(self, key: str) -> int:
        source_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.exists(source_path):
            raise FileNotFoundFromStorageError(key)
        return os.stat(source_path).st_size

    def _save_metadata(self, target_path: str, metadata: Optional[Metadata]) -> None:
        metadata_path = target_path + ".metadata"
        with atomic_create_file(metadata_path) as fp:
            json.dump(self.sanitize_metadata(metadata), fp)

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

    def create_concurrent_upload(
        self,
        key: str,
        metadata: Optional[Metadata] = None,
        mimetype: Optional[str] = None,
        cache_control: Optional[str] = None,
    ) -> ConcurrentUpload:
        upload_id = uuid.uuid4().hex
        upload = ConcurrentUpload("local", upload_id, key, metadata, {})
        chunks_dir = self._get_chunks_dir(upload)
        try:
            os.makedirs(chunks_dir, exist_ok=True)
        except OSError as ex:
            raise ConcurrentUploadError(f"Failed to initiate multipart upload for {key}") from ex
        self.stats.operation(StorageOperation.create_multipart_upload)
        return upload

    def upload_concurrent_chunk(
        self,
        upload: ConcurrentUpload,
        chunk_number: int,
        fd: BinaryIO,
        upload_progress_fn: IncrementalProgressCallbackType = None,
    ) -> None:
        chunks_dir = self._get_chunks_dir(upload)
        try:
            with atomic_create_file_binary(os.path.join(chunks_dir, str(chunk_number))) as chunk_fp:
                wrapped_fd = ProgressStream(fd)
                for data in iter(lambda: wrapped_fd.read(CHUNK_SIZE), b""):
                    chunk_fp.write(data)
                bytes_read = wrapped_fd.bytes_read
            if upload_progress_fn:
                upload_progress_fn(bytes_read)
            self.stats.operation(StorageOperation.store_file, size=bytes_read)
            upload.chunks_to_etags[chunk_number] = "no-etag"
        except OSError as ex:
            raise ConcurrentUploadError(
                f"Failed to upload chunk {chunk_number} of multipart upload for {upload.key}"
            ) from ex

    def complete_concurrent_upload(self, upload: ConcurrentUpload) -> None:
        chunks_dir = self._get_chunks_dir(upload)
        try:
            chunk_filenames = sorted(
                (str(chunk_number) for chunk_number in upload.chunks_to_etags),
                key=int,
            )
            chunk_files = (open(os.path.join(chunks_dir, chunk_file), "rb") for chunk_file in chunk_filenames)
            stream = BinaryStreamsConcatenation(chunk_files)
        except OSError as ex:
            raise ConcurrentUploadError(f"Failed to complete multipart upload for {upload.key}") from ex
        self.store_file_object(
            upload.key,
            stream,  # type: ignore[arg-type]
            metadata=upload.metadata,
        )
        try:
            shutil.rmtree(chunks_dir)
        except OSError:
            self.log.exception("Could not clean up temporary directory %r", chunks_dir)

    def abort_concurrent_upload(self, upload: ConcurrentUpload) -> None:
        chunks_dir = self._get_chunks_dir(upload)
        try:
            shutil.rmtree(chunks_dir)
        except OSError as ex:
            raise ConcurrentUploadError(f"Failed to abort multipart upload for {upload.key}") from ex

    def _get_chunks_dir(self, upload: ConcurrentUpload) -> str:
        return self.format_key_for_backend(".concurrent_upload_" + upload.backend_id)


@contextlib.contextmanager
def atomic_create_file(file_path: str) -> Iterator[TextIO]:
    """Open a temporary file for writing, rename to final name when done"""
    fd, tmp_file_path = tempfile.mkstemp(
        prefix=os.path.basename(file_path), dir=os.path.dirname(file_path), suffix=".metadata_tmp"
    )
    try:
        with os.fdopen(fd, "w") as out_file:
            yield out_file

        os.rename(tmp_file_path, file_path)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp_file_path)
        raise


@contextlib.contextmanager
def atomic_create_file_binary(file_path: str) -> Iterator[BinaryIO]:
    """Open a temporary file for writing, rename to final name when done"""
    fd, tmp_file_path = tempfile.mkstemp(prefix=os.path.basename(file_path), dir=os.path.dirname(file_path))
    try:
        with os.fdopen(fd, "wb") as out_file:
            yield out_file

        os.rename(tmp_file_path, file_path)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp_file_path)
        raise
