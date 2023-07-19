"""
rohmu - local filesystem interface

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""

from __future__ import annotations

from ..common.models import StorageModel, StorageOperation
from ..common.statsd import StatsdConfig
from ..errors import FileNotFoundFromStorageError, StorageError, UninitializedError
from ..notifier.interface import Notifier
from ..typing import Metadata
from ..util import BinaryStreamsConcatenation
from .base import (
    BaseTransfer,
    ConcurrentUpload,
    IncrementalProgressCallbackType,
    IterKeyItem,
    KEY_TYPE_OBJECT,
    KEY_TYPE_PREFIX,
    ProgressProportionCallbackType,
)
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator, Optional, TextIO, Tuple, Union

import base64
import contextlib
import datetime
import hashlib
import json
import logging
import os
import shutil
import tempfile

CHUNK_SIZE = 1024 * 1024
INTERNAL_METADATA_KEY_HASH = "_hash"
INTERNAL_METADATA_KEYS = {INTERNAL_METADATA_KEY_HASH}


class Config(StorageModel):
    directory: str
    prefix: Optional[str] = None
    concurrent_upload_directory: Optional[str] = None


class LocalTransfer(BaseTransfer[Config]):  # pylint: disable=abstract-method
    config_model = Config

    is_thread_safe = True
    supports_concurrent_upload = True

    def __init__(
        self,
        directory: Union[str, Path],
        prefix: Optional[str] = None,
        notifier: Optional[Notifier] = None,
        statsd_info: Optional[StatsdConfig] = None,
        concurrent_upload_directory: Optional[str] = None,
    ) -> None:
        prefix = os.path.join(directory, (prefix or "").strip("/"))
        super().__init__(prefix=prefix, notifier=notifier, statsd_info=statsd_info)
        # NOTE: I don't want to break the interface for existing clients, so if they don't have the configuration
        #       we just use a random directory... I assume that they won't be using the concurrent upload functionality
        #       so we shouldn't leave around stuff. When the clients are updated to use the concurrent upload functionality
        #       they should really configure this setting.
        self._concurrent_upload_directory = concurrent_upload_directory or tempfile.mkdtemp(prefix="rohmu_mpu_")
        self._mpu_cache: dict[str, LocalConcurrentUpload] = {}
        self.log.debug("LocalTransfer initialized")

    def copy_file(
        self, *, source_key: str, destination_key: str, metadata: Optional[Metadata] = None, **_kwargs: Any
    ) -> None:
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

    def _get_metadata_for_key(self, key: str) -> Metadata:
        source_path = self.format_key_for_backend(key.strip("/"))
        if not os.path.exists(source_path):
            raise FileNotFoundFromStorageError(key)
        metadata_path = source_path + ".metadata"
        try:
            with open(metadata_path, "r") as fp:
                return json.load(fp)
        except FileNotFoundError:
            raise FileNotFoundFromStorageError(key)

    def _filter_internal_metadata(self, metadata: Metadata) -> Metadata:
        return {key: value for key, value in metadata.items() if key in INTERNAL_METADATA_KEYS}

    def _filter_metadata(self, metadata: Metadata) -> Metadata:
        return {key: value for key, value in metadata.items() if key not in INTERNAL_METADATA_KEYS}

    def get_metadata_for_key(self, key: str) -> Metadata:
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

    def delete_tree(self, key: str) -> None:
        self.log.debug("Deleting tree: %r", key)
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
        with atomic_create_file(metadata_path, suffix=".metadata_tmp") as fp:
            json.dump(self.sanitize_metadata(metadata), fp)

    def store_file_object(
        self,
        key: str,
        fd: BinaryIO,
        metadata: Optional[Metadata] = None,
        *,
        cache_control: Optional[str] = None,  # pylint: disable=unused-argument
        mimetype: Optional[str] = None,  # pylint: disable=unused-argument
        multipart: Optional[bool] = None,  # pylint: disable=unused-argument
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

    def create_concurrent_upload(self, key: str, metadata: Optional[Metadata] = None) -> ConcurrentUpload:
        upload = LocalConcurrentUpload(
            transfer=self,
            concurrent_upload_directory=self._concurrent_upload_directory,
            key=key,
            metadata=self.sanitize_metadata(metadata) if metadata is not None else None,
        )
        upload.start()
        self._mpu_cache[upload.upload_id] = upload
        return upload

    def get_concurrent_upload(self, upload_id: str) -> ConcurrentUpload:
        try:
            return self._mpu_cache[upload_id]
        except KeyError:
            pass

        info = json.loads(base64.b64decode(upload_id.encode("ascii")))
        if info.pop("cloud") != "local":
            raise StorageError("Upload {} is not for local".format(upload_id))
        local_upload_id = info.pop("upload_id")
        upload = LocalConcurrentUpload(transfer=self, **info)
        upload.resume(local_upload_id)
        self._mpu_cache[upload_id] = upload
        return upload


@contextlib.contextmanager
def atomic_create_file(file_path: str, suffix: Optional[str] = None) -> Iterator[TextIO]:
    """Open a temporary file for writing in text mode, rename to final name when done"""
    fd, tmp_file_path = tempfile.mkstemp(prefix=os.path.basename(file_path), dir=os.path.dirname(file_path), suffix=suffix)
    try:
        with os.fdopen(fd, "w") as out_file:
            yield out_file

        os.rename(tmp_file_path, file_path)
    except Exception:  # pytest: disable=broad-except
        with contextlib.suppress(Exception):
            os.unlink(tmp_file_path)
        raise


@contextlib.contextmanager
def atomic_create_file_binary(file_path: str, suffix: Optional[str] = None) -> Iterator[BinaryIO]:
    """Open a temporary file for writing in text mode, rename to final name when done"""
    fd, tmp_file_path = tempfile.mkstemp(
        prefix=os.path.basename(file_path), dir=os.path.dirname(file_path), suffix=suffix, text=False
    )
    try:
        with os.fdopen(fd, "wb") as out_file:
            yield out_file

        os.rename(tmp_file_path, file_path)
    except Exception:  # pytest: disable=broad-except
        with contextlib.suppress(Exception):
            os.unlink(tmp_file_path)
        raise


class LocalConcurrentUpload:
    def __init__(
        self,
        *,
        transfer: LocalTransfer,
        key: str,
        concurrent_upload_directory: Optional[str] = None,
        metadata: Optional[dict[str, str]] = None,
    ) -> None:
        self.log = logging.getLogger(LocalConcurrentUpload.__name__)
        self.transfer = transfer
        self.concurrent_upload_directory = concurrent_upload_directory
        self.key = key
        self.metadata = metadata
        self._upload_tmp_dir = "<uninitialized>"
        self._started = False
        self._completed = False
        self._aborted = False

    def _check_started(self) -> None:
        if not self._started:
            raise UninitializedError("Upload is not initialized")

    def _check_not_started(self) -> None:
        if self._started:
            raise StorageError("Upload {} for {} was already started".format(self._upload_tmp_dir, self.key))

    def _check_not_finished(self) -> None:
        if self._completed or self._aborted:
            raise StorageError("Upload {} for {} was already completed or aborted".format(self._upload_tmp_dir, self.key))

    @property
    def upload_id(self) -> str:
        self._check_started()
        info = {
            "cloud": "local",
            "upload_id": self._upload_tmp_dir,
            "key": self.key,
        }
        return base64.b64encode(json.dumps(info).encode("ascii")).decode("ascii")

    def resume(self, local_upload_id: str) -> None:
        self._check_not_started()
        self.log.debug("Resuming to upload multipart file: %r", self.key)
        self._upload_tmp_dir = local_upload_id
        self._started = True

    def start(self) -> None:
        self._check_not_started()
        if self.concurrent_upload_directory is None:
            raise UninitializedError("You must provide the concurrent_upload_directory to start a new concurrent upload")
        self.log.debug("Starting to upload multipart file: %r", self.key)
        self.transfer.stats.operation(StorageOperation.create_multipart_upload)
        upload_directory = tempfile.mkdtemp(prefix="mpu-", dir=self.concurrent_upload_directory)
        os.mkdir(os.path.join(upload_directory, "chunks"))
        with atomic_create_file(os.path.join(upload_directory, "metadata"), suffix="metadata_tmp") as fp:
            json.dump(self.metadata or {}, fp)

        self._upload_tmp_dir = upload_directory
        self._started = True

    def list_uploaded_chunks(self) -> Iterable[int]:
        self._check_started()
        mpu_files = os.listdir(os.path.join(self._upload_tmp_dir, "chunks"))

        for chunk_filename in sorted(int(chunk_file) for chunk_file in mpu_files):
            yield int(chunk_filename)

    def upload_chunk(self, chunk_number: int, fd: BinaryIO) -> None:
        self._check_started()
        self._check_not_finished()
        try:
            with atomic_create_file_binary(os.path.join(self._upload_tmp_dir, "chunks", str(chunk_number))) as chunk_fp:
                for data in iter(lambda: fd.read(CHUNK_SIZE), b""):
                    chunk_fp.write(data)
        except OSError as ex:
            raise StorageError("Failed to upload chunk {} of multipart upload for {}".format(chunk_number, self.key)) from ex

    def complete(self) -> None:
        self._check_started()
        if self._completed:
            return
        elif self._aborted:
            raise StorageError("Upload {} for {} was already aborted".format(self._upload_tmp_dir, self.key))
        try:
            try:
                with open(os.path.join(self._upload_tmp_dir, "metadata")) as metadata_fp:
                    metadata = json.load(metadata_fp)
            except FileNotFoundError:
                metadata = None
            chunks_dir = os.path.join(self._upload_tmp_dir, "chunks")
            chunk_filenames = sorted(
                (chunk_file for chunk_file in os.listdir(chunks_dir)),
                key=int,
            )
            chunk_files = (open(os.path.join(chunks_dir, chunk_file), "rb") for chunk_file in chunk_filenames)
            stream = BinaryStreamsConcatenation(chunk_files)
        except OSError as ex:
            raise StorageError("Failed to complete multipart upload for {}".format(self.key)) from ex
        self.transfer.store_file_object(
            self.key,
            stream,  # type: ignore[arg-type]
            metadata=metadata,
        )
        self._completed = True
        try:
            shutil.rmtree(self._upload_tmp_dir)
        except OSError as ex:
            self.log.exception("Could not clean up temporary directory %r", self._upload_tmp_dir)

    def abort(self) -> None:
        self._check_started()
        if self._aborted:
            return
        elif self._completed:
            raise StorageError("Upload {} for {} was already completed".format(self._upload_tmp_dir, self.key))
        try:
            shutil.rmtree(self._upload_tmp_dir)
            self._aborted = True
        except OSError as ex:
            raise StorageError("Failed to abort multipart upload for {}".format(self.key)) from ex
