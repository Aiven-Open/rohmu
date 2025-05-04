# Copyright (c) 2016 Ohmu Ltd
# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""Rohmu - sftp object store interface"""

from io import BytesIO
from rohmu.common.statsd import StatsdConfig
from rohmu.errors import Error, FileNotFoundFromStorageError, InvalidConfigurationError
from rohmu.notifier.interface import Notifier
from rohmu.object_storage.base import (
    BaseTransfer,
    IncrementalProgressCallbackType,
    IterKeyItem,
    KEY_TYPE_OBJECT,
    KEY_TYPE_PREFIX,
    ProgressProportionCallbackType,
)
from rohmu.object_storage.config import SFTPObjectStorageConfig as Config
from rohmu.typing import Metadata
from stat import S_ISDIR
from typing import Any, BinaryIO, Callable, cast, Iterator, Optional, Tuple, TypeVar

import datetime
import functools
import json
import logging
import os
import paramiko
import warnings

T = TypeVar("T")

def check_socket_closed(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except OSError as ex:
            if ex.args == ('Socket is closed',):
                self.invalidate_client()
            raise
    return wrapper


class SFTPTransfer(BaseTransfer[Config]):
    config_model = Config

    def __init__(
        self,
        server: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        prefix: Optional[str] = None,
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
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key

        if not password and not private_key:
            raise InvalidConfigurationError("Password or private key required")

        logging.getLogger("paramiko").setLevel(logging.WARNING)

        # https://github.com/paramiko/paramiko/issues/1386#issuecomment-470847772
        warnings.filterwarnings(action="ignore", module=".*paramiko.*")

        self.client: Optional[paramiko.SFTPClient] = None
        self.get_client()

        self.log.debug("SFTPTransfer initialized")

    def get_client(self) -> paramiko.SFTPClient:
        if self.client is None:
            transport = paramiko.Transport((self.server, self.port))

            if self.private_key:
                pkey = paramiko.RSAKey.from_private_key_file(self.private_key)
                transport.connect(username=self.username, pkey=pkey)
            else:  # password must be defined due to previous check above
                transport.connect(username=self.username, password=self.password)

            self.client = cast(paramiko.SFTPClient, paramiko.SFTPClient.from_transport(transport))

        return self.client

    def invalidate_client(self):
        self.client = None

    def _retry_idempotent_op(self, operation: Callable[[], T]) -> T:
        """
        Retries an operation once (after reconnecting the client) if it fails with a socket closed error.
        This should only be used to wrap idempotent operations that can be repeated.
        """
        try:
            return operation()
        except OSError as ex:
            if ex.args == ('Socket is closed',):
                self.invalidate_client()
                return operation()
            raise

    def _verify_object_storage_unwrapped(self) -> None:
        """No-op for now. Eventually, the SFTP connection could be tested here instead of in the constructor."""

    def verify_object_storage(self) -> None:
        """No-op for now. Eventually, the SFTP connection could be tested here instead of in the constructor."""

    def _create_object_store_if_needed_unwrapped(self) -> None:
        """No-op as it's not applicable to SFTP transfers"""

    def create_object_store_if_needed(self) -> None:
        """No-op as it's not applicable to SFTP transfers"""

    @check_socket_closed
    def get_contents_to_fileobj(
        self,
        key: str,
        fileobj_to_store_to: BinaryIO,
        *,
        byte_range: Optional[Tuple[int, int]] = None,
        progress_callback: ProgressProportionCallbackType = None,
    ) -> Metadata:
        if byte_range:
            raise NotImplementedError("byte range fetching not supported")
        self._get_contents_to_fileobj(key, fileobj_to_store_to, progress_callback)
        return self.get_metadata_for_key(key)

    def _get_contents_to_fileobj(
        self, key: str, fileobj_to_store_to: BinaryIO, progress_callback: ProgressProportionCallbackType = None
    ) -> None:
        target_path = self.format_key_for_backend(key.strip("/"))
        self.log.debug("Get file content: %r", target_path)

        try:
            # the paramiko progress callback has the same interface as pghoard for downloads
            self.get_client().getfo(remotepath=target_path, fl=fileobj_to_store_to, callback=progress_callback)
        except FileNotFoundError as ex:
            raise FileNotFoundFromStorageError(key) from ex

    @check_socket_closed
    def get_file_size(self, key: str) -> int:
        target_path = self.format_key_for_backend(key.strip("/"))
        try:
            return self._retry_idempotent_op(lambda: self.get_client().stat(target_path).st_size)  # type: ignore
        except FileNotFoundError as ex:
            raise FileNotFoundFromStorageError(key) from ex

    @check_socket_closed
    def get_metadata_for_key(self, key: str) -> Metadata:
        bio = BytesIO()
        self._retry_idempotent_op(lambda: self._get_contents_to_fileobj(key + ".metadata", bio))
        return json.loads(bio.getvalue().decode())

    @staticmethod
    def _skip_file_name(file_name: str) -> bool:
        return file_name.startswith(".") or file_name.endswith(".metadata") or ".metadata_tmp" in file_name

    def iter_key(
        self, key: str, *, with_metadata: bool = True, deep: bool = False, include_key: bool = False
    ) -> Iterator[IterKeyItem]:
        target_path = self.format_key_for_backend(key.strip("/"))
        self.log.debug("Listing path: %r", target_path)

        try:
            attrs = self._retry_idempotent_op(lambda: self.get_client().listdir_attr(target_path))
        except FileNotFoundError:  # if not a directory will throw exception
            if include_key:
                file_name = os.path.basename(target_path)
                if self._skip_file_name(file_name):
                    return

                try:
                    attr = self._retry_idempotent_op(lambda: self.get_client().stat(target_path))

                    if with_metadata:
                        metadata = self.get_metadata_for_key(key)
                    else:
                        metadata = None

                    last_modified = datetime.datetime.fromtimestamp(
                        attr.st_mtime,  # type: ignore[arg-type]
                        tz=datetime.timezone.utc,
                    )
                    yield IterKeyItem(
                        type=KEY_TYPE_OBJECT,
                        value={
                            "name": key,
                            "size": attr.st_size,
                            "last_modified": last_modified,
                            "metadata": metadata,
                        },
                    )
                    return
                except FileNotFoundError:
                    return
            else:
                return

        files = {attr.filename for attr in attrs}

        for attr in attrs:
            if self._skip_file_name(attr.filename):
                continue

            file_key = os.path.join(key.strip("/"), attr.filename)
            if S_ISDIR(attr.st_mode):  # type: ignore[arg-type]
                if deep:
                    yield from self.iter_key(file_key, with_metadata=with_metadata, deep=True)
                else:
                    yield IterKeyItem(type=KEY_TYPE_PREFIX, value=file_key)
            else:  # noqa: PLR5501
                # Don't return files if metadata file is not present; files are written in two phases and
                # should be considered available only after also metadata has been written
                if attr.filename + ".metadata" in files:
                    if with_metadata:
                        metadata = self.get_metadata_for_key(file_key)
                    else:
                        metadata = None

                    last_modified = datetime.datetime.fromtimestamp(
                        attr.st_mtime,  # type: ignore[arg-type]
                        tz=datetime.timezone.utc,
                    )
                    yield IterKeyItem(
                        type=KEY_TYPE_OBJECT,
                        value={
                            "name": file_key,
                            "size": attr.st_size,
                            "last_modified": last_modified,
                            "metadata": metadata,
                        },
                    )

    # can't support remote copy, only remote rename
    def copy_file(
        self, *, source_key: str, destination_key: str, metadata: Optional[Metadata] = None, **_kwargs: Any
    ) -> None:
        raise NotImplementedError

    @check_socket_closed
    def delete_key(self, key: str, preserve_trailing_slash: bool = False) -> None:
        if preserve_trailing_slash:
            raise Error("SftpTransfer does not support preserving trailing slashes")
        target_path = self.format_key_for_backend(key.strip("/"))
        self.log.info("Removing path: %r", target_path)

        try:
            self._retry_idempotent_op(lambda: self.get_client().remove(target_path + ".metadata"))
            self._retry_idempotent_op(lambda: self.get_client().remove(target_path))
            self.notifier.object_deleted(key=key)
        except FileNotFoundError as ex:
            raise FileNotFoundFromStorageError(key) from ex

    @check_socket_closed
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
        bytes_written = self._put_object(
            key, fd, metadata=metadata, upload_progress_fn=self._proportional_to_incremental_progress(upload_progress_fn)
        )
        self.notifier.object_created(key=key, size=bytes_written, metadata=self.sanitize_metadata(metadata))
        if upload_progress_fn:
            upload_progress_fn(bytes_written)

    def _put_object(
        self,
        key: str,
        fd: BinaryIO,
        *,
        metadata: Optional[Metadata] = None,
        upload_progress_fn: ProgressProportionCallbackType = None,
    ) -> int:
        target_path = self.format_key_for_backend(key.strip("/"))
        total_bytes_written = 0

        self.log.debug("Store path: %r", target_path)

        def wrapper_upload_progress_fn(bytes_written: int, total_bytes: int) -> None:
            nonlocal total_bytes_written
            total_bytes_written = bytes_written
            if upload_progress_fn:
                upload_progress_fn(bytes_written, total_bytes)

        self._mkdir_p(os.path.dirname(target_path))
        self.get_client().putfo(fl=fd, remotepath=target_path, callback=wrapper_upload_progress_fn)

        # metadata is saved last, because we ignore data files until the metadata file exists
        # see iter_key above
        self._save_metadata(target_path, metadata)
        return total_bytes_written

    def _save_metadata(self, target_path: str, metadata: Optional[Metadata]) -> None:
        metadata_path = target_path + ".metadata"
        self.log.debug("Save metadata: %r", metadata_path)

        sanitised = self.sanitize_metadata(metadata)
        bio = BytesIO(json.dumps(sanitised).encode())
        self.get_client().putfo(fl=bio, remotepath=metadata_path)

    # https://stackoverflow.com/questions/14819681/upload-files-using-sftp-in-python-but-create-directories-if-path-doesnt-exist
    def _mkdir_p(self, remote: str) -> None:
        dirs_ = []
        dir_ = remote
        while len(dir_) > 1:
            dirs_.append(dir_)
            dir_, _ = os.path.split(dir_)

        if len(dir_) == 1 and not dir_.startswith("/"):
            dirs_.append(dir_)  # For a remote path like y/x.txt

        while len(dirs_):
            dir_ = dirs_.pop()
            try:
                self.get_client().stat(dir_)
            except OSError:
                self.get_client().mkdir(dir_)
