# Copyright (c) 2016 Ohmu Ltd
# See LICENSE for details
"""Rohmu - exception classes"""

from typing import Optional


class Error(Exception):
    """Generic exception"""


class StorageError(Error):
    """Storage exception"""


class FileNotFoundFromStorageError(StorageError):
    """File not found from remote storage"""


class InvalidConfigurationError(Error):
    """Invalid configuration"""


class TransferObjectStoreInitializationError(Error):
    """Raised when a transient network or permission issue does not allow us to validate access to the object store"""


class TransferObjectStorePermissionError(TransferObjectStoreInitializationError):
    """Raised when a permission issue does not allow us to validate access to the object store"""


class TransferObjectStoreMissingError(TransferObjectStoreInitializationError):
    """Raised when we know for sure the bucket is missing"""


class LocalFileIsRemoteFileError(StorageError):
    """File transfer operation source and destination point to the same file"""


class MissingLibraryError(Exception):
    """Missing dependency library"""


class MaybeRecoverableError(Error):
    """An error that may be recoverable"""

    def __init__(self, message: str, position: Optional[int] = None) -> None:
        self.position = position
        super().__init__(message)


class UninitializedError(Error):
    """Error trying to access an uninitialized resource"""


class InvalidByteRangeError(Error):
    """Error specifying a content-range in a request"""


class InvalidTransferError(Error):
    """You tried to access a transfer object that you already returned to the pool"""


class ConcurrentUploadError(StorageError):
    """A generic error related to concurrent uploads"""
