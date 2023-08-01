"""
rohmu - exception classes

Copyright (c) 2016 Ohmu Ltd
See LICENSE for details
"""


class Error(Exception):
    """Generic exception"""


class StorageError(Error):
    """Storage exception"""


class FileNotFoundFromStorageError(StorageError):
    """File not found from remote storage"""


class InvalidConfigurationError(Error):
    """Invalid configuration"""


class LocalFileIsRemoteFileError(StorageError):
    """File transfer operation source and destination point to the same file"""


class MissingLibraryError(Exception):
    """Missing dependency library"""


class MaybeRecoverableError(Error):
    """An error that may be recoverable"""


class UninitializedError(Error):
    """Error trying to access an uninitialized resource"""


class InvalidByteRangeError(Error):
    """Error specifying a content-range in a request"""


class InvalidTransferError(Error):
    """You tried to access a transfer object that you already returned to the pool"""


class ConcurrentUploadError(StorageError):
    """A generic error related to concurrent uploads"""
