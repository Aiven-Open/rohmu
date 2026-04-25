# Copyright (c) 2016 Ohmu Ltd
# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""Rohmu"""

from .common.constants import IO_BLOCK_SIZE
from .common.models import StorageModel
from .errors import InvalidConfigurationError
from .factory import (
    Config,
    get_class_for_notifier,
    get_class_for_storage_driver,
    get_class_for_transfer,
    get_notifier,
    get_transfer,
    get_transfer_from_model,
    get_transfer_model,
    NOTIFIER_TYPE,
    STORAGE_TYPE,
)
from .notifier.interface import Notifier
from rohmu.object_storage.azure import ENDPOINT_SUFFIXES
from rohmu.object_storage.base import BaseTransfer
from rohmu.object_storage.config import (
    AzureObjectStorageConfig,
    GoogleObjectStorageConfig,
    LocalObjectStorageConfig,
    ProxyInfo,
    S3AddressingStyle,
    S3ObjectStorageConfig,
    SFTPObjectStorageConfig,
    StorageDriver,
    SwiftObjectStorageConfig,
)

__all__ = [
    "AzureObjectStorageConfig",
    "BaseTransfer",
    "Config",
    "ENDPOINT_SUFFIXES",
    "get_class_for_notifier",
    "get_class_for_storage_driver",
    "get_class_for_transfer",
    "get_notifier",
    "get_transfer_from_model",
    "get_transfer_model",
    "get_transfer",
    "GoogleObjectStorageConfig",
    "InvalidConfigurationError",
    "IO_BLOCK_SIZE",
    "LocalObjectStorageConfig",
    "NOTIFIER_TYPE",
    "Notifier",
    "ProxyInfo",
    "S3AddressingStyle",
    "S3ObjectStorageConfig",
    "SFTPObjectStorageConfig",
    "STORAGE_TYPE",
    "StorageDriver",
    "StorageModel",
    "SwiftObjectStorageConfig",
]
