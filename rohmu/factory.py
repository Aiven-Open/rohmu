# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/

from .common.models import StorageDriver, StorageModel
from .errors import InvalidConfigurationError
from .notifier.interface import Notifier
from rohmu.object_storage.base import BaseTransfer
from rohmu.object_storage.config import StorageModelT
from typing import Any, Dict, Optional, Type

STORAGE_TYPE = "storage_type"
NOTIFIER_TYPE = "notifier_type"
Config = Dict[str, Any]


def get_class_for_transfer(obj_store: Config) -> Type[BaseTransfer[Any]]:
    return get_class_for_storage_driver(StorageDriver(obj_store[STORAGE_TYPE]))


def get_class_for_storage_driver(storage_driver: StorageDriver) -> Type[BaseTransfer[Any]]:
    if storage_driver == StorageDriver.azure:
        from rohmu.object_storage.azure import AzureTransfer

        return AzureTransfer
    elif storage_driver == StorageDriver.google:
        from rohmu.object_storage.google import GoogleTransfer

        return GoogleTransfer
    elif storage_driver == StorageDriver.sftp:
        from rohmu.object_storage.sftp import SFTPTransfer

        return SFTPTransfer
    elif storage_driver == StorageDriver.local:
        from rohmu.object_storage.local import LocalTransfer

        return LocalTransfer
    elif storage_driver == StorageDriver.s3:
        from rohmu.object_storage.s3 import S3Transfer

        return S3Transfer
    elif storage_driver == StorageDriver.swift:
        from rohmu.object_storage.swift import SwiftTransfer

        return SwiftTransfer

    raise InvalidConfigurationError(f"unsupported storage type {storage_driver!r}")


def get_class_for_notifier(notifier_config: Config) -> Type[Notifier]:
    notifier_type = notifier_config[NOTIFIER_TYPE]
    if notifier_type == "http":
        from .notifier.http import BackgroundHTTPNotifier

        return BackgroundHTTPNotifier
    raise InvalidConfigurationError(f"unsupported storage type {repr(notifier_type)}")


def get_notifier(notifier_config: Config) -> Notifier:
    notificer_class = get_class_for_notifier(notifier_config)
    notifier_config = notifier_config.copy()
    notifier_config.pop(NOTIFIER_TYPE)
    return notificer_class(**notifier_config)


def get_transfer_model(storage_config: Config) -> StorageModel:
    storage_class = get_class_for_transfer(storage_config)
    return storage_class.config_model(**storage_config)


def get_transfer(storage_config: Config) -> BaseTransfer[Any]:
    storage_config = storage_config.copy()
    noitifier_config = storage_config.pop("notifier")
    notifier = get_notifier(noitifier_config)
    model = get_transfer_model(storage_config)
    return get_transfer_from_model(model, notifier)


def get_transfer_from_model(model: StorageModelT, notifier: Optional[Notifier] = None) -> BaseTransfer[StorageModelT]:
    storage_class = get_class_for_storage_driver(model.storage_type)
    return storage_class.from_model(model, notifier)
