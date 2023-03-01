"""
rohmu

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""
from .common.models import StorageModel
from .errors import InvalidConfigurationError
from .notifier.interface import Notifier
from .object_storage.base import BaseTransfer
from typing import Any, Dict, Mapping, Type

IO_BLOCK_SIZE = 2**20  # 1 MiB
STORAGE_TYPE = "storage_type"
NOTIFIER_TYPE = "notifier_type"
Config = Mapping[str, Any]


def get_class_for_transfer(obj_store: Config) -> Type[BaseTransfer]:
    storage_type = obj_store[STORAGE_TYPE]
    if storage_type == "azure":
        from .object_storage.azure import AzureTransfer

        return AzureTransfer
    elif storage_type == "google":
        from .object_storage.google import GoogleTransfer

        return GoogleTransfer
    elif storage_type == "sftp":
        from .object_storage.sftp import SFTPTransfer

        return SFTPTransfer
    elif storage_type == "local":
        from .object_storage.local import LocalTransfer

        return LocalTransfer
    elif storage_type == "s3":
        from .object_storage.s3 import S3Transfer

        return S3Transfer
    elif storage_type == "swift":
        from .object_storage.swift import SwiftTransfer

        return SwiftTransfer

    raise InvalidConfigurationError("unsupported storage type {0!r}".format(storage_type))


def get_class_for_notifier(notifier_config: dict) -> Type[Notifier]:
    notifier_type = notifier_config[NOTIFIER_TYPE]
    if notifier_type == "http":
        from .notifier.http import BackgroundHTTPNotifier

        return BackgroundHTTPNotifier
    raise InvalidConfigurationError("unsupported storage type {0!r}".format(notifier_type))


def get_notifier(notifier_config: dict) -> Notifier:
    notificer_class = get_class_for_notifier(notifier_config)
    notifier_config = notifier_config.copy()
    notifier_config.pop(NOTIFIER_TYPE)
    return notificer_class(**notifier_config)


def get_transfer_model(storage_config: Config) -> Type[StorageModel]:
    storage_class = get_class_for_transfer(storage_config)
    storage_config = dict(storage_config)
    storage_config.pop(STORAGE_TYPE)
    notifier_config = storage_config.pop("notifier", None)
    notifier = None
    if notifier_config is not None:
        notifier = get_notifier(notifier_config)

    model = storage_class.config_model(**storage_config, notifier=notifier)
    return model


def get_transfer(storage_config: Config) -> BaseTransfer:
    storage_class = get_class_for_transfer(storage_config)
    model = get_transfer_model(storage_config)
    return storage_class.from_model(model)
