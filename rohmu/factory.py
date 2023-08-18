# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/

from .common.models import StorageModel
from .errors import InvalidConfigurationError
from .notifier.interface import Notifier
from .object_storage.base import BaseTransfer
from typing import Any, cast, Dict, Type

STORAGE_TYPE = "storage_type"
NOTIFIER_TYPE = "notifier_type"
Config = Dict[str, Any]


def get_class_for_transfer(obj_store: Config) -> Type[BaseTransfer[StorageModel]]:
    storage_type = obj_store[STORAGE_TYPE]
    if storage_type == "azure":
        from .object_storage.azure import AzureTransfer

        return cast(Type[BaseTransfer[StorageModel]], AzureTransfer)
    elif storage_type == "google":
        from .object_storage.google import GoogleTransfer

        return cast(Type[BaseTransfer[StorageModel]], GoogleTransfer)
    elif storage_type == "sftp":
        from .object_storage.sftp import SFTPTransfer

        return cast(Type[BaseTransfer[StorageModel]], SFTPTransfer)
    elif storage_type == "local":
        from .object_storage.local import LocalTransfer

        return cast(Type[BaseTransfer[StorageModel]], LocalTransfer)
    elif storage_type == "s3":
        from .object_storage.s3 import S3Transfer

        return cast(Type[BaseTransfer[StorageModel]], S3Transfer)
    elif storage_type == "swift":
        from .object_storage.swift import SwiftTransfer

        return cast(Type[BaseTransfer[StorageModel]], SwiftTransfer)

    raise InvalidConfigurationError("unsupported storage type {0!r}".format(storage_type))


def get_class_for_notifier(notifier_config: Config) -> Type[Notifier]:
    notifier_type = notifier_config[NOTIFIER_TYPE]
    if notifier_type == "http":
        from .notifier.http import BackgroundHTTPNotifier

        return BackgroundHTTPNotifier
    raise InvalidConfigurationError("unsupported storage type {0!r}".format(notifier_type))


def get_notifier(notifier_config: Config) -> Notifier:
    notificer_class = get_class_for_notifier(notifier_config)
    notifier_config = notifier_config.copy()
    notifier_config.pop(NOTIFIER_TYPE)
    return notificer_class(**notifier_config)


def get_transfer_model(storage_config: Config) -> StorageModel:
    storage_class = get_class_for_transfer(storage_config)
    storage_config = dict(storage_config)
    storage_config.pop(STORAGE_TYPE)
    notifier_config = storage_config.pop("notifier", None)
    notifier = None
    if notifier_config is not None:
        notifier = get_notifier(notifier_config)

    model = storage_class.config_model(**storage_config, notifier=notifier)
    return model


def get_transfer(storage_config: Config) -> BaseTransfer[StorageModel]:
    storage_class = get_class_for_transfer(storage_config)
    model = get_transfer_model(storage_config)
    return storage_class.from_model(model)
