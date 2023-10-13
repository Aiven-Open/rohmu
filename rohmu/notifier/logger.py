# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/

from __future__ import annotations

from .interface import Notifier
from logging import Logger
from typing import Optional


class LoggerNotifier(Notifier):
    def __init__(self, log: Logger) -> None:
        self._log = log

    def object_created(self, key: str, size: Optional[int], metadata: Optional[dict[str, str]]) -> None:
        self._log.info("Object created key %r size %r", key, size)

    def object_deleted(self, key: str) -> None:
        self._log.info("Object deleted key %r", key)

    def tree_deleted(self, key: str) -> None:
        self._log.info("Tree deleted key %r", key)
