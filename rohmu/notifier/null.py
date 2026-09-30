# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/

from __future__ import annotations

from .interface import Notifier


class NullNotifier(Notifier):
    """Empty implementation.

    Used by default if configuration is missing to avoid None checks
    """

    def object_created(self, key: str, size: int | None, metadata: dict[str, str] | None) -> None:
        pass

    def object_deleted(self, key: str) -> None:
        pass

    def tree_deleted(self, key: str) -> None:
        pass
