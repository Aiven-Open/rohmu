"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from rohmu.notifier.interface import Notifier
from typing import Any, Optional


class _TestNotifier(Notifier):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.object_created_called = 0
        self.object_deleted_called = 0
        self.tree_deleted_called = 0

    def object_created(self, key: str, size: Optional[int], metadata: Optional[dict[str, str]]) -> None:
        self.object_created_called += 1

    def object_deleted(self, key: str) -> None:
        self.object_deleted_called += 1

    def tree_deleted(self, key: str) -> None:
        self.tree_deleted_called += 1


def test_interface() -> None:
    test = _TestNotifier()
    key = "test_interface"

    assert test.object_created_called == 0
    test.object_created(key=key, size=0, metadata=None)
    assert test.object_created_called == 1

    assert test.object_created_called == 1
    test.object_copied(key=key, size=0, metadata=None)
    assert test.object_created_called == 2, "default implementation calls object_created"

    assert test.object_deleted_called == 0
    test.object_deleted(key=key)
    assert test.object_deleted_called == 1

    assert test.tree_deleted_called == 0
    test.tree_deleted(key=key)
    assert test.tree_deleted_called == 1

    test.close()
