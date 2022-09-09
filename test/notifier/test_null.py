"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from rohmu.notifier.null import NullNotifier


def test_null_notifier() -> None:
    notifier = NullNotifier()
    key = "test_null_notifier"
    size = 2

    notifier.object_created(key=key, size=size)
    notifier.object_deleted(key=key)
    notifier.tree_deleted(key=key)
