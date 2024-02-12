# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from pytest import LogCaptureFixture
from rohmu.notifier.logger import LoggerNotifier

import logging


def test_logger_notifier_object_created(caplog: LogCaptureFixture) -> None:
    notifier = LoggerNotifier(logging.getLogger())
    key = "test_logger_notifier"
    size = 1

    with caplog.at_level(logging.DEBUG):
        assert len(caplog.messages) == 0
        notifier.object_created(key=key, size=size, metadata=None)
        assert len(caplog.messages) == 1


def test_logger_notifier_object_created_size_none(caplog: LogCaptureFixture) -> None:
    notifier = LoggerNotifier(logging.getLogger())
    key = "test_logger_notifier"
    size = None

    with caplog.at_level(logging.DEBUG):
        assert len(caplog.messages) == 0
        notifier.object_created(key=key, size=size, metadata=None)
        assert len(caplog.messages) == 1


def test_logger_notifier_object_deleted(caplog: LogCaptureFixture) -> None:
    notifier = LoggerNotifier(logging.getLogger())
    key = "test_logger_notifier"

    with caplog.at_level(logging.DEBUG):
        assert len(caplog.messages) == 0
        notifier.object_deleted(key=key)
        assert len(caplog.messages) == 1


def test_logger_notifier_tree_deleted(caplog: LogCaptureFixture) -> None:
    notifier = LoggerNotifier(logging.getLogger())
    key = "test_logger_notifier"

    with caplog.at_level(logging.DEBUG):
        assert len(caplog.messages) == 0
        notifier.tree_deleted(key=key)
        assert len(caplog.messages) == 1
