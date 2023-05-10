from __future__ import annotations

from rohmu.inotify import parse_inotify_buffer

import pytest
import struct


def _make_buffer(wd: int, mask: int, cookie: int, name: bytes) -> bytes:
    return struct.pack("iIII", wd, mask, cookie, len(name)) + name


@pytest.mark.parametrize(
    "buffer,result",
    [
        (b"", []),
        (_make_buffer(1, 2, 3, b"Hello, World!"), [(1, 2, 3, b"Hello, World!")]),
        (
            _make_buffer(11, 12, 13, b"Hello, ") + _make_buffer(101, 102, 103, b"World!"),
            [(11, 12, 13, b"Hello, "), (101, 102, 103, b"World!")],
        ),
    ],
)
def test_parse_inotify_buffer(buffer: bytes, result: list[tuple[int, int, int, bytes]]) -> None:
    got = list(parse_inotify_buffer(buffer))
    assert got == result
