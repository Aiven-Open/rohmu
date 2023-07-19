from __future__ import annotations

from io import BytesIO
from rohmu.util import BinaryStreamsConcatenation, get_total_size_from_content_range
from typing import Optional

import pytest


@pytest.mark.parametrize(
    "content_range,result",
    [
        ("0-100/100", 100),
        ("50-55/100", 100),
        ("0-100/*", None),
        ("0-100/1", 1),
    ],
)
def test_get_total_size_from_content_range(content_range: str, result: Optional[int]) -> None:
    assert get_total_size_from_content_range(content_range) == result


@pytest.mark.parametrize(
    "input_file_contents,chunk_size,expected_outputs",
    [
        ([b"Hello, World!"], 3, [b"Hel", b"lo,", b" Wo", b"rld", b"!"]),
        ([b"Hello", b", ", b"World", b"!"], 3, [b"Hel", b"lo,", b" Wo", b"rld", b"!"]),
        ([b"Hello", b", ", b"World", b"!"], -1, [b"Hello, World!"]),
        ([b"a" * 256 * 1024, b"b" * 128 * 1024], 1024, [b"a" * 1024] * 256 + [b"b" * 1024] * 128),
        ([b""], 1, []),
        ([b""] * 10, 1, []),
        ([b""] * 10, -1, []),
    ],
)
def test_binary_stream_concatenation(
    input_file_contents: list[bytes], chunk_size: int, expected_outputs: list[bytes]
) -> None:
    inputs = [BytesIO(content) for content in input_file_contents]
    concatenation = BinaryStreamsConcatenation(inputs)
    outputs = []
    for output_chunk in iter(lambda: concatenation.read(chunk_size), b""):
        outputs.append(output_chunk)
    assert outputs == expected_outputs
