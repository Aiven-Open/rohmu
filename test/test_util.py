from __future__ import annotations

from io import BytesIO, UnsupportedOperation
from rohmu.util import BinaryStreamsConcatenation, get_total_size_from_content_range, ProgressStream
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


def test_progress_stream() -> None:
    stream = BytesIO(b"Hello, World!\nSecond line\nThis is a longer third line\n")
    progress_stream = ProgressStream(stream)
    assert progress_stream.readable()
    assert not progress_stream.writable()
    # stream is seekable if underlying stream is
    assert progress_stream.seekable()

    assert progress_stream.read(14) == b"Hello, World!\n"
    assert progress_stream.bytes_read == 14
    assert progress_stream.readlines() == [b"Second line\n", b"This is a longer third line\n"]
    assert progress_stream.bytes_read == 54

    with pytest.raises(UnsupportedOperation):
        progress_stream.truncate(0)
    with pytest.raises(UnsupportedOperation):
        progress_stream.write(b"Something")
    with pytest.raises(UnsupportedOperation):
        progress_stream.writelines([b"Something"])
    with pytest.raises(UnsupportedOperation):
        progress_stream.fileno()

    # seeking the stream, in any position, resets the bytes_read counter
    progress_stream.seek(10)
    assert progress_stream.bytes_read == 0
    # the seek works as expected on the stream
    assert progress_stream.read(10) == b"ld!\nSecond"
    assert progress_stream.bytes_read == 10

    assert not progress_stream.closed
    with progress_stream:
        # check that __exit__ closes the file
        pass
    assert progress_stream.closed
