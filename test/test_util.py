from __future__ import annotations

from collections.abc import Iterator
from io import BytesIO, UnsupportedOperation
from rohmu.util import (
    BinaryStreamsConcatenation,
    file_object_is_empty,
    get_total_size_from_content_range,
    parallel_map,
    ProgressStream,
)

import pytest
import threading
import time


def test_parallel_map_preserves_order() -> None:
    def slow_square(value: int) -> int:
        time.sleep(0.001 * (10 - value))
        return value * value

    assert list(parallel_map(slow_square, range(10), max_workers=4)) == [value * value for value in range(10)]


def test_parallel_map_runs_concurrently() -> None:
    barrier = threading.Barrier(3, timeout=5)
    # Raises BrokenBarrierError if the calls run sequentially
    list(parallel_map(lambda _: barrier.wait(), range(3), max_workers=3))


def test_parallel_map_reads_input_lazily() -> None:
    consumed = []

    def source() -> Iterator[int]:
        for value in range(100):
            consumed.append(value)
            yield value

    results = parallel_map(lambda value: value, source(), max_workers=2)
    assert next(results) == 0
    results.close()
    assert len(consumed) == 4


def test_parallel_map_raises_in_order() -> None:
    def fail_on_three(value: int) -> int:
        if value == 3:
            raise ValueError(value)
        return value

    results = parallel_map(fail_on_three, range(10), max_workers=2)
    assert [next(results) for _ in range(3)] == [0, 1, 2]
    with pytest.raises(ValueError):
        next(results)


@pytest.mark.parametrize(
    "content_range,result",
    [
        ("0-100/100", 100),
        ("50-55/100", 100),
        ("0-100/*", None),
        ("0-100/1", 1),
    ],
)
def test_get_total_size_from_content_range(content_range: str, result: int | None) -> None:
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


def test_file_object_is_empty() -> None:
    assert not file_object_is_empty(BytesIO(b"Hello, World!\nSecond line\nThis is a longer third line\n"))
    assert file_object_is_empty(BytesIO(b""))
