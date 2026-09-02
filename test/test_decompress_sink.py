from __future__ import annotations

from rohmu.compressor import (
    CompressionFile,
    DecompressSink,
    OUTPUT_CHUNK_SIZE,
    SNAPPY_INPUT_SLICE_SIZE,
)
from rohmu.encryptor import SymmetricDecryptSink, SymmetricEncryptor
from rohmu.typing import BinaryData
from typing import Iterable

import hashlib
import io
import itertools
import pytest
import random


class MeasuringSink:
    def __init__(self) -> None:
        self.digest = hashlib.sha256()
        self.max_write_size = 0
        self.total_written = 0
        self.write_count = 0

    def write(self, data: BinaryData) -> int:
        view = memoryview(data)
        self.digest.update(view)
        self.max_write_size = max(self.max_write_size, len(view))
        self.total_written += len(view)
        self.write_count += 1
        return len(view)


class ShortWriteSink(MeasuringSink):
    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit

    def write(self, data: BinaryData) -> int:
        view = memoryview(data)
        accepted = min(len(view), self.limit)
        accepted_data = view[:accepted]
        self.digest.update(accepted_data)
        self.max_write_size = max(self.max_write_size, accepted)
        self.total_written += accepted
        self.write_count += 1
        return accepted


def compress(algorithm: str, data: bytes) -> bytes:
    target = io.BytesIO()
    compressor = CompressionFile(target, algorithm)
    compressor.write(data)
    compressor.close()
    return target.getvalue()


def boundaries(data: bytes, sizes: Iterable[int]) -> Iterable[memoryview]:
    view = memoryview(data)
    offset = 0
    for size in itertools.cycle(sizes):
        if size <= 0:
            raise ValueError("boundary sizes must be positive")
        if offset >= len(view):
            return
        end = min(offset + size, len(view))
        yield view[offset:end]
        offset = end


def seeded_boundaries(data: bytes) -> Iterable[memoryview]:
    randomizer = random.Random(0)
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        size = randomizer.randint(1, 128 * 1024)
        end = min(offset + size, len(view))
        yield view[offset:end]
        offset = end


@pytest.fixture(scope="module")
def source_data() -> bytes:
    return (b"rohmu decompression sink\n" * 65536) + bytes(range(256)) * 1024


@pytest.mark.parametrize("algorithm", ("snappy", "zstd", "lzma"))
@pytest.mark.parametrize("input_sizes", ((1,), (7,), (64 * 1024,), (1024 * 1024,)))
def test_decompress_sink_preserves_data_across_input_boundaries(
    algorithm: str, input_sizes: tuple[int, ...], source_data: bytes
) -> None:
    # Decompressed output must match the original when compressed input arrives in fixed-size chunks.
    # Covers tiny (1 byte), small, and large (up to 1 MiB) write boundaries for each algorithm.
    compressed = compress(algorithm, source_data)
    sink = MeasuringSink()
    decompressor = DecompressSink(sink, algorithm)

    for chunk in boundaries(compressed, input_sizes):
        assert decompressor.write(chunk) == len(chunk)

    assert sink.total_written == len(source_data)
    assert sink.digest.digest() == hashlib.sha256(source_data).digest()


@pytest.mark.parametrize("algorithm", ("snappy", "zstd", "lzma"))
def test_decompress_sink_preserves_data_across_seeded_boundaries(algorithm: str, source_data: bytes) -> None:
    # Same correctness check as fixed boundaries, but with pseudo-random chunk sizes (seeded).
    compressed = compress(algorithm, source_data)
    sink = MeasuringSink()
    decompressor = DecompressSink(sink, algorithm)

    for chunk in seeded_boundaries(compressed):
        assert decompressor.write(chunk) == len(chunk)

    assert sink.total_written == len(source_data)
    assert sink.digest.digest() == hashlib.sha256(source_data).digest()


@pytest.mark.parametrize("algorithm", ("snappy", "zstd", "lzma"))
def test_decompress_sink_retries_short_downstream_writes(algorithm: str, source_data: bytes) -> None:
    # Downstream sink accepts only 37 KiB per write; Sink must retry until all decompressed bytes land.
    compressed = compress(algorithm, source_data)
    sink = ShortWriteSink(37 * 1024)

    assert DecompressSink(sink, algorithm).write(compressed) == len(compressed)
    assert sink.total_written == len(source_data)
    assert sink.digest.digest() == hashlib.sha256(source_data).digest()


@pytest.mark.parametrize("algorithm", ("zstd", "lzma"))
def test_decompress_sink_bounds_output_writes(algorithm: str) -> None:
    # Large input must be decompressed in multiple downstream writes, each no larger than OUTPUT_CHUNK_SIZE.
    source = b"a" * (OUTPUT_CHUNK_SIZE * 4)
    compressed = compress(algorithm, source)
    sink = MeasuringSink()

    assert DecompressSink(sink, algorithm).write(compressed) == len(compressed)
    assert sink.total_written == len(source)
    assert sink.write_count > 1
    assert sink.max_write_size <= OUTPUT_CHUNK_SIZE


def test_snappy_decompress_sink_bounds_decoder_input() -> None:
    # Snappy slices compressed input at SNAPPY_INPUT_SLICE_SIZE; each slice's decompressed output stays bounded.
    source = bytes(range(256)) * (32 * 1024)
    compressed = compress("snappy", source)
    sink = MeasuringSink()

    assert len(compressed) > SNAPPY_INPUT_SLICE_SIZE
    assert DecompressSink(sink, "snappy").write(memoryview(compressed)) == len(compressed)
    assert sink.total_written == len(source)
    assert sink.max_write_size <= SNAPPY_INPUT_SLICE_SIZE * 22


@pytest.mark.parametrize(
    ("algorithm", "expected_output"),
    (("snappy", 327680), ("zstd", 262144), ("lzma", 340000)),
)
def test_decompress_sink_preserves_truncated_stream_behavior(algorithm: str, expected_output: int) -> None:
    # Missing the final compressed byte emits partial output without raising (no explicit end-of-stream flush).
    source = b"rohmu-truncation-" * 20000
    compressed = compress(algorithm, source)
    sink = MeasuringSink()

    assert DecompressSink(sink, algorithm).write(compressed[:-1]) == len(compressed) - 1
    assert sink.total_written == expected_output


def test_decrypt_sink_then_decompress_sink_preserves_data(source_data: bytes) -> None:
    # Pipeline integration: encrypted chunks → decrypt → decompress → verify full original via SHA-256.
    compressed = compress("snappy", source_data)
    key = bytes(range(32))
    encryptor = SymmetricEncryptor(key)
    encrypted = encryptor.update(compressed) + encryptor.finalize()
    sink = MeasuringSink()
    decrypt_sink = SymmetricDecryptSink(DecompressSink(sink, "snappy"), len(encrypted), key)

    for chunk in seeded_boundaries(encrypted):
        assert decrypt_sink.write(chunk) == len(chunk)

    assert sink.total_written == len(source_data)
    assert sink.digest.digest() == hashlib.sha256(source_data).digest()
