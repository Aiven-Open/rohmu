# Copyright (c) 2016 Ohmu Ltd
# See LICENSE for details
"""Rohmu - compressor interface"""

from .errors import InvalidConfigurationError
from .filewrap import Sink, Stream
from .snappyfile import SnappyFile
from .typing import BinaryData, Compressor, FileLike, HasRead, HasWrite, SinkDecompressor
from .zstdfile import open as zstd_open
from typing import cast, IO

import io
import lzma

try:
    import snappy
except ImportError:
    snappy = None  # type: ignore

try:
    import zstandard as zstd
except ImportError:
    zstd = None  # type: ignore


OUTPUT_CHUNK_SIZE = 128 * 1024
SNAPPY_INPUT_SLICE_SIZE = 256 * 1024


def CompressionFile(dst_fp: FileLike, algorithm: str, level: int = 0, threads: int = 0) -> FileLike:
    """This looks like a class to users, but is actually a function that instantiates a class based on algorithm."""
    if algorithm == "lzma":
        return lzma.open(cast(IO[bytes], dst_fp), "w", preset=level)

    if algorithm == "snappy":
        return SnappyFile(dst_fp, "wb")

    if algorithm == "zstd":
        return zstd_open(dst_fp, "wb", level=level, threads=threads)

    if algorithm:
        raise InvalidConfigurationError(f"invalid compression algorithm: {repr(algorithm)}")

    return dst_fp


class CompressionStream(Stream):
    """Non-seekable stream of data that adds compression on top of given source stream"""

    def __init__(self, src_fp: HasRead, algorithm: str, level: int = 0) -> None:
        super().__init__(src_fp, minimum_read_size=32 * 1024)
        self._compressor: Compressor
        if algorithm == "lzma":
            self._compressor = lzma.LZMACompressor(lzma.FORMAT_XZ, -1, level, None)
        elif algorithm == "snappy":
            self._compressor = snappy.StreamCompressor()
        elif algorithm == "zstd":
            self._compressor = zstd.ZstdCompressor(level=level).compressobj()
        else:
            raise InvalidConfigurationError(f"invalid compression algorithm: {repr(algorithm)}")

    def _process_chunk(self, data: bytes) -> bytes:
        return self._compressor.compress(data)

    def _finalize(self) -> bytes:
        return self._compressor.flush()


def DecompressionFile(src_fp: FileLike, algorithm: str) -> FileLike:
    """This looks like a class to users, but is actually a function that instantiates a class based on algorithm."""
    if algorithm == "lzma":
        return lzma.open(cast(IO[bytes], src_fp), "r")

    if algorithm == "snappy":
        return SnappyFile(src_fp, "rb")

    if algorithm == "zstd":
        return zstd_open(src_fp, "rb")

    if algorithm:
        raise InvalidConfigurationError(f"invalid compression algorithm: {repr(algorithm)}")

    return src_fp


class SnappySinkDecompressor:
    def __init__(self, next_sink: HasWrite) -> None:
        self._sink = Sink(next_sink)
        self._decompressor = snappy.StreamDecompressor()

    def decompress(self, data: memoryview) -> None:
        for offset in range(0, len(data), SNAPPY_INPUT_SLICE_SIZE):
            output = self._decompressor.decompress(bytes(data[offset : offset + SNAPPY_INPUT_SLICE_SIZE]))
            if output:
                self._sink.write(output)


class LzmaSinkDecompressor:
    def __init__(self, next_sink: HasWrite) -> None:
        self._sink = Sink(next_sink)
        self._decompressor = lzma.LZMADecompressor()

    def decompress(self, data: memoryview) -> None:
        output = self._decompressor.decompress(
            data,
            max_length=OUTPUT_CHUNK_SIZE,
        )

        # Drain buffered output until the decoder needs more input
        # or reaches EOF.
        while True:
            if output:
                self._sink.write(output)

            if self._decompressor.needs_input or self._decompressor.eof:
                return

            output = self._decompressor.decompress(
                b"",
                max_length=OUTPUT_CHUNK_SIZE,
            )


class ZstdOutputSink(io.RawIOBase):
    def __init__(self, next_sink: HasWrite) -> None:
        super().__init__()
        self._sink = Sink(next_sink)

    def write(self, data: BinaryData) -> int:  # type: ignore[override]
        return self._sink.write(data)

    def writable(self) -> bool:
        return True


class ZstdSinkDecompressor:
    def __init__(self, next_sink: HasWrite) -> None:
        self._output_sink = ZstdOutputSink(next_sink)

        self._decompression_writer = zstd.ZstdDecompressor().stream_writer(
            cast(IO[bytes], self._output_sink),
            closefd=False,
            write_size=OUTPUT_CHUNK_SIZE,
        )

    def decompress(self, data: memoryview) -> None:
        self._decompression_writer.write(data)


class DecompressSink(Sink):
    def __init__(
        self,
        next_sink: HasWrite,
        compression_algorithm: str,
    ) -> None:
        super().__init__(next_sink)

        self.decompressor: SinkDecompressor = self._create_decompressor(compression_algorithm)

    def _create_decompressor(
        self,
        alg: str,
    ) -> SinkDecompressor:
        if alg == "snappy":
            return SnappySinkDecompressor(self.next_sink)

        if alg == "lzma":
            return LzmaSinkDecompressor(self.next_sink)

        if alg == "zstd":
            return ZstdSinkDecompressor(self.next_sink)

        raise InvalidConfigurationError(f"invalid compression algorithm: {alg!r}")

    def write(self, data: BinaryData) -> int:
        view = memoryview(data)

        if view:
            self.decompressor.decompress(view)

        return len(view)
