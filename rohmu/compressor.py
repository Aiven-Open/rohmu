"""
rohmu - compressor interface

Copyright (c) 2016 Ohmu Ltd
See LICENSE for details
"""
from .errors import InvalidConfigurationError
from .filewrap import Sink, Stream
from .snappyfile import SnappyFile
from .typing import BinaryData, Compressor, Decompressor, FileLike, HasRead, HasWrite
from .zstdfile import open as zstd_open
from typing import cast, IO

import lzma

try:
    import snappy
except ImportError:
    snappy = None  # type: ignore

try:
    import zstandard as zstd
except ImportError:
    zstd = None  # type: ignore


def CompressionFile(dst_fp: FileLike, algorithm: str, level: int = 0, threads: int = 0) -> FileLike:
    """This looks like a class to users, but is actually a function that instantiates a class based on algorithm."""
    if algorithm == "lzma":
        return lzma.open(cast(IO[bytes], dst_fp), "w", preset=level)

    if algorithm == "snappy":
        return SnappyFile(dst_fp, "wb")

    if algorithm == "zstd":
        return zstd_open(dst_fp, "wb", level=level, threads=threads)

    if algorithm:
        raise InvalidConfigurationError("invalid compression algorithm: {!r}".format(algorithm))

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
            raise InvalidConfigurationError("invalid compression algorithm: {!r}".format(algorithm))

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
        raise InvalidConfigurationError("invalid compression algorithm: {!r}".format(algorithm))

    return src_fp


class DecompressSink(Sink):
    def __init__(self, next_sink: HasWrite, compression_algorithm: str):
        super().__init__(next_sink)
        self.decompressor = self._create_decompressor(compression_algorithm)

    def _create_decompressor(self, alg: str) -> Decompressor:
        if alg == "snappy":
            return snappy.StreamDecompressor()
        elif alg == "lzma":
            return lzma.LZMADecompressor()
        elif alg == "zstd":
            return zstd.ZstdDecompressor().decompressobj()
        raise InvalidConfigurationError("invalid compression algorithm: {!r}".format(alg))

    def write(self, data: BinaryData) -> int:
        data = bytes(data) if not isinstance(data, bytes) else data
        written = len(data)
        if not data:
            return written
        data = self.decompressor.decompress(data)
        self._write_to_next_sink(data)
        return written
