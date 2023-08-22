"""
rohmu - compressor interface

Copyright (c) 2016 Ohmu Ltd
See LICENSE for details
"""
from .errors import InvalidConfigurationError
from .filewrap import Sink, Stream
from .snappyfile import SnappyFile
from .typing import BinaryData, CompressionAlgorithm, Compressor, Decompressor, FileLike, HasRead, HasWrite
from .zstdfile import open as zstd_open
from typing import cast, IO

import lzma

try:
    import cramjam

    # Cramjam streaming classes are lazy and diverge from Compressor and Decompressor interfaces.
    # Adapt the parent classes to flush and return the inner buffer after compress and decompress calls.
    class CramjamStreamingCompressor(Compressor):
        def __init__(self) -> None:
            self._compressor = cramjam.snappy.Compressor()

        def compress(self, data: bytes) -> bytes:
            self._compressor.compress(data)
            return self.flush()

        def flush(self) -> bytes:
            buf = self._compressor.flush()
            return buf.read()

    class CramjamStreamingDecompressor(Decompressor):
        def __init__(self) -> None:
            self._decompressor = cramjam.snappy.Decompressor()

        def decompress(self, data: bytes) -> bytes:
            self._decompressor.decompress(data)
            buf = self._decompressor.flush()
            return buf.read()

except ImportError:
    cramjam = None  # type: ignore
    CramjamStreamingCompressor: Compressor | None = None  # type: ignore[no-redef]
    CramjamStreamingDecompressor: Decompressor | None = None  # type: ignore[no-redef]

try:
    import zstandard as zstd
except ImportError:
    zstd = None  # type: ignore


def CompressionFile(dst_fp: FileLike, algorithm: CompressionAlgorithm, level: int = 0, threads: int = 0) -> FileLike:
    """This looks like a class to users, but is actually a function that instantiates a class based on algorithm."""
    compression_fileobj: FileLike
    match algorithm:
        case "lzma":
            compression_fileobj = lzma.open(cast(IO[bytes], dst_fp), "w", preset=level)
        case "snappy":
            compression_fileobj = SnappyFile(dst_fp, "wb")
        case "zstd":
            compression_fileobj = zstd_open(dst_fp, "wb", level=level, threads=threads)
        case _:
            raise InvalidConfigurationError(f"invalid compression algorithm: {repr(algorithm)}")
    return compression_fileobj


def create_streaming_compressor(algorithm: CompressionAlgorithm, level: int = 0) -> Compressor:
    compressor: Compressor
    match algorithm:
        case "lzma":
            compressor = lzma.LZMACompressor(lzma.FORMAT_XZ, -1, level, None)
        case "snappy":
            if CramjamStreamingCompressor is None:
                raise ImportError("Unable to import cramjam")
            compressor = CramjamStreamingCompressor()
        case "zstd":
            compressor = zstd.ZstdCompressor(level=level).compressobj()
        case _:
            raise InvalidConfigurationError(f"invalid compression algorithm: {repr(algorithm)}")
    return compressor


class CompressionStream(Stream):
    """Non-seekable stream of data that adds compression on top of given source stream"""

    def __init__(self, src_fp: HasRead, algorithm: CompressionAlgorithm, level: int = 0) -> None:
        super().__init__(src_fp, minimum_read_size=32 * 1024)
        self._compressor = create_streaming_compressor(algorithm, level)

    def _process_chunk(self, data: bytes) -> bytes:
        return self._compressor.compress(data)

    def _finalize(self) -> bytes:
        return self._compressor.flush()


def DecompressionFile(src_fp: FileLike, algorithm: CompressionAlgorithm) -> FileLike:
    """This looks like a class to users, but is actually a function that instantiates a class based on algorithm."""
    match algorithm:
        case "lzma":
            return lzma.open(cast(IO[bytes], src_fp), "r")
        case "snappy":
            return SnappyFile(src_fp, "rb")
        case "zstd":
            return zstd_open(src_fp, "rb")
        case _:
            raise InvalidConfigurationError(f"invalid compression algorithm: {repr(algorithm)}")


def create_streaming_decompressor(algorithm: CompressionAlgorithm) -> Decompressor:
    decompressor: Decompressor
    match algorithm:
        case "lzma":
            decompressor = lzma.LZMADecompressor()
        case "snappy":
            if CramjamStreamingDecompressor is None:
                raise ImportError("Unable to import cramjam")
            decompressor = CramjamStreamingDecompressor()
        case "zstd":
            decompressor = zstd.ZstdDecompressor().decompressobj()
        case _:
            raise InvalidConfigurationError(f"invalid compression algorithm: {repr(algorithm)}")
    return decompressor


class DecompressSink(Sink):
    def __init__(self, next_sink: HasWrite, compression_algorithm: CompressionAlgorithm):
        super().__init__(next_sink)
        self.decompressor = create_streaming_decompressor(compression_algorithm)

    def write(self, data: BinaryData) -> int:
        data = bytes(data) if not isinstance(data, bytes) else data
        written = len(data)
        if not data:
            return written
        decompressed_data = self.decompressor.decompress(data)
        self._write_to_next_sink(decompressed_data)
        return written
