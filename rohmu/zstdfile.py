# Copyright (c) 2016 Ohmu Ltd
# See LICENSE for details
"""Rohmu - file-like interface for zstd"""

from .common.constants import IO_BLOCK_SIZE
from .filewrap import FileWrap
from .typing import BinaryData, FileLike
from typing import Optional

import io

try:
    import zstandard as zstd
except ImportError:
    zstd = None  # type: ignore


class _ZstdFileWriter(FileWrap):
    def __init__(self, next_fp: FileLike, level: int, threads: int = 0) -> None:
        self._zstd = zstd.ZstdCompressor(level=level, threads=threads).compressobj()
        super().__init__(next_fp)

    def close(self) -> None:
        if self.closed:
            return
        data = self._zstd.flush() or b""
        if data:
            self.next_fp.write(data)
        self.next_fp.flush()
        super().close()

    def write(self, data: BinaryData) -> int:  # type: ignore[override]
        self._check_not_closed()
        data_as_bytes = bytes(data)
        compressed_data = self._zstd.compress(data_as_bytes)
        self.next_fp.write(compressed_data)
        self.offset += len(data_as_bytes)
        return len(data_as_bytes)

    def writable(self) -> bool:
        return True


class _ZtsdFileReader(FileWrap):
    def __init__(self, next_fp: FileLike) -> None:
        self._stream = zstd.ZstdDecompressor().stream_reader(
            next_fp,  # type: ignore[arg-type]
            read_size=IO_BLOCK_SIZE,
            read_across_frames=True,
        )
        super().__init__(next_fp)

    def close(self) -> None:
        if self.closed:
            return
        self._stream.close()
        super().close()

    def read(self, size: Optional[int] = -1) -> bytes:
        self._check_not_closed()
        if size == 0:
            return b""

        read_size = size if size and size > 0 else IO_BLOCK_SIZE
        data = self._stream.read(read_size)
        self.offset += len(data)
        return data

    def readable(self) -> bool:
        return True


def open(fp: FileLike, mode: str, level: int = 0, threads: int = 0) -> FileWrap:
    if zstd is None:
        raise io.UnsupportedOperation("zstd is not available")

    if mode == "wb":
        return _ZstdFileWriter(fp, level, threads)

    if mode == "rb":
        return _ZtsdFileReader(fp)

    raise io.UnsupportedOperation("unsupported mode for zstd")
