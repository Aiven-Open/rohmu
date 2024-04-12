# Copyright (c) 2016 Ohmu Ltd
# See LICENSE for details
"""Rohmu - file-like interface for snappy"""

from .common.constants import IO_BLOCK_SIZE
from .filewrap import FileWrap
from .typing import BinaryData, FileLike
from typing import Optional

import io

try:
    import snappy
except ImportError:
    snappy = None  # type: ignore


class SnappyFile(FileWrap):
    def __init__(self, next_fp: FileLike, mode: str) -> None:
        if snappy is None:
            raise io.UnsupportedOperation("Snappy is not available")

        if mode == "rb":
            self.decr = snappy.StreamDecompressor()
            self.encr = None
        elif mode == "wb":
            self.decr = None
            self.encr = snappy.StreamCompressor()
        else:
            raise io.UnsupportedOperation("unsupported mode for SnappyFile")

        super().__init__(next_fp)
        self.decr_done = False

    def close(self) -> None:
        if self.closed:
            return
        if self.encr:
            data = self.encr.flush() or b""
            if data:
                self.next_fp.write(data)
            self.next_fp.flush()
        super().close()

    def write(self, data: BinaryData) -> int:  # type: ignore[override]
        self._check_not_closed()
        if self.encr is None:
            raise io.UnsupportedOperation("file not open for writing")
        data_as_bytes = bytes(data)
        compressed_data = self.encr.compress(data_as_bytes)
        self.next_fp.write(compressed_data)
        self.offset += len(data_as_bytes)
        return len(data_as_bytes)

    def writable(self) -> bool:
        return self.encr is not None

    def read(self, size: Optional[int] = -1) -> bytes:
        # NOTE: size arg is ignored, random size output is returned
        self._check_not_closed()
        if self.decr is None:
            raise io.UnsupportedOperation("file not open for reading")
        while not self.decr_done:
            compressed = self.next_fp.read(IO_BLOCK_SIZE)
            if not compressed:
                self.decr_done = True
                output = self.decr.flush()
            else:
                output = self.decr.decompress(compressed)

            if output:
                self.offset += len(output)
                return output

        return b""

    def readable(self) -> bool:
        return self.decr is not None
