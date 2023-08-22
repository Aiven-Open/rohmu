"""
rohmu - file-like interface for snappy

Copyright (c) 2016 Ohmu Ltd
See LICENSE for details
"""
from .common.constants import IO_BLOCK_SIZE
from .filewrap import FileWrap
from .typing import BinaryData, FileLike
from typing import Optional

import io

try:
    import cramjam
except ImportError:
    cramjam = None  # type: ignore


class SnappyFile(FileWrap):
    def __init__(self, next_fp: FileLike, mode: str) -> None:
        if cramjam is None:
            raise io.UnsupportedOperation("Snappy is not available")

        if mode == "rb":
            self.decr = cramjam.snappy.Decompressor()
            self.encr = None
        elif mode == "wb":
            self.decr = None
            self.encr = cramjam.snappy.Compressor()
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

    def write(self, data: BinaryData) -> int:  # type: ignore [override]
        self._check_not_closed()
        if self.encr is None:
            raise io.UnsupportedOperation("file not open for writing")
        data_as_bytes = bytes(data)
        block_size = self.encr.compress(data_as_bytes)
        compressed_buffer = self.encr.flush()
        self.next_fp.write(compressed_buffer)
        self.offset += block_size
        return block_size

    def writable(self) -> bool:
        return self.encr is not None

    def read(self, size: Optional[int] = -1) -> bytes:  # pylint: disable=unused-argument
        # NOTE: size arg is ignored, random size output is returned
        self._check_not_closed()
        if self.decr is None:
            raise io.UnsupportedOperation("file not open for reading")
        num_decompressed_bytes = 0
        while compressed := self.next_fp.read(IO_BLOCK_SIZE):
            chunk_size = self.decr.decompress(compressed)
            num_decompressed_bytes += chunk_size
        self.offset += num_decompressed_bytes
        output = self.decr.flush().read()
        return output

    def readable(self) -> bool:
        return self.decr is not None
