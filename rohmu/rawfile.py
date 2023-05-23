"""
rohmu - file-like interface for raw file

Copyright (c) 2016 Ohmu Ltd
See LICENSE for details
"""
from . import IO_BLOCK_SIZE
from .filewrap import FileWrap
from .typing import BinaryData, FileLike
from typing import Optional


class RawFile(FileWrap):
    def __init__(self, next_fp: FileLike) -> None:
        super().__init__(next_fp)

    def close(self) -> None:
        if self.closed:
            return
        data = self.flush() or b""
        if data:
            self.next_fp.write(data)
        self.next_fp.flush()
        super().close()

    def write(self, data: BinaryData) -> int:
        self._check_not_closed()
        data_as_bytes = bytes(data)
        self.next_fp.write(data_as_bytes)
        self.offset += len(data_as_bytes)
        return len(data_as_bytes)

    def writable(self) -> bool:
        return True

    def read(self, size: Optional[int] = -1) -> bytes:  # pylint: disable=unused-argument
        # NOTE: size arg is ignored, random size output is returned
        self._check_not_closed()
        while not self._done:
            output = self.next_fp.read(IO_BLOCK_SIZE)

            if output:
                self.offset += len(output)
                return output

        return b""

    def readable(self) -> bool:
        return True

