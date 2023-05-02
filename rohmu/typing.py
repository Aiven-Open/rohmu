from array import array
from os import PathLike
from pickle import PickleBuffer
from typing import Any, Protocol, Union

import ctypes
import mmap

Metadata = dict[str, Any]

AnyPath = Union[str, bytes, PathLike[str], PathLike[bytes]]


class HasFileno(Protocol):
    def fileno(self) -> int:
        ...


class Compressor(Protocol):
    def compress(self, data: bytes) -> Any:
        ...

    def flush(self) -> bytes:
        ...


class Decompressor(Protocol):
    def decompress(self, data: bytes) -> bytes:
        ...


BinaryData = Union[
    bytes,
    bytearray,
    memoryview,
    array[Any],  # pylint: disable=unsubscriptable-object
    mmap.mmap,
    ctypes._CData,  # pylint: disable=no-member,protected-access
    PickleBuffer,
]
