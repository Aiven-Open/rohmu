from __future__ import annotations

from types import TracebackType
from typing import Any, Dict, Optional, Protocol, Type, TYPE_CHECKING, Union

try:
    # Remove when dropping support for Python 3.7
    from pickle import PickleBuffer
except ImportError:
    PickleBuffer = bytes  # type: ignore[misc,assignment]
import mmap

if TYPE_CHECKING:
    from array import array
    from os import PathLike

    import ctypes

Metadata = Dict[str, Any]

AnyPath = Union[str, bytes, "PathLike[str]", "PathLike[bytes]"]

BinaryData = Union[
    bytes,
    bytearray,
    memoryview,
    "array[Any]",
    mmap.mmap,
    "ctypes._CData",
    PickleBuffer,
]

StrOrPathLike = Union[str, "PathLike[str]"]


class HasFileno(Protocol):
    def fileno(self) -> int:
        ...


class HasRead(Protocol):
    def read(self, n: int = -1, /) -> bytes:
        ...


class HasWrite(Protocol):
    def write(self, data: BinaryData) -> int:
        ...


class HasSeek(Protocol):
    def seek(self, offset: int, whence: int = 0, /) -> int:
        ...


class HasName(Protocol):
    name: str


class FileLike(Protocol):
    def __enter__(self) -> FileLike:
        ...

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        ...

    def read(self, n: int = -1, /) -> bytes:
        ...

    def flush(self) -> None:
        ...

    def write(self, data: BinaryData) -> int:
        ...

    def close(self) -> None:
        ...

    def fileno(self) -> int:
        ...

    def tell(self) -> int:
        ...

    def seek(self, offset: int, whence: int = 0, /) -> int:
        ...


class Compressor(Protocol):
    def compress(self, data: bytes) -> bytes:
        ...

    def flush(self) -> bytes:
        ...


class Decompressor(Protocol):
    def decompress(self, data: bytes) -> bytes:
        ...
