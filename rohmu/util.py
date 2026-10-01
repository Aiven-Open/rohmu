# Copyright (c) 2022 Ohmu Ltd
# See LICENSE for details
"""Rohmu - common utility functions"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Generator, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from io import BytesIO, UnsupportedOperation
from itertools import islice
from rohmu.typing import HasFileno
from typing import BinaryIO, TypeVar
from typing_extensions import Buffer

import fcntl
import logging
import os
import platform
import types

LOG = logging.getLogger(__name__)


def increase_pipe_capacity(*pipes: int | HasFileno) -> None:
    if platform.system() != "Linux":
        return
    try:
        with open("/proc/sys/fs/pipe-max-size", encoding="utf-8") as f:
            pipe_max_size = int(f.read())
    except FileNotFoundError:
        return
    # Attempt to get as big pipe as possible; as Linux pipe usage quotas are
    # account wide (and not visible to us), brute-force attempting is
    # the best we can do.
    #
    # F_SETPIPE_SZ can also return EBUSY if trying to shrink pipe from
    # what is in the buffer (not true in our case as pipe should be
    # growing), or ENOMEM, and we bail in both of those cases.
    for pipe in pipes:
        for shift in range(0, 16):
            size = pipe_max_size >> shift
            if size <= 65536:
                # Default size
                LOG.warning("Unable to grow pipe buffer at all, performance may suffer")
                return
            try:
                fcntl.fcntl(pipe, 1031, pipe_max_size)  # F_SETPIPE_SZ
                break
            except PermissionError:
                pass


def set_stream_nonblocking(stream: HasFileno) -> None:
    fd = stream.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)


def file_object_is_empty(fd: BinaryIO) -> bool:
    # not seekable, so we cannot verify it has no contents
    if not hasattr(fd, "seekable") or not fd.seekable():
        return False

    fd.seek(0)
    is_empty = len(fd.read(1)) == 0

    # rewind file
    fd.seek(0)
    return is_empty


T = TypeVar("T")
R = TypeVar("R")


def parallel_map(fn: Callable[[T], R], iterable: Iterable[T], *, max_workers: int) -> Generator[R, None, None]:
    """Like map(), but runs up to `max_workers` calls of `fn` concurrently in threads.

    Results are yielded in input order. The input is consumed lazily, at most `2 * max_workers` items ahead
    of the consumer. If `fn` raises or the consumer stops early, pending calls are cancelled and running
    calls are waited for before returning.
    """
    executor = ThreadPoolExecutor(max_workers=max_workers)
    pending: deque[Future[R]] = deque()
    try:
        for item in iterable:
            pending.append(executor.submit(fn, item))
            if len(pending) >= 2 * max_workers:
                yield pending.popleft().result()
        while pending:
            yield pending.popleft().result()
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


def batched(iterable: Iterable[T], n: int) -> Generator[tuple[T, ...], None, None]:
    "Batch data into tuples of length n. The last batch may be shorter."
    # batched('ABCDEFG', 3) --> ABC DEF G
    # NOTE: can replace with itertools version once on python 3.12
    if n < 1:
        raise ValueError("n must be at least one")
    it = iter(iterable)
    batch = tuple(islice(it, n))
    while batch:
        yield batch
        batch = tuple(islice(it, n))


def get_total_size_from_content_range(content_range: str) -> int | None:
    length = content_range.rsplit("/", 1)[1]
    # RFC 9110 section 14.4 specifies that the * can be returned when the total length is unknown
    return int(length) if length != "*" else None


class BinaryStreamsConcatenation:
    """Concatenate a sequence of binary streams.
    The concatenation only allows for the read() call.
    """

    def __init__(self, files: Iterable[BinaryIO]) -> None:
        self._iter_files = iter(files)
        self._current_file: BinaryIO | None = None

    def _read_chunk(self, size: int = -1) -> bytes:
        if self._current_file is None:
            self._current_file = next(self._iter_files, None)
            if self._current_file is None:
                return b""
        data = self._current_file.read(size) if size > 0 else self._current_file.read()
        if not data:
            self._current_file.close()
            self._current_file = next(self._iter_files, None)
        return data

    def read(self, size: int = -1) -> bytes:
        result = BytesIO()
        size_left = size
        while True:
            chunk = self._read_chunk(size_left)
            if not chunk and self._current_file is None:
                # we finished reading all files
                break
            result.write(chunk)
            size_left -= len(chunk)
            if size > 0 and size_left == 0:
                # we finished reading the amount requested
                break

        return result.getvalue()


class ProgressStream(BinaryIO):
    """Wrapper for binary streams that can report the amount of bytes read through it."""

    def __init__(self, raw_stream: BinaryIO) -> None:
        self.raw_stream = raw_stream
        self.bytes_read = 0

    def seekable(self) -> bool:
        """A progress stream is seekable if the underlying stream is."""
        return self.raw_stream.seekable()

    def writable(self) -> bool:
        return False

    def readable(self) -> bool:
        return True

    @property
    def closed(self) -> bool:
        return self.raw_stream.closed

    @property
    def name(self) -> str:
        return self.raw_stream.name

    @property
    def mode(self) -> str:
        return self.raw_stream.mode

    def read(self, n: int = -1) -> bytes:
        data = self.raw_stream.read(n)
        self.bytes_read += len(data)
        return data

    def readline(self, limit: int = -1) -> bytes:
        line = self.raw_stream.readline(limit)
        self.bytes_read += len(line)
        return line

    def readlines(self, hint: int = -1) -> list[bytes]:
        lines = self.raw_stream.readlines(hint)
        self.bytes_read += sum(map(len, lines))
        return lines

    def __iter__(self) -> ProgressStream:
        return self

    def __next__(self) -> bytes:
        data = next(self.raw_stream)
        self.bytes_read += len(data)
        return data

    def __enter__(self) -> ProgressStream:
        self.raw_stream.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        return self.raw_stream.__exit__(exc_type, exc_val, exc_tb)

    def close(self) -> None:
        self.raw_stream.close()

    def flush(self) -> None:
        self.raw_stream.flush()

    def isatty(self) -> bool:
        return self.raw_stream.isatty()

    def tell(self) -> int:
        return self.raw_stream.tell()

    def seek(self, offset: int, whence: int = 0, /) -> int:
        """Seek the underlying file if this operation is supported.

        NOTE: Calling this method will reset the bytes_read field!
        """
        result = self.raw_stream.seek(offset, whence)

        self.bytes_read = 0
        return result

    def truncate(self, size: int | None = None) -> int:
        raise UnsupportedOperation("truncate")

    def write(self, s: bytes | Buffer) -> int:
        raise UnsupportedOperation("write")

    def writelines(self, __lines: Iterable[bytes] | Iterable[Buffer]) -> None:
        raise UnsupportedOperation("writelines")

    def fileno(self) -> int:
        raise UnsupportedOperation("fileno")
