"""
rohmu - common utility functions

Copyright (c) 2022 Ohmu Ltd
See LICENSE for details
"""
from itertools import islice
from rohmu.typing import HasFileno
from typing import Generator, Iterable, Optional, Tuple, TypeVar, Union

import fcntl
import logging
import os
import platform

LOG = logging.getLogger("rohmu.util")


def increase_pipe_capacity(*pipes: Union[int, HasFileno]) -> None:
    if platform.system() != "Linux":
        return
    try:
        with open("/proc/sys/fs/pipe-max-size", "r") as f:
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


T = TypeVar("T")


def batched(iterable: Iterable[T], n: int) -> Generator[Tuple[T, ...], None, None]:
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


def get_total_size_from_content_range(content_range: str) -> Optional[int]:
    length = content_range.rsplit("/", 1)[1]
    # RFC 9110 section 14.4 specifies that the * can be returned when the total length is unknown
    return int(length) if length != "*" else None
