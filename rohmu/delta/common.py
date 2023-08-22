# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from multiprocessing.dummy import Pool
from pathlib import Path
from pydantic import BaseModel, Field
from rohmu.dates import now
from rohmu.typing import AnyPath, HasRead
from types import TracebackType
from typing import Any, Callable, Iterable, List, Optional, Sequence, Type, TypeVar

import functools
import hashlib
import json as _json
import logging
import math
import os

_hash = hashlib.blake2s
_log_1_1 = math.log(1.1)

# Hexdigest is 32 bytes, so something orders of magnitude more at least
EMBEDDED_FILE_SIZE = 150

logger = logging.getLogger(__name__)


def hash_hexdigest_readable(f: HasRead, *, read_buffer: int = 1_000_000) -> str:
    h = _hash()
    while True:
        data = f.read(read_buffer)
        if not data:
            break
        h.update(data)
    return h.hexdigest()


def increase_worth_reporting(value: int, new_value: Optional[int] = None, *, total: Optional[int] = None) -> bool:
    """Make reporting sparser and sparser as values grow larger
    - report every 1.1**N or so
    - if we know total, report every percent
    """
    if new_value is None:
        new_value = value
        value = new_value - 1
    if total is not None:
        if new_value == total or total <= 100:
            return True
        old_percent = 100 * value // total
        new_percent = 100 * new_value // total
        return old_percent != new_percent
    if value <= 10 or new_value <= 10:
        return True
    old_exp = int(math.log(value) / _log_1_1)
    new_exp = int(math.log(new_value) / _log_1_1)
    return old_exp != new_exp


class DeltaModel(BaseModel):
    class Config:
        # As we're keen to both export and decode json, just using
        # enum values for encode/decode is much saner than the default
        # enumname.value (it is also slightly less safe but oh well)
        use_enum_values = True

        # Extra values should be errors, as they are most likely typos
        # which lead to grief when not detected. However, if we ever
        # start deprecating some old fields and not wanting to parse
        # them, this might need to be revisited.
        extra = "forbid"

        # Validate field default values too
        validate_all = True

        # Validate also assignments
        # validate_assignment = True
        # TBD: Figure out why this doesn't work in some unit tests;
        # possibly the tests themselves are broken
        validate_assignment = True

    def jsondict(self, **kw: Any) -> dict[str, Any]:
        # By default,
        #
        # .json() returns json string.
        # .dict() returns Python dict, but it has things that are not
        # json serializable.
        #
        # We provide json seralizable dict (super inefficiently) here.
        #
        # This is mostly used for test code so that should be fine
        return _json.loads(self.json(**kw))


class SizeLimitedFile:
    def __init__(self, *, path: AnyPath, file_size: int) -> None:
        self._f = open(path, "rb")  # pylint: disable=consider-using-with
        self._file_size = file_size
        self.tell = self._f.tell

    def __enter__(self) -> SizeLimitedFile:
        return self

    def __exit__(self, t: Optional[Type[BaseException]], v: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        self._f.close()

    def read(self, n: Optional[int] = None) -> bytes:
        can_read = max(0, self._file_size - self._f.tell())
        if n is None:
            n = can_read
        n = min(can_read, n)
        return self._f.read(n)

    def seek(self, ofs: int, whence: int = 0) -> int:
        if whence == os.SEEK_END:
            ofs += self._file_size
            whence = os.SEEK_SET
        return self._f.seek(ofs, whence)


class SnapshotHash(DeltaModel):
    """
    This class represents something that is to be stored in the object storage.

    size is provided mainly to allow for even loading of nodes in case
    same hexdigest is available from multiple nodes.

    """

    hexdigest: str
    size: int

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, SnapshotHash):
            return self.hexdigest == other.hexdigest
        return False

    def __hash__(self) -> int:
        # hexdigests should be unique, regardless of size
        return hash(self.hexdigest)


@functools.total_ordering
class SnapshotFile(DeltaModel):
    relative_path: Path = Field(..., allow_mutation=False)
    file_size: int
    stored_file_size: int
    mtime_ns: int
    hexdigest: str = ""
    content_b64: Optional[str] = None
    # Indicator if a file should be part of a chunk/bundle - useful for the files which are small to be treated as
    # separate delta hash files, but not small enough to be embedded into a manifest file, so better to group them
    # together when e.g. uploading to the object storage
    should_be_bundled: bool = False
    missing_ok: bool = True

    def __lt__(self, o: SnapshotFile) -> bool:
        # In our use case, paths uniquely identify files we care about
        return self.relative_path < o.relative_path

    def __hash__(self) -> int:
        return hash(self.relative_path)

    def equals_excluding_mtime(self, o: SnapshotFile) -> bool:
        return self.copy(update={"mtime_ns": 0}) == o.copy(update={"mtime_ns": 0})

    def open_for_reading(self, root_path: Path) -> SizeLimitedFile:
        return SizeLimitedFile(path=root_path / self.relative_path, file_size=self.file_size)


class SnapshotState(DeltaModel):
    root_globs: List[str]
    files: List[SnapshotFile]
    empty_dirs: List[Path]


class SnapshotResult(DeltaModel):
    # when was the operation started ( / done )
    start: datetime = Field(default_factory=now)
    end: Optional[datetime]
    #
    # should be passed opaquely to restore
    state: Optional[SnapshotState]
    #
    # Summary data for manifest use
    files: int = 0
    total_size: int = 0

    # populated only if state is available
    hashes: Optional[List[SnapshotHash]]


class SnapshotUploadResult(DeltaModel):
    total_size: int = 0
    total_stored_size: int = 0


class BackupManifest(DeltaModel):
    start: datetime
    end: datetime = Field(default_factory=now)

    # Filesystem snapshot contents of the backup
    snapshot_result: SnapshotResult

    # What did the upload return (mostly for statistics)
    upload_result: SnapshotUploadResult


class Progress(DeltaModel):
    """JSON-encodable progress meter of sorts"""

    handled: int = 0
    failed: int = 0
    total: int = 0
    final: bool = False

    def __repr__(self) -> str:
        finished = ", finished" if self.final else ""
        return f"{self.handled}/{self.total} handled, {self.failed} failures{finished}"

    def start(self, n: int) -> None:
        "Optional 'first' step, just for logic handling state (e.g. no progress object reuse desired)"
        assert not self.total
        logger.debug("start")
        self.add_total(n)

    def add_total(self, n: int) -> None:
        if not n:
            return
        old_total = self.total
        self.total += n
        if increase_worth_reporting(old_total, self.total):
            logger.debug("add_total %r -> %r", n, self)
        assert not self.final

    def add_fail(self, n: int = 1, *, info: str = "add_fail") -> None:
        assert n > 0
        old_failed = self.failed
        self.failed += n
        if increase_worth_reporting(old_failed, self.failed):
            logger.debug("%s %r -> %r", info, n, self)
        assert not self.final

    def add_success(self, n: int = 1, *, info: str = "add_success") -> None:
        assert n > 0
        old_handled = self.handled
        self.handled += n
        assert self.handled <= self.total
        if increase_worth_reporting(old_handled, self.handled, total=self.total):
            logger.debug("%s %r -> %r", info, n, self)
        assert not self.final

    def download_success(self, size: int) -> None:
        self.add_success(size, info="download_success")

    def upload_success(self, hexdigest: str) -> None:
        self.add_success(info=f"upload_success {hexdigest}")

    def upload_missing(self, hexdigest: str) -> None:
        self.add_fail(info=f"upload_missing {hexdigest}")

    def upload_failure(self, hexdigest: str) -> None:
        self.add_fail(info=f"upload_failure {hexdigest}")

    def done(self) -> None:
        assert self.total is not None and self.handled <= self.total
        assert not self.final
        self.final = True
        logger.debug("done %r", self)

    @property
    def finished_successfully(self) -> bool:
        return self.final and not self.failed and self.handled == self.total

    @property
    def finished_failed(self) -> bool:
        return self.final and not self.finished_successfully

    @classmethod
    def merge(cls, progresses: Sequence[Progress]) -> Progress:
        p = cls()
        for progress in progresses:
            p.handled += progress.handled
            p.failed += progress.failed
            p.total += progress.total
        p.final = all(progress.final for progress in progresses)
        return p


Item = TypeVar("Item")
Result = TypeVar("Result")


def parallel_map_to(
    *, fun: Callable[[Item], Result], iterable: Iterable[Item], result_callback: Callable[..., bool], n: Optional[int] = None
) -> bool:
    iterable_as_list = list(iterable)
    with Pool(n) as p:
        for map_in, map_out in zip(iterable_as_list, p.imap(fun, iterable_as_list)):
            if not result_callback(map_in=map_in, map_out=map_out):
                return False
    return True


@dataclass(frozen=True)
class BackupPath:
    path: Path
    missing_ok: bool = True
