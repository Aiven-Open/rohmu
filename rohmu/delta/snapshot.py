# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/

from __future__ import annotations

from pathlib import Path
from rohmu.delta.common import (
    BackupPath,
    EMBEDDED_FILE_SIZE,
    hash_hexdigest_readable,
    increase_worth_reporting,
    parallel_map_to,
    Progress,
    ProgressMetrics,
    ProgressStep,
    SnapshotFile,
    SnapshotHash,
    SnapshotState,
)
from rohmu.typing import StrOrPathLike
from typing import Any, Callable, Generator, Iterable, List, Optional, Sequence, Set, Tuple, Union

import base64
import logging
import os
import threading

logger = logging.getLogger(__name__)


class Snapshotter:
    """Snapshotter keeps track of files on disk, and their hashes.

    The hash on disk MAY change, which may require subsequent
    incremental snapshot and-or ignoring the files which have changed.

    The output to outside is just root object's hash, as well as list
    of other hashes which correspond to files referred to within the
    file list contained in root object.

    Note that any call to public API MUST be made with
    snapshotter.lock held. This is because Snapshotter is process-wide
    utility that is shared across operations, possibly used from
    multiple threads, and the single-operation-only mode of operation
    is not exactly flawless (the 'new operation can be started with
    old running' is intentional feature but new operation should
    eventually replace the old). The lock itself might not need to be
    built-in to Snapshotter, but having it there enables asserting its
    state during public API calls.
    """

    def __init__(
        self,
        *,
        src: StrOrPathLike,
        dst: StrOrPathLike,
        globs: list[str],
        src_iterate_func: Optional[Callable[[], Iterable[Union[BackupPath, str, Path]]]] = None,
        parallel: int = 1,
        min_delta_file_size: int = 0,
    ) -> None:
        assert globs
        self.src = Path(src)
        self.dst = Path(dst)
        self.globs = globs
        self.src_iterate_func = src_iterate_func
        self.relative_path_to_snapshotfile: dict[Path, SnapshotFile] = {}
        self.hexdigest_to_snapshotfiles: dict[str, List[SnapshotFile]] = {}
        self.parallel = parallel
        self.lock = threading.Lock()
        self.empty_dirs: List[Path] = []
        self.min_delta_file_size = min_delta_file_size

    def _list_files(self, basepath: Path) -> List[Path]:
        result_files = set()
        for glob in self.globs:
            for path in basepath.glob(glob):
                if not path.is_file() or path.is_symlink():
                    continue
                relpath = path.relative_to(basepath)
                result_files.add(relpath)

        return sorted(result_files)

    def _list_dirs_and_files(self, basepath: Path) -> Tuple[List[Path], List[Path]]:
        files = self._list_files(basepath)
        dirs = {p.parent for p in files}
        return sorted(dirs), files

    def _add_snapshotfile(self, snapshotfile: SnapshotFile) -> None:
        old_snapshotfile = self.relative_path_to_snapshotfile.get(snapshotfile.relative_path, None)
        if old_snapshotfile:
            self._remove_snapshotfile(old_snapshotfile)
        self.relative_path_to_snapshotfile[snapshotfile.relative_path] = snapshotfile
        if snapshotfile.hexdigest:
            self.hexdigest_to_snapshotfiles.setdefault(snapshotfile.hexdigest, []).append(snapshotfile)

    def _remove_snapshotfile(self, snapshotfile: SnapshotFile) -> None:
        assert self.relative_path_to_snapshotfile[snapshotfile.relative_path] == snapshotfile
        del self.relative_path_to_snapshotfile[snapshotfile.relative_path]
        if snapshotfile.hexdigest:
            self.hexdigest_to_snapshotfiles[snapshotfile.hexdigest].remove(snapshotfile)

    def _snapshotfile_from_path(self, relative_path: Path, missing_ok: bool) -> SnapshotFile:
        src_path = self.src / relative_path
        st = src_path.stat()
        return SnapshotFile(
            relative_path=relative_path,
            mtime_ns=st.st_mtime_ns,
            file_size=st.st_size,
            stored_file_size=0,
            missing_ok=missing_ok,
        )

    def _gen_snapshot_hashes(
        self, relative_paths: Sequence[Path], reuse_old_snapshotfiles: bool, required_paths: Optional[Set[Path]] = None
    ) -> Generator[SnapshotFile, None, None]:
        same = 0
        lost = 0

        if required_paths:
            missing_files = required_paths.difference(set(relative_paths))
            if missing_files:
                logger.error("Required file(s) disappeared during the backup: %r", missing_files)
                raise FileNotFoundError("File(s) disappeared during the backup, aborting.")

        for relative_path in relative_paths:
            old_snapshotfile = self.relative_path_to_snapshotfile.get(relative_path)
            missing_ok = True
            if required_paths and relative_path in required_paths:
                missing_ok = False
            try:
                snapshotfile = self._snapshotfile_from_path(relative_path, missing_ok=missing_ok)
            except FileNotFoundError as e:
                if not missing_ok:
                    raise FileNotFoundError(f"Required file disappeared during the backup: {relative_path}") from e
                lost += 1
                if increase_worth_reporting(lost):
                    logger.debug("#%d. lost - %s disappeared before stat, ignoring", lost, self.src / relative_path)
                continue
            if reuse_old_snapshotfiles and old_snapshotfile:
                snapshotfile.hexdigest = old_snapshotfile.hexdigest
                snapshotfile.content_b64 = old_snapshotfile.content_b64
                snapshotfile.should_be_bundled = old_snapshotfile.should_be_bundled
                snapshotfile.missing_ok = old_snapshotfile.missing_ok
                if old_snapshotfile == snapshotfile:
                    same += 1
                    if increase_worth_reporting(same):
                        logger.debug("#%d. same - %r in %s is same", same, old_snapshotfile, relative_path)
                    continue
            yield snapshotfile

    def get_snapshot_hashes(self) -> List[SnapshotHash]:
        assert self.lock.locked()
        return [
            SnapshotHash(hexdigest=dig, size=sf[0].file_size) for dig, sf in self.hexdigest_to_snapshotfiles.items() if sf
        ]

    def get_snapshot_state(self) -> SnapshotState:
        assert self.lock.locked()
        return SnapshotState(
            root_globs=self.globs, files=sorted(self.relative_path_to_snapshotfile.values()), empty_dirs=self.empty_dirs
        )

    def update_snapshot_file_data(
        self, *, relative_path: Path, hexdigest: str, file_size: int, stored_file_size: int
    ) -> None:
        snapshotfile = self.relative_path_to_snapshotfile[relative_path]
        snapshotfile.hexdigest = hexdigest
        snapshotfile.file_size = file_size
        snapshotfile.stored_file_size = stored_file_size

    def _snapshot_create_missing_directories(self, *, src_dirs: Sequence[Path], dst_dirs: Sequence[Path]) -> int:
        changes = 0
        for i, relative_dir in enumerate(set(src_dirs).difference(dst_dirs), 1):
            dst_path = self.dst / relative_dir
            dst_path.mkdir(parents=True, exist_ok=True)
            if increase_worth_reporting(i):
                logger.debug("#%d. new directory: %r", i, relative_dir)
            changes += 1
        return changes

    def _snapshot_remove_extra_files(
        self,
        *,
        src_files: Sequence[Path],
        dst_files: Sequence[Path],
        progress: Optional[Progress] = None,
        progress_callback: Optional[Callable[[ProgressStep, ProgressMetrics], None]] = None,
    ) -> int:
        if progress is None:
            progress = Progress()
        changes = 0
        for i, relative_path in enumerate(set(dst_files).difference(src_files), 1):
            dst_path = self.dst / relative_path
            snapshotfile = self.relative_path_to_snapshotfile.get(relative_path)
            if snapshotfile:
                self._remove_snapshotfile(snapshotfile)
                if progress_callback:
                    progress.add_success()
                    progress_callback(ProgressStep.REMOVING_EXTRA_FILES, progress.progress_metrics())
            dst_path.unlink()
            if increase_worth_reporting(i):
                logger.debug("#%d. extra file: %r", i, relative_path)
            changes += 1
        return changes

    def _snapshot_add_missing_files(self, *, src_files: Sequence[Path], dst_files: Sequence[Path]) -> int:
        existing = 0
        disappeared = 0
        changes = 0
        for i, relative_path in enumerate(set(src_files).difference(dst_files), 1):
            src_path = self.src / relative_path
            dst_path = self.dst / relative_path
            try:
                os.link(src=src_path, dst=dst_path, follow_symlinks=False)
            except FileExistsError:
                # This happens only if snapshot is started twice at
                # same time. While it is technically speaking upstream
                # error, we rather handle it here than leave
                # exceptions not handled.
                existing += 1
                if increase_worth_reporting(existing):
                    logger.debug("#%d. %s already existed, ignoring", existing, src_path)
                continue
            except FileNotFoundError:
                disappeared += 1
                if increase_worth_reporting(disappeared):
                    logger.debug("#%d. %s disappeared before linking, ignoring", disappeared, src_path)
                continue
            if increase_worth_reporting(i - disappeared):
                logger.debug("#%d. new file: %r", i - disappeared, relative_path)
            changes += 1
        return changes

    def snapshot(
        self,
        *,
        progress: Optional[Progress] = None,
        reuse_old_snapshotfiles: bool = True,
        progress_callback: Optional[Callable[[ProgressStep, ProgressMetrics], None]] = None,
    ) -> int:
        assert self.lock.locked()

        if progress is None:
            progress = Progress()
        progress.start(3)

        required_paths: Set[Path] = set()

        if self.src_iterate_func:
            src_dirs_set = set()
            src_files_set = set()
            for item in self.src_iterate_func():
                if isinstance(item, BackupPath):
                    missing_ok = item.missing_ok
                    path = item.path
                else:
                    # Default behaviour for backward compatibility
                    path = Path(item)
                    missing_ok = True

                if path.is_file() and not path.is_symlink():
                    if not missing_ok:
                        required_paths.add(path.relative_to(self.src))
                    src_files_set.add(path.relative_to(self.src))
                elif path.is_dir():
                    src_dirs_set.add(path.relative_to(self.src))
                elif not missing_ok:
                    raise FileNotFoundError(f"Required file disappeared during the backup: {path}")

            src_dirs = sorted(src_dirs_set | {p.parent for p in src_files_set})
            src_files = sorted(src_files_set)
        else:
            src_dirs, src_files = self._list_dirs_and_files(self.src)

        dst_dirs, dst_files = self._list_dirs_and_files(self.dst)

        # Create missing directories
        changes = self._snapshot_create_missing_directories(src_dirs=src_dirs, dst_dirs=dst_dirs)
        progress.add_success()
        if progress_callback:
            progress_callback(ProgressStep.CREATING_MISSING_DIRECTORIES, progress.progress_metrics())

        # Remove extra files
        changes += self._snapshot_remove_extra_files(
            src_files=src_files, dst_files=dst_files, progress=progress, progress_callback=progress_callback
        )
        progress.add_success()

        # Add missing files
        changes += self._snapshot_add_missing_files(src_files=src_files, dst_files=dst_files)
        progress.add_success()
        if progress_callback:
            progress_callback(ProgressStep.ADDING_MISSING_FILES, progress.progress_metrics())

        # We COULD also remove extra directories, but it is not
        # probably really worth it and due to ignored files it
        # actually might not even work.

        # Then, create/update corresponding snapshotfile objects (old
        # ones were already removed)
        dst_dirs, dst_files = self._list_dirs_and_files(self.dst)
        self.empty_dirs = src_dirs
        snapshotfiles = list(self._gen_snapshot_hashes(dst_files, reuse_old_snapshotfiles, required_paths=required_paths))

        progress.add_total(len(snapshotfiles))

        def _cb(snapshotfile: SnapshotFile) -> SnapshotFile:
            # src may or may not be present; dst is present as it is in snapshot
            with snapshotfile.open_for_reading(self.dst) as f:
                if snapshotfile.file_size <= EMBEDDED_FILE_SIZE:
                    snapshotfile.content_b64 = base64.b64encode(f.read()).decode()
                elif snapshotfile.file_size < self.min_delta_file_size:
                    snapshotfile.should_be_bundled = True
                else:
                    snapshotfile.hexdigest = hash_hexdigest_readable(f)
            return snapshotfile

        def _result_cb(*, map_in: Any, map_out: SnapshotFile) -> bool:
            self._add_snapshotfile(map_out)
            assert progress is not None
            progress.add_success()
            if progress_callback:
                progress_callback(ProgressStep.PROCESSING_AND_HASHING_SNAPSHOT_FILES, progress.progress_metrics())
            return True

        changes += len(snapshotfiles)
        parallel_map_to(iterable=snapshotfiles, fun=_cb, result_callback=_result_cb, n=self.parallel)
        return changes
