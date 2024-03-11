# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/

from __future__ import annotations

from pathlib import Path
from rohmu.delta.common import (
    BackupPath,
    EMBEDDED_FILE_SIZE,
    Progress,
    ProgressMetrics,
    ProgressStep,
    SizeLimitedFile,
    SnapshotFile,
    SnapshotHash,
)
from rohmu.typing import AnyPath
from test.conftest import SnapshotterWithDefaults
from typing import Any, Callable, Union
from unittest.mock import patch

import os
import pytest


@pytest.mark.timeout(2)
def test_snapshot(snapshotter_creator: Callable[..., SnapshotterWithDefaults]) -> None:
    snapshotter = snapshotter_creator()
    samples: dict[Union[str, Path], str] = {
        "foo": "foobar",
        "foo2": "foobar",
        "foobig": "foobar" * EMBEDDED_FILE_SIZE,
        "foobig2": "foobar" * EMBEDDED_FILE_SIZE,
    }
    with snapshotter.lock:
        # Start with empty
        assert snapshotter.snapshot(progress=Progress()) == 0
        src = snapshotter.src
        dst = snapshotter.dst
        assert not (dst / "foo").is_file()

        # Create files in src, run snapshot
        snapshotter.create_samples(samples=samples)
        ss2 = snapshotter.get_snapshot_state()

        assert (dst / "foo").is_file()
        assert (dst / "foo").read_text() == "foobar"
        assert (dst / "foo2").read_text() == "foobar"

        hashes = snapshotter.get_snapshot_hashes()
        assert len(hashes) == 1
        assert hashes == [
            SnapshotHash(hexdigest="c6479bce75c9a573ba073af83191c280721170793da6e9e9480201de94ab0654", size=900)
        ]

        while True:
            (src / "foo").write_text("barfoo")  # same length
            if snapshotter.snapshot(progress=Progress()) > 0:
                # Sometimes fails on first iteration(s) due to same mtime
                # (inaccurate timestamps)
                break
        ss3 = snapshotter.get_snapshot_state()
        assert ss2 != ss3
        assert snapshotter.snapshot(progress=Progress()) == 0
        assert (dst / "foo").is_file()
        assert (dst / "foo").read_text() == "barfoo"

        # Remove file from src, run snapshot
        for filename in ["foo", "foo2", "foobig", "foobig2"]:
            (src / filename).unlink()
            assert snapshotter.snapshot(progress=Progress()) > 0
            assert snapshotter.snapshot(progress=Progress()) == 0
            assert not (dst / filename).is_file()

        # Now shouldn't have any data hashes
        hashes_empty = snapshotter.get_snapshot_hashes()
        assert not hashes_empty

    with pytest.raises(AssertionError):
        snapshotter.snapshot(progress=Progress())

    with pytest.raises(AssertionError):
        snapshotter.get_snapshot_state()

    with pytest.raises(AssertionError):
        snapshotter.get_snapshot_hashes()


@pytest.mark.parametrize("test", [(os, "link", 1, 1), (None, "_snapshotfile_from_path", 3, 0)])
def test_snapshot_error_filenotfound(
    snapshotter_creator: Callable[..., SnapshotterWithDefaults], test: tuple[Any, str, int, int]
) -> None:
    (obj, fun, exp_progress_1, exp_progress_2) = test

    def _not_really_found(*a: Any, **kw: Any) -> None:
        raise FileNotFoundError

    snapshotter = snapshotter_creator()
    obj = obj or snapshotter
    with patch.object(obj, fun, new=_not_really_found):
        (snapshotter.src / "foo").write_text("foobar")
        (snapshotter.src / "bar").write_text("foobar")
        with snapshotter.lock:
            progress = Progress()
            assert snapshotter.snapshot(progress=progress) == exp_progress_1
            progress = Progress()
            assert snapshotter.snapshot(progress=progress) == exp_progress_2


@pytest.mark.timeout(2)
def test_snapshot_single_file_size(snapshotter_creator: Callable[..., SnapshotterWithDefaults]) -> None:
    snapshotter = snapshotter_creator(min_delta_file_size=1024 * 1024)
    samples: dict[Union[str, Path], str] = {
        "embed1": "foobar",
        "embed2": "foobar",
        "bundle1": "foobar" * EMBEDDED_FILE_SIZE,
        "bundle2": "foobar" * EMBEDDED_FILE_SIZE,
        "big1": "x" * 2 * 1024 * 1024,
        "big2": "y" * 1 * 1024 * 1024,
    }
    with snapshotter.lock:
        snapshotter.snapshot(progress=Progress())
        snapshotter.create_samples(samples=samples)

        hashes = snapshotter.get_snapshot_hashes()
        assert all(Path(file_name) in snapshotter.relative_path_to_snapshotfile for file_name in ["bundle1", "bundle2"])

        for file_name, snapshot_file in snapshotter.relative_path_to_snapshotfile.items():
            assert snapshot_file.should_be_bundled == (str(file_name) in ["bundle1", "bundle2"])

        assert len(hashes) == 2
        assert hashes == [
            SnapshotHash(hexdigest="d7e01e55405fb81256298fb37916f090bee99b274d0b9fdfc8c6ea6a0dc7797e", size=2097152),
            SnapshotHash(hexdigest="55924e2033f99b59100385820daeaa2623cbf4a2061831dc44be63506c8a255a", size=1048576),
        ]
        # Create two more files, one of which should be bundled and another one should be a usual delta hash file
        snapshotter.create_samples(samples={"bundle3": "1" * (1024 * 1024 - 1)})
        snapshotter.create_samples(samples={"big3": "2" * (1024 * 1024)})
        snapshotter.snapshot()

        hashes = snapshotter.get_snapshot_hashes()
        bundled_file = snapshotter.relative_path_to_snapshotfile.get(Path("bundle3"))
        assert bundled_file is not None and bundled_file.should_be_bundled and not bundled_file.hexdigest
        hexdigest_file = snapshotter.relative_path_to_snapshotfile.get(Path("big3"))
        assert hexdigest_file is not None and not hexdigest_file.should_be_bundled and hexdigest_file.hexdigest

        assert len(hashes) == 3
        assert hashes == [
            SnapshotHash(hexdigest="d7e01e55405fb81256298fb37916f090bee99b274d0b9fdfc8c6ea6a0dc7797e", size=2097152),
            SnapshotHash(hexdigest="55924e2033f99b59100385820daeaa2623cbf4a2061831dc44be63506c8a255a", size=1048576),
            SnapshotHash(hexdigest="4ac533296ea373a0bdbe5f1ae8fda6b2e908399a528a5e10fe2eca3ed058403f", size=1048576),
        ]


def test_snapshot_error_when_required_files_not_found(snapshotter_creator: Callable[..., SnapshotterWithDefaults]) -> None:
    def src_iterate_func() -> list[Union[AnyPath, BackupPath]]:
        return [
            BackupPath(path=snapshotter.src / "foo", missing_ok=False),
            BackupPath(path=snapshotter.src / "bar"),
            Path(snapshotter.src / "foo_path"),
            Path(snapshotter.src / "bar_path"),
            os.path.join(snapshotter.src / "foo_str_path"),
            os.path.join(snapshotter.src / "bar_str_path"),
        ]

    snapshotter = snapshotter_creator(src_iterate_func=src_iterate_func)
    (snapshotter.src / "bar").write_text("foobar")
    (snapshotter.src / "bar_path").write_text("bar_path_text")
    (snapshotter.src / "bar_str_path").write_text("bar_str_path_text")

    with snapshotter.lock:
        with pytest.raises(FileNotFoundError):
            snapshotter.snapshot(progress=Progress())

        (snapshotter.src / "foo").write_text("foobar")
        assert snapshotter.snapshot(progress=Progress())

        def validate_snapshot() -> None:
            state = snapshotter.get_snapshot_state()
            assert len(state.files) == 4
            expected_paths = ["bar", "bar_path", "bar_str_path", "foo"]
            # Files are sorted, so we can rely on that
            for idx, sp in enumerate(state.files):
                assert sp.relative_path.name == expected_paths[idx]
                if sp.relative_path.name == "foo":
                    assert not sp.missing_ok
                else:
                    assert sp.missing_ok

        validate_snapshot()

        orig_open_for_reading = SnapshotFile.open_for_reading

        def fake_open_for_reading(self: SnapshotFile, path: Path) -> SizeLimitedFile:
            if self.relative_path.name == "foo":
                raise FileNotFoundError()
            return orig_open_for_reading(self, path)

        # Required file disappeared during hash calculation
        # should succeed if we re-use snapshot files from previous snapshot, as there will be no new snapshot files
        # created
        with patch.object(SnapshotFile, "open_for_reading", new=fake_open_for_reading):
            snapshotter.snapshot(progress=Progress(), reuse_old_snapshotfiles=True)
        validate_snapshot()

        # Should fail when files are not re-used and required file is missing
        with patch.object(SnapshotFile, "open_for_reading", new=fake_open_for_reading):
            with pytest.raises(FileNotFoundError):
                snapshotter.snapshot(progress=Progress(), reuse_old_snapshotfiles=False)

        # Should fail when files disappeared before hash calculation
        with patch("rohmu.delta.snapshot.Path.stat", side_effect=FileNotFoundError):
            with pytest.raises(FileNotFoundError):
                snapshotter.snapshot(progress=Progress(), reuse_old_snapshotfiles=True)


@pytest.mark.timeout(2)
def test_snapshot_with_callback(snapshotter_creator: Callable[..., SnapshotterWithDefaults]) -> None:
    snapshotter = snapshotter_creator()
    callback_messages: list[str] = []

    def progress_callback(message: ProgressStep, progress_metrics: ProgressMetrics) -> None:
        callback_message = f"{message.value}: {progress_metrics['handled']}"
        callback_messages.append(callback_message)

    samples: dict[Union[str, Path], str] = {
        "foo": "foobar",
        "foo2": "foobar",
        "foobig": "foobar" * EMBEDDED_FILE_SIZE,
        "foobig2": "foobar" * EMBEDDED_FILE_SIZE,
    }

    src = snapshotter.src
    for file_name, body in samples.items():
        (src / file_name).write_text(body)

    with snapshotter.lock:
        progress = Progress()
        changes_detected = snapshotter.snapshot(progress=progress, progress_callback=progress_callback)
        assert changes_detected > 0

        ss1 = snapshotter.get_snapshot_state()

        progress = Progress()
        assert snapshotter.snapshot(progress=progress, progress_callback=progress_callback) == 0

        ss2 = snapshotter.get_snapshot_state()
        assert ss1 == ss2
        expected_messages = [
            "creating_missing_directories: 1",
            "adding_missing_files: 3",
            "processing_and_hashing_snapshot_files: 4",
            "processing_and_hashing_snapshot_files: 5",
            "processing_and_hashing_snapshot_files: 6",
            "processing_and_hashing_snapshot_files: 7",
            "creating_missing_directories: 1",
            "adding_missing_files: 3",
        ]

        assert callback_messages == expected_messages
