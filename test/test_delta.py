# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/
import os
from pathlib import Path

import pytest

from rohmu.delta.common import EMBEDDED_FILE_SIZE, Progress, SnapshotHash


@pytest.mark.timeout(2)
def test_snapshot(snapshotter_creator):
    snapshotter = snapshotter_creator()
    samples = {
        "foo": "foobar",
        "foo2": "foobar",
        "foobig": "foobar" * EMBEDDED_FILE_SIZE,
        "foobig2": "foobar" * EMBEDDED_FILE_SIZE
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
def test_snapshot_error_filenotfound(snapshotter_creator, mocker, test):
    (obj, fun, exp_progress_1, exp_progress_2) = test

    def _not_really_found(*a, **kw):
        raise FileNotFoundError

    snapshotter = snapshotter_creator()
    obj = obj or snapshotter
    mocker.patch.object(obj, fun, new=_not_really_found)
    (snapshotter.src / "foo").write_text("foobar")
    (snapshotter.src / "bar").write_text("foobar")
    with snapshotter.lock:
        progress = Progress()
        assert snapshotter.snapshot(progress=progress) == exp_progress_1
        progress = Progress()
        assert snapshotter.snapshot(progress=progress) == exp_progress_2


@pytest.mark.timeout(2)
def test_snapshot_single_file_size(snapshotter_creator):
    snapshotter = snapshotter_creator(min_delta_file_size=1024 * 1024)
    samples = {
        "embed1": "foobar",
        "embed2": "foobar",
        "bundle1": "foobar" * EMBEDDED_FILE_SIZE,
        "bundle2": "foobar" * EMBEDDED_FILE_SIZE,
        "big1": "x" * 2 * 1024 * 1024,
        "big2": "y" * 1 * 1024 * 1024
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
        assert bundled_file.should_be_bundled and not bundled_file.hexdigest
        hexdigest_file = snapshotter.relative_path_to_snapshotfile.get(Path("big3"))
        assert not hexdigest_file.should_be_bundled and hexdigest_file.hexdigest

        assert len(hashes) == 3
        assert hashes == [
            SnapshotHash(hexdigest="d7e01e55405fb81256298fb37916f090bee99b274d0b9fdfc8c6ea6a0dc7797e", size=2097152),
            SnapshotHash(hexdigest="55924e2033f99b59100385820daeaa2623cbf4a2061831dc44be63506c8a255a", size=1048576),
            SnapshotHash(hexdigest="4ac533296ea373a0bdbe5f1ae8fda6b2e908399a528a5e10fe2eca3ed058403f", size=1048576),
        ]
