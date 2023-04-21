from pathlib import Path
from rohmu.delta.common import Progress
from rohmu.delta.snapshot import Snapshotter
from rohmu.object_storage.local import LocalTransfer
from typing import Dict

import pytest


@pytest.fixture(name="local_transfer")
def local_transfer(tmp_path):
    return LocalTransfer(tmp_path / "local_storage")


class SnapshotterWithDefaults(Snapshotter):
    def create_samples(self, samples: Dict[Path, str]) -> None:
        for file_name, body in samples.items():
            (self.src / file_name).write_text(body)
        progress = Progress()
        assert self.snapshot(progress=progress) > 0
        ss1 = self.get_snapshot_state()
        assert self.snapshot(progress=Progress()) == 0
        ss2 = self.get_snapshot_state()
        print("ss1", ss1)
        print("ss2", ss2)
        assert ss1 == ss2


@pytest.fixture(name="snapshotter_creator")
def fixture_snapshotter_creator(tmp_path):
    def create_snapshotter(**kwargs):
        src = tmp_path / "src"
        src.mkdir()
        dst = tmp_path / "dst"
        dst.mkdir()
        return SnapshotterWithDefaults(src=src, dst=dst, globs=["*"], parallel=1, **kwargs)

    return create_snapshotter
