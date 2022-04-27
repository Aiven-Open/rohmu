import pytest
from rohmu.object_storage.local import LocalTransfer
from rohmu.delta.snapshot import Snapshotter
from rohmu.delta.common import EMBEDDED_FILE_SIZE, Progress

@pytest.fixture(name="local_transfer")
def local_transfer(tmp_path):
    return LocalTransfer(tmp_path / "local_storage")

class SnapshotterWithDefaults(Snapshotter):
    def create_4foobar(self):
        (self.src / "foo").write_text("foobar")
        (self.src / "foo2").write_text("foobar")
        (self.src / "foobig").write_text("foobar" * EMBEDDED_FILE_SIZE)
        (self.src / "foobig2").write_text("foobar" * EMBEDDED_FILE_SIZE)
        progress = Progress()
        assert self.snapshot(progress=progress) > 0
        ss1 = self.get_snapshot_state()
        assert self.snapshot(progress=Progress()) == 0
        ss2 = self.get_snapshot_state()
        print("ss1", ss1)
        print("ss2", ss2)
        assert ss1 == ss2


@pytest.fixture(name="snapshotter")
def fixture_snapshotter(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    dst = tmp_path / "dst"
    dst.mkdir()
    yield SnapshotterWithDefaults(src=src, dst=dst, globs=["*"], parallel=1)
