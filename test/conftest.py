import pytest
from rohmu.object_storage.local import LocalTransfer

@pytest.fixture(name="local_transfer")
def local_transfer(tmp_path):
    return LocalTransfer(tmp_path / "local_storage")

