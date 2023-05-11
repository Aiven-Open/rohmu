from datetime import datetime
from io import BytesIO
from pathlib import Path
from rohmu import errors
from rohmu.object_storage.local import LocalTransfer
from typing import Any

import pytest

DUMMY_CONTENT = b"dummy"
DUMMY_METADATA = {"Content-Length": str(len(DUMMY_CONTENT))}


@pytest.mark.parametrize("transfer_type", ["local_transfer"])
def test_nonexistent(transfer_type: str, request: Any) -> None:
    transfer = request.getfixturevalue(transfer_type)
    with pytest.raises(errors.FileNotFoundFromStorageError):
        transfer.get_metadata_for_key("NONEXISTENT")
    with pytest.raises(errors.FileNotFoundFromStorageError):
        transfer.delete_key("NONEXISTENT")
    with pytest.raises(errors.FileNotFoundFromStorageError):
        transfer.get_contents_to_file("NONEXISTENT", "nonexistent/a")
    with pytest.raises(errors.FileNotFoundFromStorageError):
        transfer.get_contents_to_fileobj("NONEXISTENT", BytesIO())
    with pytest.raises(errors.FileNotFoundFromStorageError):
        transfer.get_contents_to_string("NONEXISTENT")
    assert transfer.list_path("") == []
    assert transfer.list_path("NONEXISTENT") == []


@pytest.mark.parametrize("transfer_type", ["local_transfer"])
def test_basic_upload(transfer_type: str, tmp_path: Path, request: Any) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    transfer = request.getfixturevalue(transfer_type)
    sent_metadata = {"k": "v"}
    metadata = DUMMY_METADATA.copy()
    metadata.update(sent_metadata)
    transfer.store_file_from_memory("x1", DUMMY_CONTENT, sent_metadata)

    assert transfer.get_contents_to_string("x1") == (DUMMY_CONTENT, metadata)
    # Same thing, but with a key looking like a directory
    transfer.store_file_from_memory("NONEXISTENT-DIR/x1", DUMMY_CONTENT, None)
    assert transfer.get_contents_to_string("NONEXISTENT-DIR/x1") == (DUMMY_CONTENT, DUMMY_METADATA)

    # Same thing, but from disk now
    dummy_file = scratch / "a"
    with open(dummy_file, "wb") as fp:
        fp.write(DUMMY_CONTENT)
    transfer.store_file_from_disk("test1/x1", dummy_file, None)
    out = BytesIO()

    assert transfer.get_contents_to_fileobj("test1/x1", out) == DUMMY_METADATA
    assert out.getvalue() == DUMMY_CONTENT


@pytest.mark.parametrize("transfer_type", ["local_transfer"])
def test_copy(transfer_type: str, request: Any) -> None:
    transfer = request.getfixturevalue(transfer_type)
    sent_metadata = {"k": "v"}
    metadata = DUMMY_METADATA.copy()
    metadata.update(sent_metadata)
    transfer.store_file_from_memory("dummy", DUMMY_CONTENT, sent_metadata)
    transfer.copy_file(source_key="dummy", destination_key="dummy_copy")
    assert transfer.get_contents_to_string("dummy_copy") == (DUMMY_CONTENT, metadata)

    # Same thing, but with different metadata
    transfer.copy_file(source_key="dummy", destination_key="dummy_copy_metadata", metadata={"new_k": "new_v"})
    assert transfer.get_contents_to_string("dummy_copy_metadata") == (DUMMY_CONTENT, {"new_k": "new_v"})


@pytest.mark.parametrize("transfer_type", ["local_transfer"])
def test_list(transfer_type: str, request: Any) -> None:
    transfer = request.getfixturevalue(transfer_type)
    assert transfer.list_path("") == []

    # Test with a single file at root
    sent_metadata = {"k": "v"}
    metadata = DUMMY_METADATA.copy()
    metadata.update(sent_metadata)
    transfer.store_file_from_memory("dummy", DUMMY_CONTENT, metadata=sent_metadata)
    file_list = transfer.list_path("")
    assert len(file_list) == 1
    assert file_list[0]["name"] == "dummy"
    assert file_list[0]["metadata"] == metadata
    assert file_list[0]["size"] == len("dummy")
    assert isinstance(file_list[0]["last_modified"], datetime)

    # Test with a "subdirectory"
    transfer.store_file_from_memory("dummydir/dummy", DUMMY_CONTENT, metadata=sent_metadata)
    assert len(transfer.list_path("")) == 1
    assert set(transfer.iter_prefixes("")) == {"dummydir"}
    assert len(transfer.list_path("dummydir")) == 1

    files = transfer.list_path("", deep=True)
    assert len(files) == 2
    assert set(f["name"] for f in files) == {"dummy", "dummydir/dummy"}


def test_hidden_local_files(local_transfer: LocalTransfer) -> None:
    """
    Local storage specific test.
    """
    storage_dir = Path(local_transfer.prefix)
    # Since we've never used the local storage, need to create the directory
    storage_dir.mkdir()
    # When creating the file manually, we need to create some metadata too.
    with open(Path(local_transfer.prefix) / ".null", "w"):
        pass
    with open(Path(local_transfer.prefix) / ".null.metadata", "w") as f:
        f.write('{"k": "v"}')
    assert local_transfer.list_path("") == []

    # Make sure the previous test actually worked, by manually creating a file
    # that must appear.
    with open(Path(local_transfer.prefix) / "somefile", "w"):
        pass
    with open(Path(local_transfer.prefix) / "somefile.metadata", "w") as f:
        f.write('{"k": "v"}')

    files = local_transfer.list_path("")
    assert len(files) == 1
    assert files[0]["name"] == "somefile"
