import pytest
from conftest import local_transfer
from rohmu import errors
from io import BytesIO

@pytest.mark.parametrize("transfer",
                         ["local_transfer"])
def test_nonexistent(transfer, request):
    transfer = request.getfixturevalue(transfer)
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

@pytest.mark.parametrize("transfer",
                         ["local_transfer"])
def test_basic_upload(transfer, tmp_path, request):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    transfer = request.getfixturevalue(transfer)
    transfer.store_file_from_memory("x1", b"dummy", {"k": "v"})
    assert transfer.get_contents_to_string("x1") == (b"dummy", {"k": "v"})
    # Same thing, but with a key looking like a directory
    transfer.store_file_from_memory("NONEXISTENT-DIR/x1", b"dummy", None)
    transfer.get_contents_to_string("x1") == (b"dummy", None)

    # Same thing, but from disk now
    dummy_file= scratch / "a"
    with open(dummy_file, "wb") as fp:
        fp.write(b"dummy")
    transfer.store_file_from_disk("test1/x1", dummy_file, None)
    out = BytesIO()

    assert transfer.get_contents_to_fileobj("test1/x1", out) == {}
    assert out.getvalue() == b"dummy"
