from pathlib import Path
from rohmu.atomic_opener import atomic_opener

import errno
import os
import pytest
import time


def _verify_file_not_created_and_dir_not_polluted(output_file: Path):
    assert os.listdir(output_file.parent) == []
    assert not output_file.exists()


def test_error_thrown_if_final_path_parent_doesnt_exist(tmp_path: Path):
    with pytest.raises(IOError):
        with atomic_opener(tmp_path / "nonexistingdir" / "final_path", mode="w"):
            pass


def test_error_mode_doesnt_contain_write(tmp_path: Path):
    with pytest.raises(ValueError):
        with atomic_opener(tmp_path, mode="r"):  # type: ignore
            pass


def test_file_is_atomically_created_only_after_function_execution_is_over(tmp_path: Path):
    data_block = "x" * 100_000_000
    # manually tested with block_count of 1000 but it seems overkill to do it every time and it can hog
    # the testing infra quite a bit.
    # block_count = 1000
    block_count = 1
    size = len(data_block)

    output_file = tmp_path / "something"
    try:
        _verify_file_not_created_and_dir_not_polluted(output_file)
        with atomic_opener(output_file, mode="w") as f:
            inode_inside = os.stat(f.fileno()).st_ino
            _verify_file_not_created_and_dir_not_polluted(output_file)
            for unused_counter in range(block_count):
                f.write(data_block)
                f.flush()
                _verify_file_not_created_and_dir_not_polluted(output_file)
            timestamp_before_exiting = time.monotonic()

        # this must be super-fast since atomic move is taking place. Makes more sense with
        # a large - 100ish - block count
        assert (time.monotonic() - timestamp_before_exiting) < 0.1
        assert output_file.exists()
        assert len(os.listdir(output_file.parent)) == 1
        assert output_file.stat().st_size == size * block_count
        assert output_file.stat().st_ino == inode_inside
    finally:
        # the file can be big, we want to delete it ASAP
        try:
            output_file.unlink()
        except FileNotFoundError:
            pass


def test_file_is_never_created_if_function_breaks(tmp_path: Path):
    output_file = tmp_path / "something"

    try:
        _verify_file_not_created_and_dir_not_polluted(output_file)
        with atomic_opener(output_file, mode="w") as f:
            _verify_file_not_created_and_dir_not_polluted(output_file)
            f.write("aaaaaaaaaa")
            f.flush()
            _verify_file_not_created_and_dir_not_polluted(output_file)
            time.sleep(1.0)
            _verify_file_not_created_and_dir_not_polluted(output_file)
            raise ValueError("crash")
        pytest.fail("codepath should never be taken")
    except ValueError:
        _verify_file_not_created_and_dir_not_polluted(output_file)


def test_file_is_fully_written_if_visible(tmp_path: Path):
    output_file = tmp_path / "something"

    def linkhook():
        assert output_file.exists()
        assert output_file.read_text() == "aaaaaaaaaa"

    try:
        _verify_file_not_created_and_dir_not_polluted(output_file)
        with atomic_opener(output_file, mode="w", _after_link_hook=linkhook) as f:
            _verify_file_not_created_and_dir_not_polluted(output_file)
            f.write("aaaaaaaaaa")
            _verify_file_not_created_and_dir_not_polluted(output_file)
            time.sleep(1.0)
            _verify_file_not_created_and_dir_not_polluted(output_file)

    except ValueError:
        _verify_file_not_created_and_dir_not_polluted(output_file)


def test_open_for_writing_text_opens_proper_encoding_file(tmp_path: Path):
    final_path = tmp_path / "file"
    with atomic_opener(final_path, encoding="iso-8859-1", mode="w") as f:
        f.write("à")
    assert final_path.read_bytes() == b"\xe0"


def test_open_for_writing_bytes_properly_writes_bytes(tmp_path: Path):
    final_path = tmp_path / "file"
    with atomic_opener(final_path, mode="wb") as f:
        f.write(b"\xe0")
    assert final_path.read_text("iso-8859-1") == "à"


def test_no_fd_leak_if_fdopen_fails_because_of_wrong_encoding(tmp_path: Path):
    final_path = tmp_path / "file"
    opened_fd: list[int] = []
    try:
        with atomic_opener(final_path, mode="w", encoding="unknownencoding", _fd_spy=opened_fd.append):
            pass
        pytest.fail("should fail, encoding is wrong")
    except LookupError:
        try:
            os.fstat(opened_fd[0])
            pytest.fail("should fail, file descriptor must be invalid")
        except OSError as e:
            if e.errno != errno.EBADF:
                raise
            # descriptor is invalid, all ok


def test_no_fd_leak_if_fdopen_fails_because_of_unknown_mode(tmp_path: Path):
    final_path = tmp_path / "file"
    opened_fd: list[int] = []
    try:
        with atomic_opener(final_path, mode="somethingrandomw", encoding="ascii", _fd_spy=opened_fd.append):
            pass
        pytest.fail("should fail, mode is wrong")
    except ValueError:
        try:
            os.fstat(opened_fd[0])
            pytest.fail("should fail, file descriptor must be invalid")
        except OSError as e:
            if e.errno != errno.EBADF:
                raise
            # descriptor is invalid, all ok
