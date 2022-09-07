from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Callable, cast, ContextManager, Generator, Optional, overload, TextIO, TYPE_CHECKING, Union

# workaround < Python3.8 missing Literal.
# if we just use the try/except block, mypy will complain
# about the fact that Write* variables are being redefined.
# so we need to pour in an additional branch.
if TYPE_CHECKING:
    from typing import Literal

    Write = Literal["w"]
    WriteBinary = Literal["wb"]
    WriteTest = Literal["somethingrandomw"]
else:
    try:
        from typing import Literal

        Write = Literal["w"]
        WriteBinary = Literal["wb"]
        WriteTest = Literal["somethingrandomw"]
    except ImportError:
        from typing import Any

        Write = Any
        WriteBinary = Any
        WriteTest = Any


import errno
import os


def _fd_close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError as e:
        if e.errno == errno.EBADF:
            # closed already
            return
        raise


@overload
def atomic_opener(
    final_path: Path,
    mode: WriteBinary,
    encoding: Optional[str] = None,
    _fd_spy: Callable[[int], None] = lambda unused: None,
    _after_link_hook: Callable[[], None] = lambda: None,
) -> ContextManager[BinaryIO]:
    ...


@overload
def atomic_opener(
    final_path: Path,
    mode: Write,
    encoding: Optional[str] = None,
    _fd_spy: Callable[[int], None] = lambda unused: None,
    _after_link_hook: Callable[[], None] = lambda: None,
) -> ContextManager[TextIO]:
    ...


if TYPE_CHECKING:
    # necessary for testing or tests will fail type checking
    @overload
    def atomic_opener(
        final_path: Path,
        mode: WriteTest,
        encoding: Optional[str] = None,
        _fd_spy: Callable[[int], None] = lambda unused: None,
        _after_link_hook: Callable[[], None] = lambda: None,
    ) -> ContextManager[TextIO]:
        ...


def atomic_opener(
    final_path: Path,
    mode: str,
    encoding: Optional[str] = None,
    _fd_spy: Callable[[int], None] = lambda unused: None,
    _after_link_hook: Callable[[], None] = lambda: None,
) -> ContextManager[Union[TextIO, BinaryIO]]:
    return _atomic_opener(final_path, mode, encoding, _fd_spy, _after_link_hook)


@contextmanager
def _atomic_opener(
    final_path: Path,
    mode: str,
    encoding: Optional[str] = None,
    _fd_spy: Callable[[int], None] = lambda unused: None,
    _after_link_hook: Callable[[], None] = lambda: None,
) -> Generator[Union[TextIO, BinaryIO], None, None]:
    """
    Creates a file object for writing which will only appear on the filesystem if the context manager succeeds.

    It's designed to prevent partial writes (file will either be available with full content, or will be unavailable)
    and the need for manual cleanup.
    """
    parent_dir = final_path.parent
    if not parent_dir.exists():
        raise IOError(f"Parent directory '{parent_dir}' must exist but is missing")
    if "w" not in mode:
        raise ValueError("Write mode must be used to make actual sense")

    fd = os.open(str(parent_dir), os.O_TMPFILE | os.O_RDWR, 0o600)
    _fd_spy(fd)
    try:
        file_obj = os.fdopen(fd, mode=mode, encoding=encoding)
    except Exception:  # pylint: disable=broad-except
        # when passing wrong mode, os.fdopen won't close input fd. When passing wrong encoding, it will.
        _fd_close_quietly(fd)
        raise

    try:
        if "b" in mode:
            yield cast(BinaryIO, file_obj)
        else:
            yield cast(TextIO, file_obj)
        file_obj.flush()
        path = "/proc/self/fd/{0}".format(fd)
        os.link(path, str(final_path), src_dir_fd=0, follow_symlinks=True)
        _after_link_hook()
    finally:
        file_obj.close()
