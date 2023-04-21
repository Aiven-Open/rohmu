from os import PathLike
from typing import Any, Union

Metadata = dict[str, Any]

AnyPath = Union[str, bytes, PathLike[str], PathLike[bytes]]
