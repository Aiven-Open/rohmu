# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/

from io import BytesIO
from rohmu import rohmufile
from rohmu.errors import InvalidConfigurationError
from tempfile import NamedTemporaryFile
from typing import Any

import pytest


def test_fileobj_name(tmpdir: Any) -> None:
    with NamedTemporaryFile(dir=tmpdir, suffix="foo") as raw_output_obj:
        result = rohmufile._fileobj_name(raw_output_obj)  # type: ignore# pylint: disable=protected-access
        assert result.startswith("open file ")
        assert "foo" in result


def test_get_encryption_key_data_no_metadata() -> None:
    assert rohmufile._get_encryption_key_data(None, None) is None  # pylint: disable=protected-access
    assert rohmufile._get_encryption_key_data({}, None) is None  # pylint: disable=protected-access


def test_get_encryption_key_data_invalid_configuration() -> None:
    metadata = {"encryption-key-id": "foo"}
    with pytest.raises(InvalidConfigurationError, match="File is encrypted with key 'foo' but key not found"):
        rohmufile._get_encryption_key_data(metadata, lambda key_id: None)  # pylint: disable=protected-access


def test_get_encryption_key_data() -> None:
    def _getkey(key_id: str) -> str:
        assert key_id == "foo"
        return "bar"

    metadata = {"encryption-key-id": "foo"}
    key_data = rohmufile._get_encryption_key_data(metadata, _getkey)  # pylint: disable=protected-access
    assert key_data == "bar"


def test_file_reader_no_metadata() -> None:
    fileobj = BytesIO(b"foo")
    assert rohmufile.file_reader(fileobj=fileobj) == fileobj


def test_file_reader_no_key() -> None:
    fileobj = BytesIO(b"foo")
    metadata = {"encryption-key-id": "foo"}
    with pytest.raises(InvalidConfigurationError, match="File is encrypted with key 'foo' but key not found"):
        rohmufile.file_reader(fileobj=fileobj, metadata=metadata)


def test_file_reader_no_encryption_compression() -> None:
    fileobj = BytesIO(b"foo")
    metadata = {"a": "b"}
    assert rohmufile.file_reader(fileobj=fileobj, metadata=metadata) == fileobj
