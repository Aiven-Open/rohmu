# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/

from io import BytesIO
from tempfile import NamedTemporaryFile

import pytest

from rohmu import rohmufile
from rohmu.errors import InvalidConfigurationError


def test_fileobj_name(tmpdir):
    with NamedTemporaryFile(dir=tmpdir, suffix="foo") as raw_output_obj:
        result = rohmufile._fileobj_name(raw_output_obj)  # pylint: disable=protected-access
        assert result.startswith("open file ")
        assert "foo" in result


def test_get_encryption_key_data_no_metadata():
    assert rohmufile._get_encryption_key_data(None, None) is None  # pylint: disable=protected-access
    assert rohmufile._get_encryption_key_data({}, None) is None  # pylint: disable=protected-access


def test_get_encryption_key_data_invalid_configuration():
    metadata = {"encryption-key-id": "foo"}
    with pytest.raises(InvalidConfigurationError, match="File is encrypted with key 'foo' but key not found"):
        rohmufile._get_encryption_key_data(metadata, lambda key_id: None)  # pylint: disable=protected-access


def test_get_encryption_key_data():
    def _getkey(key_id):
        assert key_id == "foo"
        return "bar"

    metadata = {"encryption-key-id": "foo"}
    key_data = rohmufile._get_encryption_key_data(metadata, _getkey)  # pylint: disable=protected-access
    assert key_data == "bar"


def test_file_reader_no_metadata():
    fileobj = BytesIO(b"foo")
    assert rohmufile.file_reader(fileobj=fileobj) == fileobj


def test_file_reader_no_key():
    fileobj = BytesIO(b"foo")
    metadata = {"encryption-key-id": "foo"}
    with pytest.raises(InvalidConfigurationError, match="File is encrypted with key 'foo' but key not found"):
        rohmufile.file_reader(fileobj=fileobj, metadata=metadata)


def test_file_reader_no_encryption_compression():
    fileobj = BytesIO(b"foo")
    metadata = {"a": "b"}
    assert rohmufile.file_reader(fileobj=fileobj, metadata=metadata) == fileobj
