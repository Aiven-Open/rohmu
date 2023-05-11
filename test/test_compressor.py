from rohmu.compressor import CompressionFile, DecompressionFile

import io
import pytest


@pytest.mark.parametrize(
    "algorithm,contents",
    [
        ("lzma", b""),
        ("snappy", b""),
        ("lzma", b"Some contents"),
        ("snappy", b"Some contents"),
    ],
)
def test_compress_decompress_simple_file(algorithm: str, contents: bytes) -> None:
    bio = io.BytesIO()
    ef = CompressionFile(bio, algorithm=algorithm)
    ef.write(contents)
    ef.close()
    bio.seek(0)

    df = DecompressionFile(bio, algorithm=algorithm)
    data = df.read()
    assert data == contents
