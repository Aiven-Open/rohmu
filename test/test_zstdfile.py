# Copyright (c) 2025 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
from rohmu import zstdfile

import io


def test_compress_and_decompress() -> None:
    """Test basic compression and decompression"""
    original_data = b"Hello, World! " * 10_000

    compressed_buffer = io.BytesIO()
    with zstdfile.open(compressed_buffer, "wb", level=3) as zf:
        written = zf.write(original_data)
        assert written == len(original_data)

    compressed_buffer.seek(0)
    decompressed_data = b""
    with zstdfile.open(compressed_buffer, "rb") as zf:
        chunk = zf.read(512)
        assert len(chunk) <= 512
        while chunk:
            decompressed_data += chunk
            chunk = zf.read(512)

    assert decompressed_data == original_data
