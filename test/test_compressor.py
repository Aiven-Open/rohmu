from rohmu.compressor import CompressionFile, CompressionStream, DecompressionFile, DecompressSink
from rohmu.typing import CompressionAlgorithm
from typing import Final

import io
import math
import pytest
import random
import string

SAMPLE_BYTES: Final[bytes] = b"Some contents"


@pytest.mark.parametrize("algorithm", ["lzma", "snappy", "zstd"])
@pytest.mark.parametrize("contents", [b"", 100 * SAMPLE_BYTES], ids=["empty", "sample-bytes"])
def test_compress_decompress_simple_file(algorithm: CompressionAlgorithm, contents: bytes) -> None:
    bio = io.BytesIO()
    ef = CompressionFile(bio, algorithm=algorithm)
    ef.write(contents)
    ef.close()
    bio.seek(0)

    df = DecompressionFile(bio, algorithm=algorithm)
    data = df.read()
    assert data == contents


@pytest.mark.skip(reason="neither snappy nor zstd seem to handle multiple chunks")
@pytest.mark.parametrize("algorithm", ["lzma", "snappy", "zstd"])
def test_compress_decompress_multiple_chunks(algorithm: CompressionAlgorithm) -> None:
    contents = "".join(random.choices(string.ascii_letters + string.digits, k=1_000_000)).encode()
    num_bytes = len(contents)
    print(f"Data size exponent (block size = 20): {math.log2(num_bytes)}")
    bytes_buf = io.BytesIO()
    ef = CompressionFile(bytes_buf, algorithm=algorithm)
    ef.write(contents)
    ef.close()

    bytes_buf.seek(0)
    df = DecompressionFile(bytes_buf, algorithm=algorithm)
    data = df.read()
    assert data == contents


@pytest.mark.parametrize("algorithm", ["lzma", "snappy", "zstd"])
@pytest.mark.parametrize("contents", [b"", 100 * SAMPLE_BYTES], ids=["empty", "sample-bytes"])
def test_compress_decompress_streaming(algorithm: CompressionAlgorithm, contents: bytes) -> None:
    input_buffer = io.BytesIO()
    input_buffer.write(contents)
    input_buffer.seek(0)
    compression_stream = CompressionStream(input_buffer, algorithm)
    compressed_bytes = compression_stream.read()
    assert compression_stream.tell() == len(compressed_bytes)

    output_buffer = io.BytesIO()
    decompression_sink = DecompressSink(output_buffer, algorithm)
    num_bytes_written = decompression_sink.write(compressed_bytes)
    assert num_bytes_written == len(compressed_bytes)
    output_buffer.seek(0)
    output_data = output_buffer.read()
    assert output_data == contents
