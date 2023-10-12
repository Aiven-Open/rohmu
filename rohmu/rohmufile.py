"""
rohmu - rohmu data transformation interface

Copyright (c) 2016 Ohmu Ltd
See LICENSE for details
"""

from __future__ import annotations

from .common.constants import IO_BLOCK_SIZE
from .compressor import CompressionFile, DecompressionFile, DecompressSink
from .encryptor import DecryptorFile, DecryptSink, EncryptorFile
from .errors import InvalidConfigurationError
from .filewrap import ThrottleSink
from .typing import FileLike, HasRead, HasWrite, Metadata
from contextlib import suppress
from inspect import signature
from rohmu.object_storage.base import IncrementalProgressCallbackType
from typing import Any, Callable, Optional, Union

import time


def _obj_name(input_obj: Any) -> str:
    if hasattr(input_obj, "name"):
        name = getattr(input_obj, "name")
        return f"open file {repr(name)}"

    return repr(input_obj)


def _get_encryption_key_data(
    metadata: Optional[Metadata], key_lookup: Optional[Callable[[str], Optional[str]]]
) -> Optional[str]:
    if not metadata or not metadata.get("encryption-key-id"):
        return None

    key_id = metadata["encryption-key-id"]
    key_data = None
    if key_lookup:
        with suppress(KeyError):
            key_data = key_lookup(key_id)

    if not key_data:
        raise InvalidConfigurationError(f"File is encrypted with key {repr(key_id)} but key not found")
    return key_data


def file_reader(
    *,
    fileobj: FileLike,
    metadata: Optional[Metadata] = None,
    key_lookup: Optional[Callable[[str], Optional[str]]] = None,
) -> FileLike:
    if not metadata:
        return fileobj

    key_data = _get_encryption_key_data(metadata, key_lookup)
    if key_data:
        fileobj = DecryptorFile(fileobj, key_data)

    comp_alg = metadata.get("compression-algorithm")
    if comp_alg:
        fileobj = DecompressionFile(fileobj, comp_alg)

    return fileobj


def create_sink_pipeline(
    *,
    output: HasWrite,
    file_size: int = 0,
    metadata: Optional[Metadata] = None,
    key_lookup: Optional[Callable[[str], Optional[str]]] = None,
    throttle_time: float = 0.001,
) -> HasWrite:
    if throttle_time:
        output = ThrottleSink(output, throttle_time)

    comp_alg = metadata.get("compression-algorithm") if metadata else None
    if comp_alg:
        output = DecompressSink(output, comp_alg)

    key_data = _get_encryption_key_data(metadata, key_lookup)
    if key_data:
        output = DecryptSink(output, file_size, key_data)

    return output


def _callback_wrapper(progress_callback: IncrementalProgressCallbackType) -> IncrementalProgressCallbackType:
    # Gracefully support legacy callbacks which do not expect any arguments to be passed to them
    if progress_callback is None:
        return None
    sig = signature(progress_callback)
    if len(sig.parameters) == 0:
        return lambda f: progress_callback()  # type: ignore[misc,call-arg]
    return progress_callback


def read_file(
    *,
    input_obj: FileLike,
    output_obj: FileLike,
    metadata: Metadata,
    key_lookup: Optional[Callable[[str], Optional[str]]],
    progress_callback: IncrementalProgressCallbackType = None,
    log_func: Optional[Callable[..., None]] = None,
) -> tuple[int, int]:
    start_time = time.monotonic()
    progress_callback = _callback_wrapper(progress_callback)

    with file_reader(fileobj=input_obj, metadata=metadata, key_lookup=key_lookup) as fp_in:
        while True:
            input_data = fp_in.read(IO_BLOCK_SIZE)
            if not input_data:
                break

            output_obj.write(input_data)
            if progress_callback:
                progress_callback(len(input_data))

    original_size = input_obj.tell()
    result_size = output_obj.tell()

    if log_func:
        action = "Decompressed"
        if metadata.get("encryption-key-id"):
            action += " and decrypted"

        log_func(
            "%s %d bytes to %d bytes in %s, took: %.3fs",
            action,
            original_size,
            result_size,
            _obj_name(output_obj),
            time.monotonic() - start_time,
        )

    return original_size, result_size


def file_writer(
    *,
    fileobj: FileLike,
    compression_algorithm: Optional[str] = None,
    compression_level: int = 0,
    compression_threads: int = 0,
    rsa_public_key: Union[None, str, bytes] = None,
) -> FileLike:
    if rsa_public_key:
        fileobj = EncryptorFile(fileobj, rsa_public_key)

    if compression_algorithm:
        fileobj = CompressionFile(fileobj, compression_algorithm, compression_level, compression_threads)

    return fileobj


def write_file(
    *,
    input_obj: HasRead,
    output_obj: FileLike,
    progress_callback: IncrementalProgressCallbackType = None,
    compression_algorithm: Optional[str] = None,
    compression_level: int = 0,
    compression_threads: int = 0,
    rsa_public_key: Union[None, str, bytes] = None,
    log_func: Optional[Callable[..., None]] = None,
    header_func: Optional[Callable[[bytes], None]] = None,
    data_callback: Optional[Callable[[bytes], None]] = None,
) -> tuple[int, int]:
    start_time = time.monotonic()
    progress_callback = _callback_wrapper(progress_callback)

    original_size = 0
    with file_writer(
        fileobj=output_obj,
        compression_algorithm=compression_algorithm,
        compression_threads=compression_threads,
        compression_level=compression_level,
        rsa_public_key=rsa_public_key,
    ) as fp_out:
        header_block = True
        while True:
            input_data = input_obj.read(IO_BLOCK_SIZE)
            if not input_data:
                break

            if data_callback:
                data_callback(input_data)

            if header_block and header_func:
                header_func(input_data)
                header_block = False

            fp_out.write(input_data)
            original_size += len(input_data)
            if progress_callback:
                progress_callback(len(input_data))

    result_size = output_obj.tell()

    if log_func:
        log_compression_result(
            elapsed=time.monotonic() - start_time,
            encrypted=bool(rsa_public_key),
            log_func=log_func,
            original_size=original_size,
            result_size=result_size,
            source_name=_obj_name(input_obj),
        )

    return original_size, result_size


def log_compression_result(
    *, log_func: Callable[..., None], source_name: str, original_size: int, result_size: int, encrypted: bool, elapsed: float
) -> None:
    if original_size <= result_size:
        action = "Stored"
        ratio = ""
    else:
        action = "Compressed"
        ratio_value = result_size / original_size
        ratio = f" ({ratio_value:.0%})"

    if encrypted:
        action += " and encrypted"

    log_func("%s %d byte of %s to %d bytes%s, took: %.3fs", action, original_size, source_name, result_size, ratio, elapsed)
