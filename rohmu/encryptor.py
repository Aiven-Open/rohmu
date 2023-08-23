"""
rohmu - content encryption

Copyright (c) 2016 Ohmu Ltd
See LICENSE for details
"""
from .common.constants import IO_BLOCK_SIZE
from .errors import UninitializedError
from .filewrap import FileWrap, Sink, Stream
from .typing import BinaryData, FileLike, HasRead, HasWrite
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, CipherContext, modes
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from typing import Optional, Union

import io
import logging
import os
import struct

FILEMAGIC = b"pghoa1"
AES_BLOCK_SIZE = 16


class EncryptorError(Exception):
    """EncryptorError"""


class Encryptor:
    def __init__(self, rsa_public_key_pem: Union[str, bytes]):
        if not isinstance(rsa_public_key_pem, bytes):
            rsa_public_key_pem = rsa_public_key_pem.encode("ascii")
        public_key = serialization.load_pem_public_key(rsa_public_key_pem, backend=default_backend())
        assert isinstance(public_key, RSAPublicKey)
        self.rsa_public_key = public_key
        self._cipher: Optional[CipherContext] = None
        self._authenticator: Optional[HMAC] = None

    @property
    def cipher(self) -> CipherContext:
        if self._cipher is None:
            raise UninitializedError("cipher not initialized")
        return self._cipher

    @property
    def authenticator(self) -> HMAC:
        if self._authenticator is None:
            raise UninitializedError("authenticator not initialized")
        return self._authenticator

    def update(self, data: bytes) -> bytes:
        ret = b""
        if self._cipher is None:
            key = os.urandom(16)
            nonce = os.urandom(16)
            auth_key = os.urandom(32)
            self._cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend()).encryptor()
            self._authenticator = HMAC(auth_key, SHA256(), backend=default_backend())
            pad = padding.OAEP(mgf=padding.MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None)
            cipherkey = self.rsa_public_key.encrypt(key + nonce + auth_key, pad)
            ret = FILEMAGIC + struct.pack(">H", len(cipherkey)) + cipherkey
        cur = self.cipher.update(data)
        self.authenticator.update(cur)
        if ret:
            return ret + cur
        else:
            return cur

    def finalize(self) -> bytes:
        if self._cipher is None:
            return b""  # empty plaintext input yields empty encrypted output

        ret = self.cipher.finalize()
        self.authenticator.update(ret)
        ret += self.authenticator.finalize()
        self._cipher = None
        self._authenticator = None
        return ret


class EncryptorFile(FileWrap):
    def __init__(self, next_fp: FileLike, rsa_public_key_pem: Union[str, bytes]) -> None:
        super().__init__(next_fp)
        self.key = rsa_public_key_pem
        self._encryptor: Optional[Encryptor] = Encryptor(self.key)
        self.offset = 0
        self.state = "OPEN"

    @property
    def encryptor(self) -> Encryptor:
        if self._encryptor is None:
            raise UninitializedError("encryptor was not initialized")
        return self._encryptor

    def flush(self) -> None:
        self._check_not_closed()
        self.next_fp.flush()

    def close(self) -> None:
        if self.state == "CLOSED":
            return
        final = self.encryptor.finalize()
        self.next_fp.write(final)
        super().close()
        self._encryptor = None

    def writable(self) -> bool:
        """True if this stream supports writing"""
        self._check_not_closed()
        return True

    def write(self, data: BinaryData) -> int:  # type: ignore [override]
        """Encrypt and write the given bytes"""
        self._check_not_closed()
        if not data:
            return 0
        data_as_bytes = bytes(data)
        enc_data = self.encryptor.update(data_as_bytes)
        self.next_fp.write(enc_data)
        self.offset += len(data_as_bytes)
        return len(data_as_bytes)


class EncryptorStream(Stream):
    """Non-seekable stream of data that adds encryption on top of given source stream"""

    def __init__(self, src_fp: HasRead, rsa_public_key_pem: Union[str, bytes]) -> None:
        super().__init__(src_fp)
        self._encryptor = Encryptor(rsa_public_key_pem)

    def _process_chunk(self, data: bytes) -> bytes:
        return self._encryptor.update(data)

    def _finalize(self) -> bytes:
        return self._encryptor.finalize()


class Decryptor:
    def __init__(self, rsa_private_key_pem: Union[str, bytes]) -> None:
        if not isinstance(rsa_private_key_pem, bytes):
            rsa_private_key_pem = rsa_private_key_pem.encode("ascii")
        self.rsa_private_key = serialization.load_pem_private_key(
            data=rsa_private_key_pem, password=None, backend=default_backend()
        )
        self._cipher: Optional[CipherContext] = None
        self._authenticator: Optional[HMAC] = None
        self._cipher_key_len = None
        self._header_size = None
        self._footer_size = 32

    @property
    def authenticator(self) -> HMAC:
        if self._authenticator is None:
            raise UninitializedError("authenticator not initialized")
        return self._authenticator

    @property
    def cipher(self) -> CipherContext:
        if self._cipher is None:
            raise UninitializedError("cipher not initialized")
        return self._cipher

    def expected_header_bytes(self) -> int:
        if self._header_size is not None:
            return 0
        return self._cipher_key_len or 8

    def header_size(self) -> int:
        if self._header_size is None:
            raise UninitializedError("header_size not initialized")
        return self._header_size

    def footer_size(self) -> int:
        return self._footer_size

    def process_header(self, data: bytes) -> None:
        if self._cipher_key_len is None:
            if data[0:6] != FILEMAGIC:
                raise EncryptorError("Invalid magic bytes")
            self._cipher_key_len = struct.unpack(">H", data[6:8])[0]
        else:
            pad = padding.OAEP(mgf=padding.MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None)
            try:
                plainkey = self.rsa_private_key.decrypt(data, pad)
            except AssertionError:
                raise EncryptorError("Decrypting key data failed")
            if len(plainkey) != 64:
                raise EncryptorError("Integrity check failed")
            key = plainkey[0:16]
            nonce = plainkey[16:32]
            auth_key = plainkey[32:64]
            self._header_size = 8 + len(data)

            self._cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend()).decryptor()
            self._authenticator = HMAC(auth_key, SHA256(), backend=default_backend())

    def process_data(self, data: bytes) -> bytes:
        if not data:
            return b""
        self.authenticator.update(data)
        return self.cipher.update(data)

    def finalize(self, footer: bytes) -> bytes:
        if footer != self.authenticator.finalize():
            raise EncryptorError("Integrity check failed")
        result = self.cipher.finalize()
        self._cipher = None
        self._authenticator = None
        return result


class DecryptorFile(FileWrap):
    def __init__(self, next_fp: FileLike, rsa_private_key_pem: Union[bytes, str]):
        super().__init__(next_fp)
        self._key = rsa_private_key_pem
        self.log = logging.getLogger(self.__class__.__name__)
        self._maybe_decryptor: Optional[Decryptor] = None
        self._maybe_crypted_size: Optional[int] = None
        self._maybe_plaintext_size: Optional[int] = None
        self._maybe_boundary_block: Optional[bytes] = None
        # Our actual plain-text read offset. seek may change self.offset to something
        # else temporarily but we keep _decrypt_offset intact until we actually do a
        # read in case the caller just called seek in order to then immediately seek back
        self._decrypt_offset = 0
        self.offset = 0
        self._reset()

    @property
    def _decryptor(self) -> Decryptor:
        if self._maybe_decryptor is None:
            raise UninitializedError("decryptor not initialized")
        return self._maybe_decryptor

    @property
    def _crypted_size(self) -> int:
        if self._maybe_crypted_size is None:
            raise UninitializedError("crypted_size not initialized")
        return self._maybe_crypted_size

    @property
    def _plaintext_size(self) -> int:
        if self._maybe_plaintext_size is None:
            raise UninitializedError("plaintext_size not initialized")
        return self._maybe_plaintext_size

    def _reset(self) -> None:
        self._maybe_decryptor = Decryptor(self._key)
        self._maybe_crypted_size = self._file_size(self.next_fp)
        self._maybe_boundary_block = None
        self._maybe_plaintext_size = None
        self._decrypt_offset = 0
        # Plaintext offset
        self.offset = 0
        self.state = "OPEN"

    @classmethod
    def _file_size(cls, file: FileLike) -> int:
        current_offset = file.seek(0, os.SEEK_SET)
        file_end_offset = file.seek(0, os.SEEK_END)
        file.seek(current_offset, os.SEEK_SET)
        return file_end_offset

    def _initialize_decryptor(self) -> None:
        if self._maybe_plaintext_size is not None:
            return
        while True:
            required_bytes = self._decryptor.expected_header_bytes()
            if not required_bytes:
                break
            self._decryptor.process_header(self._read_raw_exactly(required_bytes))
        self._maybe_plaintext_size = self._crypted_size - self._decryptor.header_size() - self._decryptor.footer_size()

    def _read_raw_exactly(self, required_bytes: int) -> bytes:
        data = self.next_fp.read(required_bytes)
        while data and len(data) < required_bytes:
            next_chunk = self.next_fp.read(required_bytes - len(data))
            if not next_chunk:
                break
            data += next_chunk
        if not data or len(data) != required_bytes:
            raise EncryptorError(f"Failed to read {required_bytes} bytes of header or footer data")
        return data

    def _move_decrypt_offset_to_plaintext_offset(self) -> None:
        if self._decrypt_offset == self.offset:
            return
        seek_to = self.offset
        if self._decrypt_offset > self.offset:
            self.log.warning("Negative seek from %d to %d, must re-initialize decryptor", self._decrypt_offset, self.offset)
            self._reset()
            self._initialize_decryptor()
        discard_bytes = seek_to - self._decrypt_offset
        self.offset = self._decrypt_offset
        while discard_bytes > 0:
            data = self._read_block(discard_bytes)
            discard_bytes -= len(data)

    def _read_all(self) -> bytes:
        full_data = bytearray()
        while True:
            data = self._read_block(IO_BLOCK_SIZE)
            if not data:
                return bytes(full_data)
            full_data.extend(data)

    def _read_block(self, size: int) -> bytes:
        if self._crypted_size == 0:
            return b""

        self._initialize_decryptor()

        if self.offset == self._plaintext_size:
            return b""

        self._move_decrypt_offset_to_plaintext_offset()

        # If we have an existing boundary block, fulfil the read entirely from that
        if self._maybe_boundary_block:
            boundary_block: bytes = self._maybe_boundary_block
            size = min(size, len(boundary_block) - self.offset % AES_BLOCK_SIZE)
            data = boundary_block[self.offset % AES_BLOCK_SIZE : self.offset % AES_BLOCK_SIZE + size]
            if self.offset % AES_BLOCK_SIZE + size == len(boundary_block):
                self._maybe_boundary_block = None
            data_len = len(data)
            self.offset += data_len
            self._decrypt_offset += data_len
            return data

        # Only serve multiples of AES_BLOCK_SIZE whenever possible to keep things simpler
        read_size = size
        if self.offset + max(AES_BLOCK_SIZE, size) >= self._plaintext_size:
            read_size = self._plaintext_size - self.offset
        elif size > AES_BLOCK_SIZE and size % AES_BLOCK_SIZE != 0 and self.offset + size < self._plaintext_size:
            read_size = size - size % AES_BLOCK_SIZE
        elif size < AES_BLOCK_SIZE:
            read_size = AES_BLOCK_SIZE

        encrypted = self._read_raw_exactly(read_size)
        decrypted = self._decryptor.process_data(encrypted)
        if self.offset + read_size == self._plaintext_size:
            footer = self._read_raw_exactly(self._decryptor.footer_size())
            last_part = self._decryptor.finalize(footer)
            if last_part:
                decrypted += last_part

        if size < AES_BLOCK_SIZE:
            self._maybe_boundary_block = decrypted
            return self._read_block(size)
        decrypted_len = len(decrypted)
        self.offset += decrypted_len
        self._decrypt_offset += decrypted_len
        return decrypted

    def close(self) -> None:
        super().close()
        self._maybe_decryptor = None

    def read(self, size: Optional[int] = -1) -> bytes:
        """Read up to size decrypted bytes"""
        self._check_not_closed()
        if self.state == "EOF" or size == 0:
            return b""
        elif size is None or size < 0:
            return self._read_all()
        else:
            return self._read_block(size)

    def readable(self) -> bool:
        """True if this stream supports reading"""
        self._check_not_closed()
        return self.state in ["OPEN", "EOF"]

    def seek(self, offset: int, whence: int = 0) -> int:
        self._check_not_closed()
        self._initialize_decryptor()
        if whence == os.SEEK_SET:
            if offset != self.offset:
                if offset > self._plaintext_size:
                    raise io.UnsupportedOperation("DecryptorFile does not support seeking beyond EOF")
                if offset < 0:
                    raise ValueError("negative seek position")
                self.offset = offset
            return self.offset
        elif whence == os.SEEK_CUR:
            if offset != 0:
                raise io.UnsupportedOperation("can't do nonzero cur-relative seeks")
            return self.offset
        elif whence == os.SEEK_END:
            if offset != 0:
                raise io.UnsupportedOperation("can't do nonzero end-relative seeks")
            self.offset = self._plaintext_size
            return self.offset
        else:
            raise ValueError("Invalid whence value")

    def seekable(self) -> bool:
        """True if this stream supports random access"""
        self._check_not_closed()
        return True


class DecryptSink(Sink):
    def __init__(self, next_sink: HasWrite, file_size: int, encryption_key_data: Union[str, bytes]) -> None:
        super().__init__(next_sink)
        if file_size < 0:
            raise ValueError("Invalid file_size: " + str(file_size))
        self.data_bytes_received = 0
        self.data_size = file_size
        self.decryptor = Decryptor(encryption_key_data)
        self.file_size = file_size
        self.footer = b""
        self.header = b""

    def _extract_encryption_footer_bytes(self, data: bytes) -> bytes:
        expected_data_bytes = self.data_size - self.data_bytes_received
        if len(data) > expected_data_bytes:
            self.footer += data[expected_data_bytes:]
            data = data[:expected_data_bytes]
        return data

    def _process_encryption_header(self, data: bytes) -> bytes:
        if not data or not self.decryptor.expected_header_bytes():
            return data
        if self.header:
            data = self.header + data
            self.header = b""
        offset = 0
        while self.decryptor.expected_header_bytes() > 0:
            header_bytes = self.decryptor.expected_header_bytes()
            if header_bytes + offset > len(data):
                self.header = data[offset:]
                return b""
            self.decryptor.process_header(data[offset : offset + header_bytes])
            offset += header_bytes
        data = data[offset:]
        self.data_size = self.file_size - self.decryptor.header_size() - self.decryptor.footer_size()
        return data

    def write(self, data: BinaryData) -> int:
        data = bytes(data) if not isinstance(data, bytes) else data
        written = len(data)
        data = self._process_encryption_header(data)
        if not data:
            return written
        data = self._extract_encryption_footer_bytes(data)
        self.data_bytes_received += len(data)
        if data:
            data = self.decryptor.process_data(data)
        if len(self.footer) == self.decryptor.footer_size():
            final_data = self.decryptor.finalize(self.footer)
            if final_data:
                data += final_data
        if not data:
            return written
        self._write_to_next_sink(data)
        return written
