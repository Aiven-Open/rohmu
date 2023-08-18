"""
Copyright (c) 2015 Ohmu Ltd
See LICENSE for details
"""
from __future__ import annotations

from py.path import LocalPath  # type: ignore [import] # pylint: disable=import-error
from rohmu import IO_BLOCK_SIZE
from rohmu.encryptor import Decryptor, DecryptorFile, Encryptor, EncryptorFile, EncryptorStream
from typing import cast, IO

import io
import json
import os
import pytest
import random
import tarfile
import textwrap


@pytest.fixture(name="rsa_public_key")
def fixture_rsa_public_key() -> str:
    return textwrap.dedent(
        """\
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQ9yu7rNmu0GFMYeQq9Jo2B3d9
        hv5t4a+54TbbxpJlks8T27ipgsaIjqiQP7+uXNfU6UCzGFEHs9R5OELtO3Hq0Dn+
        JGdxJlJ1prxVkvjCICCpiOkhc2ytmn3PWRuVf2VyeAddslEWHuXhZPptvIr593kF
        lWN+9KPe+5bXS8of+wIDAQAB
        -----END PUBLIC KEY-----"""
    )


@pytest.fixture(name="rsa_private_key")
def fixture_rsa_private_key() -> str:
    return textwrap.dedent(
        """\
        -----BEGIN PRIVATE KEY-----
        MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAND3K7us2a7QYUxh
        5Cr0mjYHd32G/m3hr7nhNtvGkmWSzxPbuKmCxoiOqJA/v65c19TpQLMYUQez1Hk4
        Qu07cerQOf4kZ3EmUnWmvFWS+MIgIKmI6SFzbK2afc9ZG5V/ZXJ4B12yURYe5eFk
        +m28ivn3eQWVY370o977ltdLyh/7AgMBAAECgYEAkuAobRFhL+5ndTiZF1g1zCQT
        aLepvbITwaL63B8GZz55LowRj5PL18/tyvYD1JqNWalZQIim67MKdOmGoRhXSF22
        gUc6/SeqD27/9rsj8I+j0TrzLdTZwn88oX/gtndNutZuryCC/7KbJ8j18Jjn5qf9
        ZboRKbEc7udxOb+RcYECQQD/ZLkxIvMSj0TxPUJcW4MTEsdeJHCSnQAhreIf2omi
        hf4YwmuU3qnFA3ROje9jJe3LNtc0TK1kvAqfZwdpqyAdAkEA0XY4P1CPqycYvTxa
        dxxWJnYA8K3g8Gs/Eo8wYKIciP+K70Q0GRP9Qlluk4vrA/wJJnTKCUl7YuAX6jDf
        WdV09wJALGHXoQde0IHfTEEGEEDC9YSU6vJQMdpg1HmAS2LR+lFox+q5gWR0gk1I
        YAJgcI191ovQOEF+/HuFKRBhhGZ9rQJAXOt13liNs15/sgshEq/mY997YUmxfNYG
        v+P3kRa5U+kRKD14YxukARgNXrT2R+k54e5zZhVMADvrP//4RTDVVwJBAN5TV9p1
        UPZXbydO8vZgPuo001KoEd9N3inq/yNcsHoF/h23Sdt/rcdfLMpCWuIYs/JAqE5K
        nkMAHqg9PS372Cs=
        -----END PRIVATE KEY-----"""
    )


@pytest.mark.parametrize(
    ("plaintext"),
    (
        (b"test"),
        (b""),
    ),
)
def test_encryptor_decryptor(plaintext: bytes, rsa_private_key: str, rsa_public_key: str) -> None:
    for op in (None, "json"):
        if op == "json":
            public_key = json.loads(json.dumps(rsa_public_key))
            private_key = json.loads(json.dumps(rsa_private_key))
        else:
            public_key = rsa_public_key
            private_key = rsa_private_key

        encryptor = Encryptor(public_key)
        decryptor = Decryptor(private_key)
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        if len(plaintext) > 0:
            assert plaintext not in encrypted
        offset = 0
        while decryptor.expected_header_bytes() > 0:
            chunk = encrypted[offset : offset + decryptor.expected_header_bytes()]
            decryptor.process_header(chunk)
            offset += len(chunk)
        decrypted_size = len(encrypted) - decryptor.header_size() - decryptor.footer_size()
        decrypted = decryptor.process_data(encrypted[decryptor.header_size() : decryptor.header_size() + decrypted_size])
        decrypted += decryptor.finalize(encrypted[-decryptor.footer_size() :])
        assert plaintext == decrypted


def test_encryptor_stream(rsa_private_key: str, rsa_public_key: str) -> None:
    plaintext = os.urandom(2 * 1024 * 1024)
    encrypted_stream = EncryptorStream(io.BytesIO(plaintext), rsa_public_key)
    result_data = io.BytesIO()
    while True:
        bytes_requested = random.randrange(1, 12345)
        data = encrypted_stream.read(bytes_requested)
        if not data:
            break
        result_data.write(data)
        # Must return exactly the amount of data requested except when reaching end of stream
        if len(data) < bytes_requested:
            assert not encrypted_stream.read(1)
            break
        assert len(data) == bytes_requested
        assert encrypted_stream.tell() == result_data.tell()
    assert result_data.tell() > 0
    result_data.seek(0)
    decrypted = DecryptorFile(result_data, rsa_private_key).read()
    assert plaintext == decrypted

    encrypted_stream = EncryptorStream(io.BytesIO(plaintext), rsa_public_key)
    result_data = io.BytesIO()
    result_data.write(encrypted_stream.read())
    result_data.seek(0)
    decrypted = DecryptorFile(result_data, rsa_private_key).read()
    assert plaintext == decrypted


def test_decryptorfile(tmpdir: LocalPath, rsa_public_key: str, rsa_private_key: str) -> None:
    # create a plaintext blob bigger than IO_BLOCK_SIZE
    plaintext1 = b"rvdmfki6iudmx8bb25tx1sozex3f4u0nm7uba4eibscgda0ckledcydz089qw1p1wer"
    repeat = int(1.5 * IO_BLOCK_SIZE / len(plaintext1))
    plaintext = repeat * plaintext1
    encryptor = Encryptor(rsa_public_key)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    plain_fp = open(tmpdir.join("plain").strpath, mode="w+b")
    plain_fp.write(ciphertext)
    plain_fp.seek(0)
    fp = DecryptorFile(plain_fp, rsa_private_key)  # pylint: disable=redefined-variable-type
    assert fp.fileno() == plain_fp.fileno()
    assert fp.readable() is True
    assert fp.writable() is False
    fp.flush()
    result = fp.read()
    assert plaintext == result

    assert fp.seekable() is True
    with pytest.raises(ValueError):
        fp.seek(-1)
    fp.seek(0, os.SEEK_SET)
    with pytest.raises(io.UnsupportedOperation):
        fp.seek(1, os.SEEK_CUR)
    with pytest.raises(io.UnsupportedOperation):
        fp.seek(1, os.SEEK_END)
    with pytest.raises(ValueError):
        fp.seek(1, 0xFF)
    assert fp.seek(0, os.SEEK_END) == len(plaintext)
    assert fp.seek(0, os.SEEK_CUR) == len(plaintext)

    fp.seek(0)
    result = fp.read()
    assert plaintext == result
    assert fp.read(1234) == b""
    assert fp.read() == b""

    fp.seek(0)
    result = fp.read(8192)
    assert result == plaintext[:8192]
    result = fp.read(8192)
    assert result == plaintext[8192 : 8192 * 2]
    result = fp.read(IO_BLOCK_SIZE * 2)
    assert plaintext[8192 * 2 :] == result
    assert fp.seek(IO_BLOCK_SIZE // 2) == IO_BLOCK_SIZE // 2
    result = fp.read()
    assert len(result) == len(plaintext) - IO_BLOCK_SIZE // 2
    assert plaintext[IO_BLOCK_SIZE // 2 :] == result

    fp.seek(2)
    result = fp.read(1)
    assert plaintext[2:3] == result
    assert fp.tell() == 3
    result = fp.read(17)
    assert plaintext[3:16] == result
    result = fp.read(6)
    assert plaintext[16:22] == result
    result = fp.read(6)
    assert plaintext[22:28] == result
    result = fp.read(6)
    assert plaintext[28:32] == result
    fp.seek(len(plaintext) - 3)
    assert plaintext[-3:-2] == fp.read(1)
    assert plaintext[-2:] == fp.read()

    with pytest.raises(io.UnsupportedOperation):
        fp.truncate()
    # close the file (this can be safely called multiple times), other ops should fail after that
    fp.close()
    fp.close()
    with pytest.raises(ValueError):
        fp.truncate()


def test_decryptorfile_for_tarfile(tmpdir: LocalPath, rsa_public_key: str, rsa_private_key: str) -> None:
    testdata = b"file contents"
    data_tmp_name = tmpdir.join("plain.data").strpath
    with open(data_tmp_name, mode="wb") as data_tmp:
        data_tmp.write(testdata)

    tar_data = io.BytesIO()
    with tarfile.open(name="foo", fileobj=tar_data, mode="w") as tar:
        tar.add(data_tmp_name, arcname="archived_content")
    plaintext = tar_data.getvalue()

    encryptor = Encryptor(rsa_public_key)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    enc_tar_name = tmpdir.join("enc.tar.data").strpath
    with open(enc_tar_name, "w+b") as enc_tar:
        enc_tar.write(ciphertext)
        enc_tar.seek(0)

        dfile = DecryptorFile(enc_tar, rsa_private_key)
        with tarfile.open(fileobj=cast(IO[bytes], dfile), mode="r") as tar:
            info = tar.getmember("archived_content")
            assert info.isfile() is True
            assert info.size == len(testdata)
            content_file = tar.extractfile("archived_content")
            assert content_file is not None
            content = content_file.read()
            content_file.close()
            assert testdata == content

            decout = tmpdir.join("dec_out_dir").strpath
            os.makedirs(decout)
            tar.extract("archived_content", decout)
            extracted_path = os.path.join(decout, "archived_content")
            with open(extracted_path, "rb") as ext_fp:
                assert testdata == ext_fp.read()


def test_encryptorfile(tmpdir: LocalPath, rsa_public_key: str, rsa_private_key: str) -> None:
    # create a plaintext blob bigger than IO_BLOCK_SIZE
    plaintext1 = b"rvdmfki6iudmx8bb25tx1sozex3f4u0nm7uba4eibscgda0ckledcydz089qw1p1"
    repeat = int(1.5 * IO_BLOCK_SIZE / len(plaintext1))
    plaintext = repeat * plaintext1

    fn = tmpdir.join("data").strpath
    with open(fn, "w+b") as plain_fp:
        enc_fp = EncryptorFile(plain_fp, rsa_public_key)
        assert enc_fp.fileno() == plain_fp.fileno()
        assert enc_fp.readable() is False
        with pytest.raises(io.UnsupportedOperation):
            enc_fp.read(1)
        assert enc_fp.seekable() is False
        with pytest.raises(io.UnsupportedOperation):
            enc_fp.seek(1, os.SEEK_CUR)
        assert enc_fp.writable() is True

        enc_fp.write(plaintext)
        enc_fp.write(b"")
        assert enc_fp.tell() == len(plaintext)
        assert enc_fp.next_fp.tell() > len(plaintext)
        enc_fp.close()
        enc_fp.close()

        plain_fp.seek(0)

        dec_fp = DecryptorFile(plain_fp, rsa_private_key)
        assert dec_fp.fileno() == plain_fp.fileno()
        assert dec_fp.readable() is True
        assert dec_fp.seekable() is True
        assert dec_fp.writable() is False
        with pytest.raises(io.UnsupportedOperation):
            dec_fp.write(b"x")
        dec_fp.flush()

        result = dec_fp.read()
        assert plaintext == result


def test_encryptorfile_for_tarfile(tmpdir: LocalPath, rsa_public_key: str, rsa_private_key: str) -> None:
    testdata = b"file contents"
    data_tmp_name = tmpdir.join("plain.data").strpath
    with open(data_tmp_name, mode="wb") as data_tmp:
        data_tmp.write(testdata)

    enc_tar_name = tmpdir.join("enc.tar.data").strpath
    with open(enc_tar_name, "w+b") as plain_fp:
        enc_fp = EncryptorFile(plain_fp, rsa_public_key)
        with tarfile.open(name="foo", fileobj=cast(IO[bytes], enc_fp), mode="w") as tar:
            tar.add(data_tmp_name, arcname="archived_content")
        enc_fp.close()

        plain_fp.seek(0)

        dfile = DecryptorFile(plain_fp, rsa_private_key)
        with tarfile.open(fileobj=cast(IO[bytes], dfile), mode="r") as tar:
            info = tar.getmember("archived_content")
            assert info.isfile() is True
            assert info.size == len(testdata)
            content_file = tar.extractfile("archived_content")
            assert content_file is not None
            content = content_file.read()
            content_file.close()
            assert testdata == content


def test_empty_file(rsa_public_key: str, rsa_private_key: str) -> None:
    bio = io.BytesIO()
    ef = EncryptorFile(bio, rsa_public_key)
    ef.write(b"")
    ef.close()
    assert bio.tell() == 0

    df = DecryptorFile(bio, rsa_private_key)
    data = df.read()
    assert data == b""
