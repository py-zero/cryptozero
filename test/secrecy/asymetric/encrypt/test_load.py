import io
import os
import random
from tempfile import NamedTemporaryFile
from typing import IO

import pytest

from cryptozero.secrecy.asymetric import Encrypt


@pytest.fixture
def public_key() -> bytes:
    # we don't intend this to be secure, so we'll use `randbits`
    return bytes(bytearray(
        random.getrandbits(8)
        for _ in range(1024)
    ))


@pytest.fixture
def public_key_file(public_key) -> IO:
    return io.BytesIO(public_key)


@pytest.fixture
def public_key_file_path(public_key) -> str:
    with NamedTemporaryFile(delete=False) as file:
        file.write(public_key)
        file_name = file.name

    yield file_name

    os.unlink(file_name)


def test_init_sets_public_key(public_key: bytes):
    encrypter = Encrypt(public_key)

    assert encrypter.public_key == public_key


def test_loading_from_public_key(public_key: bytes):
    expected_encrypter = Encrypt(public_key)
    encrypter = Encrypt.from_public_key(public_key)

    assert expected_encrypter == encrypter


def test_loading_from_public_key_file(public_key: bytes, public_key_file: IO):
    expected_encrypter = Encrypt(public_key)
    encrypter = Encrypt.from_public_key_file(public_key_file)

    assert expected_encrypter == encrypter


def test_loading_from_public_key_path(public_key: bytes, public_key_file_path: str):
    expected_encrypter = Encrypt(public_key)
    encrypter = Encrypt.from_public_key_path(public_key_file_path)

    assert expected_encrypter == encrypter
