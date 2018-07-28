import io
import os
import random
from tempfile import NamedTemporaryFile
from typing import IO

import pytest

from cryptozero.secrecy.asymetric import Decrypt


@pytest.fixture
def private_key() -> bytes:
    # we don't intend this to be secure, so we'll use `randbits`
    return bytes(bytearray(
        random.getrandbits(8)
        for _ in range(1024)
    ))


@pytest.fixture
def private_key_file(private_key) -> IO:
    return io.BytesIO(private_key)


@pytest.fixture
def private_key_file_path(private_key) -> str:
    with NamedTemporaryFile(delete=False) as file:
        file.write(private_key)
        file_name = file.name

    yield file_name

    os.unlink(file_name)


def test_init_sets_private_key(private_key: bytes):
    decrypter = Decrypt(private_key)

    assert decrypter.private_key == private_key


def test_loading_from_private_key(private_key: bytes):
    expected_decrypter = Decrypt(private_key)
    decrypter = Decrypt.from_private_key(private_key)

    assert expected_decrypter == decrypter


def test_loading_from_private_key_file(private_key: bytes, private_key_file: IO):
    expected_decrypter = Decrypt(private_key)
    decrypter = Decrypt.from_private_key_file(private_key_file)

    assert expected_decrypter == decrypter


def test_loading_from_private_key_path(private_key: bytes, private_key_file_path: str):
    expected_decrypter = Decrypt(private_key)
    decrypter = Decrypt.from_private_key_path(private_key_file_path)

    assert expected_decrypter == decrypter
