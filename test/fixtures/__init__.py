import io
import os
import random
from tempfile import NamedTemporaryFile
from typing import IO

import pytest


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
