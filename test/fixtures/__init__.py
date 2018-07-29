import io
import os
import random
import string
from tempfile import NamedTemporaryFile
from typing import IO

import pytest

from cryptozero.key import stretch


@pytest.fixture
def random_key() -> bytes:
    # we don't intend this to be secure, so we'll use `randbits`
    return bytes(bytearray(random.getrandbits(8) for _ in range(1024)))


@pytest.fixture
def public_key(random_key) -> bytes:
    return random_key


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
def private_key(random_key) -> bytes:
    return random_key


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


@pytest.fixture
def random_password() -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(16))


@pytest.fixture
def stretched_random_password(random_password: str) -> bytes:
    return stretch(random_password)
