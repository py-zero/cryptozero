import hashlib
from typing import Callable


DEFAULT_HASH_NAME = 'sha256'
DEFAULT_SALT = b'this is not a great salt'
DEFAULT_ITERATIONS = 100000


def pbkdf2_hmac_stretcher(
        input_key: str,
        salt=DEFAULT_SALT,
        hash_name=DEFAULT_HASH_NAME,
        iterations=DEFAULT_ITERATIONS,
) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name=hash_name,
        password=input_key.encode(),
        salt=salt,
        iterations=iterations,
    )


def stretch(
        input_key: str,
        stretcher: Callable[[str], bytes] = pbkdf2_hmac_stretcher,
) -> bytes:
    return stretcher(input_key)
