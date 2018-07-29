import hashlib
from typing import Callable, Optional

from mypy_extensions import Arg, DefaultNamedArg

_UNSET = object()

DEFAULT_HASH_NAME = "sha256"
DEFAULT_SALT = b"this is not a great salt"
DEFAULT_ITERATIONS = 100000

StretcherBackend = Callable[
    [Arg(str, "input_key"), DefaultNamedArg(bytes, "salt")], bytes
]


def pbkdf2_hmac_stretcher(
    input_key: str,
    salt: bytes = DEFAULT_SALT,
    hash_name: str = DEFAULT_HASH_NAME,
    iterations: int = DEFAULT_ITERATIONS,
) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name=hash_name,
        password=input_key.encode(),
        salt=salt,
        iterations=iterations,
    )


def stretch(
    input_key: str,
    salt: Optional[bytes] = _UNSET,
    stretcher: StretcherBackend = pbkdf2_hmac_stretcher,
) -> bytes:
    kwargs = {}
    if salt is not _UNSET:
        kwargs["salt"] = salt
    return stretcher(input_key, **kwargs)
