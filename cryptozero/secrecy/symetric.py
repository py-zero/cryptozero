import base64
import enum
import os
from typing import Callable, Optional, NamedTuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from cryptozero.key import stretch, pbkdf2_hmac_stretcher


BackendPayload = NamedTuple('BackendPayload', (
    ('backend_name', str),
    ('salt', bytes),
    ('payload', bytes),
))


def serialise_payload(payload: BackendPayload) -> bytes:
    return b'$'.join((
        payload.backend_name.encode(),
        base64.urlsafe_b64encode(payload.salt),
        base64.urlsafe_b64encode(payload.payload),
    ))


def deserialise_payload(serialised_payload: bytes) -> BackendPayload:
    backend_name, salt, payload = serialised_payload.split(b'$')
    return BackendPayload(
        backend_name=backend_name.decode(),
        salt=base64.urlsafe_b64decode(salt),
        payload=base64.urlsafe_b64decode(payload),
    )


def fernet_backend(password: str, salt: bytes, message: str) -> BackendPayload:
    key = pbkdf2_hmac_stretcher(password, salt=salt, hash_name='sha256')
    encoded_key = base64.urlsafe_b64encode(key)
    f = Fernet(encoded_key)
    payload = f.encrypt(message.encode())
    return BackendPayload(
        backend_name='fernet',
        salt=salt,
        payload=payload,
    )


def aes_cbc_pkcs7_backend(password: str, salt: bytes, message: str) -> BackendPayload:
    key = pbkdf2_hmac_stretcher(password, salt=salt, hash_name='sha256')
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CBC(salt),
        backend=default_backend(),
    )
    padder = PKCS7(cipher.algorithm.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return BackendPayload(
        backend_name='aes_cbc',
        salt=salt,
        payload=ct,
    )


class BackendName(str, enum.Enum):
    AES_CBC = 'aes_cbc'
    FERNET = 'fernet'


def fernet_decrypt_backend(backend_payload: BackendPayload) -> str:
    pass


def aes_cbc_pkcs7_decrypt_backend(backend_payload: BackendPayload) -> str:
    pass


DECRYPT_BACKEND_REGISTRY = {
    BackendName.AES_CBC: aes_cbc_pkcs7_decrypt_backend,
    BackendName.FERNET: fernet_decrypt_backend,
}


def get_decrypt_backend(backend_name: str) -> Callable:
    return DECRYPT_BACKEND_REGISTRY[backend_name]


def generate_salt():
    return os.urandom(16)


class Encrypt:
    def __init__(self, password: str) -> None:
        self.password = password

    @classmethod
    def from_password(cls, password: str) -> 'Encrypt':
        return cls(password)

    def encrypt(
            self,
            message: str,
            salt: Optional[bytes] = None,
            backend: Callable[[str, bytes, str], BackendPayload] = aes_cbc_pkcs7_backend,
    ) -> bytes:
        salt = salt or generate_salt()
        payload = backend(self.password, salt, message)
        return serialise_payload(payload)

    def __eq__(self, other: 'Encrypt') -> bool:
        return bool(
            type(self) is type(other)
            and self.password == other.password
        )


class Decrypt:
    def __init__(self, password: str) -> None:
        self.password = password

    @classmethod
    def from_password(cls, password: str) -> 'Decrypt':
        return cls(password)

    def __eq__(self, other: 'Decrypt') -> bool:
        return bool(
            type(self) is type(other)
            and self.password == other.password
        )
