import base64
import enum
import os
from typing import Callable, Dict, NamedTuple, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from cryptozero.key import pbkdf2_hmac_stretcher, stretch


@enum.unique
class BackendName(str, enum.Enum):
    AES_CBC = "aes_cbc"
    FERNET = "fernet"

    def __str__(self) -> str:
        return self.value


BackendPayload = NamedTuple(
    "BackendPayload",
    (("backend_name", BackendName), ("salt", bytes), ("payload", bytes)),
)


def serialise_payload(payload: BackendPayload) -> bytes:
    return b"$".join(
        (
            payload.backend_name.encode(),
            base64.urlsafe_b64encode(payload.salt),
            base64.urlsafe_b64encode(payload.payload),
        )
    )


def deserialise_payload(serialised_payload: bytes) -> BackendPayload:
    backend_name, salt, payload = serialised_payload.split(b"$")
    return BackendPayload(
        backend_name=BackendName(backend_name.decode()),
        salt=base64.urlsafe_b64decode(salt),
        payload=base64.urlsafe_b64decode(payload),
    )


def fernet_backend(password: str, salt: bytes, message: str) -> BackendPayload:
    key = pbkdf2_hmac_stretcher(password, salt=salt, hash_name="sha256")
    encoded_key = base64.urlsafe_b64encode(key)
    f = Fernet(encoded_key)
    payload = f.encrypt(message.encode())
    return BackendPayload(backend_name=BackendName.FERNET, salt=salt, payload=payload)


def aes_cbc_pkcs7_backend(password: str, salt: bytes, message: str) -> BackendPayload:
    key = pbkdf2_hmac_stretcher(password, salt=salt, hash_name="sha256")
    cipher = Cipher(
        algorithm=algorithms.AES(key), mode=modes.CBC(salt), backend=default_backend()
    )
    padder = PKCS7(cipher.algorithm.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return BackendPayload(backend_name=BackendName.AES_CBC, salt=salt, payload=ct)


def fernet_decrypt_backend(password: str, backend_payload: BackendPayload) -> str:
    key = pbkdf2_hmac_stretcher(password, salt=backend_payload.salt, hash_name="sha256")
    encoded_key = base64.urlsafe_b64encode(key)
    f = Fernet(encoded_key)
    return f.decrypt(backend_payload.payload).decode()


def aes_cbc_pkcs7_decrypt_backend(
    password: str, backend_payload: BackendPayload
) -> str:
    salt = backend_payload.salt
    key = pbkdf2_hmac_stretcher(password, salt=salt, hash_name="sha256")
    cipher = Cipher(
        algorithm=algorithms.AES(key), mode=modes.CBC(salt), backend=default_backend()
    )
    decrypter = cipher.decryptor()
    padded_message = decrypter.update(backend_payload.payload) + decrypter.finalize()
    unpadder = PKCS7(cipher.algorithm.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()


DECRYPT_BACKEND_REGISTRY = {
    BackendName.AES_CBC: aes_cbc_pkcs7_decrypt_backend,
    BackendName.FERNET: fernet_decrypt_backend,
}  # type: Dict[str, Callable[[str, BackendPayload], str]]


def get_decrypt_backend(backend_name: str) -> Callable[[str, BackendPayload], str]:
    return DECRYPT_BACKEND_REGISTRY[backend_name]


def generate_salt():
    return os.urandom(16)


class Encrypt:
    def __init__(self, password: str) -> None:
        self.password = password

    @classmethod
    def from_password(cls, password: str) -> "Encrypt":
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

    def __eq__(self, other: "Encrypt") -> bool:
        return bool(type(self) is type(other) and self.password == other.password)


class Decrypt:
    def __init__(self, password: str) -> None:
        self.password = password

    @classmethod
    def from_password(cls, password: str) -> "Decrypt":
        return cls(password)

    def decrypt(self, raw_payload: bytes) -> str:
        payload = deserialise_payload(raw_payload)
        backend = get_decrypt_backend(payload.backend_name)
        return backend(self.password, payload)

    def __eq__(self, other: "Decrypt") -> bool:
        return bool(type(self) is type(other) and self.password == other.password)


def encrypt(password: str, message: str) -> bytes:
    return Encrypt.from_password(password).encrypt(message)


def decrypt(password: str, encrypted_message: bytes) -> str:
    return Decrypt.from_password(password).decrypt(encrypted_message)
