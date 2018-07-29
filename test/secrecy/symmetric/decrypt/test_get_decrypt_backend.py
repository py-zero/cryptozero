import types

from cryptozero.secrecy.symmetric import (
    BackendName,
    BackendPayload,
    aes_cbc_pkcs7_decrypt_backend,
    fernet_decrypt_backend,
    get_decrypt_backend,
)


def test_takes_backend_name():
    backend_name = BackendName.AES_CBC
    get_decrypt_backend(backend_name=backend_name)


def test_returns_decrypt_backend():
    backend_name = BackendName.AES_CBC
    backend = get_decrypt_backend(backend_name)
    assert isinstance(backend, types.FunctionType)


def test_aes_cbc_backend_returned():
    backend_name = BackendName.AES_CBC
    backend = get_decrypt_backend(backend_name)
    assert aes_cbc_pkcs7_decrypt_backend is backend


def test_fernet_backend_returned():
    backend_name = BackendName.FERNET
    backend = get_decrypt_backend(backend_name)
    assert fernet_decrypt_backend is backend
