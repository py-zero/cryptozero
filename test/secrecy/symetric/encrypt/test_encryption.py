import inspect

from cryptozero.secrecy.symetric import Encrypt, aes_cbc_pkcs7_backend


def test_default_encrypt_backend_is_aes():
    sig = inspect.signature(Encrypt.encrypt)
    param = sig.parameters['backend']

    assert aes_cbc_pkcs7_backend is param.default


def test_encrypt_to_bytes(random_password: str):
    message = "This is a secret message"
    encrypter = Encrypt.from_password(random_password)
    encrypted_message = encrypter.encrypt(message)

    assert type(encrypted_message) is bytes


def test_encrypt_to_serialised_payload(random_password: str):
    message = "this is a secret message"
    encrypter = Encrypt.from_password(random_password)
    encrypted_message = encrypter.encrypt(message)

    assert 3 == len(encrypted_message.split(b'$'))
