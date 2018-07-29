import inspect

from cryptozero.secrecy.symmetric import (
    BackendName,
    BackendPayload,
    Encrypt,
    aes_cbc_pkcs7_backend,
)


def test_default_encrypt_backend_is_aes():
    sig = inspect.signature(Encrypt.encrypt)
    param = sig.parameters["backend"]

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

    assert 3 == len(encrypted_message.split(b"$"))


def test_aes_encrypt():
    password = "some password"
    message = "some message"
    salt = b"1234567890123456"
    # This is a verified gen of AES CBC PKCS7, using pbkdf2 hmac, with sha256 at 100k iterations.
    # It will need regenerating if we change iteration count
    expected_payload = BackendPayload(
        backend_name=BackendName.AES_CBC,
        salt=b"1234567890123456",  # 16 bytes
        payload=b"\x1cD\xb9\xd9e\x94R)\x19I_M\\\x95\xce\x9a",
    )
    output_payload = aes_cbc_pkcs7_backend(password, salt, message)
    assert expected_payload == output_payload
