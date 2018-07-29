from cryptozero.secrecy.symmetric import (
    BackendName,
    BackendPayload,
    Decrypt,
    Encrypt,
    aes_cbc_pkcs7_backend,
    aes_cbc_pkcs7_decrypt_backend,
    decrypt,
    encrypt,
    fernet_backend,
    fernet_decrypt_backend,
)


def test_aes_decrypt():
    password = "some password"
    expected_message = "some message"
    # This is a verified gen of AES CBC PKCS7, using pbkdf2 hmac, with sha256 at 100k iterations.
    # It will need regenerating if we change iteration count
    payload = BackendPayload(
        backend_name=BackendName.AES_CBC,
        salt=b"1234567890123456",  # 16 bytes
        payload=b"\x1cD\xb9\xd9e\x94R)\x19I_M\\\x95\xce\x9a",
    )
    response_message = aes_cbc_pkcs7_decrypt_backend(password, payload)
    assert expected_message == response_message


def test_fernet_decrypt():
    password = "some password"
    expected_message = "some message"
    # This is a verified generation using Fernet, with pbkdf2 hmac sha256 with 100k iterations.
    # It will need regenerating if we change iteration count
    payload = BackendPayload(
        backend_name=BackendName.FERNET,
        salt=b"1234567890123456",  # 16 bytes
        payload=b"gAAAAABbXJe-GGKECaZp1e8-BGqKGS62nrNa5-S2Vjm5VGhDR0IZRfpZok3Y47sxoy5S0JHgQ5Y-87aiNTjPhZJPzouJsS8mVA==",
    )
    response_message = fernet_decrypt_backend(password, payload)
    assert expected_message == response_message


# we can assume that encryption is going to work in these tests
def test_decrypt_default_from_message(random_password: str):
    secret_message = "this is a secret message"
    encrypter = Encrypt.from_password(random_password)
    encrypted_message = encrypter.encrypt(secret_message)

    decrypter = Decrypt.from_password(random_password)
    decrypted_message = decrypter.decrypt(encrypted_message)

    assert secret_message == decrypted_message


def test_decrypt_aes_from_message(random_password: str):
    secret_message = "this is a secret message"
    encrypter = Encrypt.from_password(random_password)
    encrypted_message = encrypter.encrypt(secret_message, backend=aes_cbc_pkcs7_backend)

    decrypter = Decrypt.from_password(random_password)
    decrypted_message = decrypter.decrypt(encrypted_message)

    assert secret_message == decrypted_message


def test_decrypt_fernet_from_message(random_password: str):
    secret_message = "this is a secret message"
    encrypter = Encrypt.from_password(random_password)
    encrypted_message = encrypter.encrypt(secret_message, backend=fernet_backend)

    decrypter = Decrypt.from_password(random_password)
    decrypted_message = decrypter.decrypt(encrypted_message)

    assert secret_message == decrypted_message


def test_shortcut_decrypt(random_password: str):
    secret_message = "this is a secret message"
    assert secret_message == decrypt(
        random_password, encrypt(random_password, secret_message)
    )
