from cryptozero.secrecy.symetric import Encrypt


def test_encrypt_to_bytes(random_password: str):
    message = "This is a secret message"
    encrypter = Encrypt.from_password(random_password)
    encrypted_message = encrypter.encrypt(message)

    assert type(encrypted_message) is bytes
