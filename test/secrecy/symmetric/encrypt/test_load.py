from cryptozero.secrecy.symmetric import Encrypt


def test_init(random_password):
    encrypter = Encrypt(random_password)

    assert random_password == encrypter.password


def test_from_password(random_password: str):
    expected_encrypter = Encrypt(random_password)
    encrypter = Encrypt.from_password(random_password)

    assert expected_encrypter == encrypter
