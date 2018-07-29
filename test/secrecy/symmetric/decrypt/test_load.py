from cryptozero.secrecy.symmetric import Decrypt


def test_init(random_password: str):
    decrypter = Decrypt(random_password)

    assert random_password == decrypter.password


def test_from_password(random_password: str):
    expected_encrypter = Decrypt(random_password)
    encrypter = Decrypt.from_password(random_password)

    assert expected_encrypter == encrypter
