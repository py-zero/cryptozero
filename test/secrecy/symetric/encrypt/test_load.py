from cryptozero.secrecy.symetric import Encrypt


def test_init(stretched_random_password):
    encrypter = Encrypt(stretched_random_password)

    assert stretched_random_password == encrypter.key


def test_from_password(random_password: str, stretched_random_password: bytes):
    expected_encrypter = Encrypt(stretched_random_password)
    encrypter = Encrypt.from_password(random_password)

    assert expected_encrypter == encrypter


def test_from_key(stretched_random_password: bytes):
    expected_encrypter = Encrypt(stretched_random_password)
    encrypter = Encrypt.from_key(stretched_random_password)

    assert expected_encrypter == encrypter
