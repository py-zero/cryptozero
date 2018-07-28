from cryptozero.secrecy.symetric import Decrypt


def test_init(stretched_random_password: bytes):
    decrypter = Decrypt(stretched_random_password)

    assert stretched_random_password == decrypter.key


def test_from_password(random_password: str, stretched_random_password: bytes):
    expected_encrypter = Decrypt(stretched_random_password)
    encrypter = Decrypt.from_password(random_password)

    assert expected_encrypter == encrypter


def test_from_key(stretched_random_password: bytes):
    expected_encrypter = Decrypt(stretched_random_password)
    encrypter = Decrypt.from_key(stretched_random_password)

    assert expected_encrypter == encrypter
