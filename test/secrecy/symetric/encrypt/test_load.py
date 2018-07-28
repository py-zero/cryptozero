from cryptozero.secrecy.symetric import Encrypt


def test_init(random_key: bytes):
    decrypter = Encrypt(random_key)

    assert random_key == decrypter.key
