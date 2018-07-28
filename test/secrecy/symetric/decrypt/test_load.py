from cryptozero.secrecy.symetric import Decrypt


def test_init(random_key: bytes):
    decrypter = Decrypt(random_key)

    assert random_key == decrypter.key
