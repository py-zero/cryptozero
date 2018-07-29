from typing import IO

from cryptozero.secrecy.asymmetric import Decrypt


def test_init_sets_private_key(private_key: bytes):
    decrypter = Decrypt(private_key)

    assert decrypter.private_key == private_key


def test_loading_from_private_key(private_key: bytes):
    expected_decrypter = Decrypt(private_key)
    decrypter = Decrypt.from_private_key(private_key)

    assert expected_decrypter == decrypter


def test_loading_from_private_key_file(private_key: bytes, private_key_file: IO):
    expected_decrypter = Decrypt(private_key)
    decrypter = Decrypt.from_private_key_file(private_key_file)

    assert expected_decrypter == decrypter


def test_loading_from_private_key_path(private_key: bytes, private_key_file_path: str):
    expected_decrypter = Decrypt(private_key)
    decrypter = Decrypt.from_private_key_path(private_key_file_path)

    assert expected_decrypter == decrypter
