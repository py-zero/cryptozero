from typing import IO

from cryptozero.secrecy.asymmetric import Encrypt


def test_init_sets_public_key(public_key: bytes):
    encrypter = Encrypt(public_key)

    assert encrypter.public_key == public_key


def test_loading_from_public_key(public_key: bytes):
    expected_encrypter = Encrypt(public_key)
    encrypter = Encrypt.from_public_key(public_key)

    assert expected_encrypter == encrypter


def test_loading_from_public_key_file(public_key: bytes, public_key_file: IO):
    expected_encrypter = Encrypt(public_key)
    encrypter = Encrypt.from_public_key_file(public_key_file)

    assert expected_encrypter == encrypter


def test_loading_from_public_key_path(public_key: bytes, public_key_file_path: str):
    expected_encrypter = Encrypt(public_key)
    encrypter = Encrypt.from_public_key_path(public_key_file_path)

    assert expected_encrypter == encrypter
