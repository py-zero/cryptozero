import hashlib
import inspect

import pytest
from cryptozero.key import pbkdf2_hmac_stretcher, stretch


def test_input_str_output_bytes():
    password = "some password"
    output = stretch(password)
    assert type(output) is bytes


def test_output_longer_than_input():
    password = "some password"
    output = stretch(password)
    assert len(password) < len(output)


def test_stretcher_is_used(mocker, random_key):
    password = "some password"
    fake_stretcher = mocker.Mock()
    fake_stretcher.return_value = random_key
    output = stretch(password, stretcher=fake_stretcher)

    assert output == random_key
    fake_stretcher.assert_called_once_with(password)


def test_default_stretcher_is_pbkdf2_hmac():
    sig = inspect.signature(stretch)
    param = sig.parameters["stretcher"]

    assert pbkdf2_hmac_stretcher is param.default


def test_sensible_defaults_for_hmac_used():
    password = "some password"
    salt = b"this is not a great salt"
    algorithm = "sha256"
    iterations = 100000  # 100k
    expected_stretched = hashlib.pbkdf2_hmac(
        hash_name=algorithm,
        password=password.encode(),
        salt=salt,
        iterations=iterations,
    )
    assert expected_stretched == stretch(password)


def test_salt_is_passed_to_backend(mocker):
    fake_backend = mocker.Mock()
    stretch("", salt=b"some salt", stretcher=fake_backend)
    fake_backend.assert_called_once_with("", salt=b"some salt")
