import pytest
from cryptozero.secrecy.symmetric import (
    BackendName,
    BackendPayload,
    deserialise_payload,
    serialise_payload,
)


def test_serialise_backend_name():
    backend_name = BackendName.AES_CBC
    payload = BackendPayload(backend_name=backend_name, salt=b"", payload=b"")
    assert b"aes_cbc$$" == serialise_payload(payload)


def test_serialise_salt_is_encoded():
    salt = b"1234"
    encoded_salt = b"MTIzNA=="  # urlsafe b64
    payload = BackendPayload(backend_name=BackendName.AES_CBC, salt=salt, payload=b"")
    expected = b"aes_cbc$%b$" % encoded_salt
    assert expected == serialise_payload(payload)


def test_serialise_payload_is_encoded():
    payload_body = b"5678"
    encoded_payload = b"NTY3OA=="  # urlsafe b64
    payload = BackendPayload(
        backend_name=BackendName.AES_CBC, salt=b"", payload=payload_body
    )
    expected = b"aes_cbc$$%b" % encoded_payload
    assert expected == serialise_payload(payload)


def test_deserialise_blank_payload():
    input = b"$$"
    with pytest.raises(ValueError):
        deserialise_payload(input)


def test_deserialise_backend_name():
    input = b"aes_cbc$$"
    expected = BackendPayload(backend_name=BackendName.AES_CBC, salt=b"", payload=b"")
    assert expected == deserialise_payload(input)


def test_deserialise_salt():
    input = b"aes_cbc$MTIzNA==$"
    expected = BackendPayload(
        backend_name=BackendName.AES_CBC, salt=b"1234", payload=b""
    )
    assert expected == deserialise_payload(input)


def test_deserialise_payload_body():
    input = b"aes_cbc$$NTY3OA=="
    expected = BackendPayload(
        backend_name=BackendName.AES_CBC, salt=b"", payload=b"5678"
    )
    assert expected == deserialise_payload(input)


def test_backend_name_is_serialisable():
    expected_name = "aes_cbc"
    assert expected_name == str(BackendName.AES_CBC)
