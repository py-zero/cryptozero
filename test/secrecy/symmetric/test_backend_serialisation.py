from cryptozero.secrecy.symmetric import BackendPayload, serialise_payload, deserialise_payload


def test_serialise_blank_payload():
    payload = BackendPayload('', b'', b'')
    output = serialise_payload(payload)
    assert b'$$' == output


def test_serialise_backend_name():
    backend_name = 'some_backend'
    payload = BackendPayload(
        backend_name=backend_name,
        salt=b'',
        payload=b'',
    )
    assert b'some_backend$$' == serialise_payload(payload)


def test_serialise_salt_is_encoded():
    salt = b'1234'
    encoded_salt = b'MTIzNA=='  # urlsafe b64
    payload = BackendPayload(
        backend_name='',
        salt=salt,
        payload=b'',
    )
    expected = b'$%b$' % encoded_salt
    assert expected == serialise_payload(payload)


def test_serialise_payload_is_encoded():
    payload_body = b'5678'
    encoded_payload = b'NTY3OA=='  # urlsafe b64
    payload = BackendPayload(
        backend_name='',
        salt=b'',
        payload=payload_body,
    )
    expected = b'$$%b' % encoded_payload
    assert expected == serialise_payload(payload)


def test_deserialise_blank_payload():
    input = b'$$'
    expected = BackendPayload(
        backend_name='',
        salt=b'',
        payload=b'',
    )
    assert expected == deserialise_payload(input)


def test_deserialise_backend_name():
    input = b'some_backend$$'
    expected = BackendPayload(
        backend_name='some_backend',
        salt=b'',
        payload=b'',
    )
    assert expected == deserialise_payload(input)


def test_deserialise_salt():
    input = b'$MTIzNA==$'
    expected = BackendPayload(
        backend_name='',
        salt=b'1234',
        payload=b'',
    )
    assert expected == deserialise_payload(input)


def test_deserialise_payload_body():
    input = b'$$NTY3OA=='
    expected = BackendPayload(
        backend_name='',
        salt=b'',
        payload=b'5678',
    )
    assert expected == deserialise_payload(input)
