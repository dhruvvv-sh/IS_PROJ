import pytest
from cipherchat.crypto.encryption import AuthenticationError, Ciphertext, decrypt, encrypt

def test_gcm_round_trip_nonce_and_authentication_failures():
    key, aad = b"k" * 32, b"metadata"
    one, two = encrypt(key, b"hello", aad), encrypt(key, b"hello", aad)
    assert one.nonce != two.nonce and decrypt(key, one, aad) == b"hello"
    with pytest.raises(AuthenticationError): decrypt(key, Ciphertext(one.nonce, bytes([one.data[0] ^ 1]) + one.data[1:]), aad)
    with pytest.raises(AuthenticationError): decrypt(key, one, b"changed")
    with pytest.raises(AuthenticationError): decrypt(key, Ciphertext(bytes([one.nonce[0] ^ 1]) + one.nonce[1:], one.data), aad)
    with pytest.raises(AuthenticationError): decrypt(b"z" * 32, one, aad)
