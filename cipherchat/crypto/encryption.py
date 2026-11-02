"""AES-256-GCM authenticated encryption."""
import os
from dataclasses import dataclass
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12


class AuthenticationError(Exception):
    """Raised when GCM authentication fails; callers must fail closed."""


@dataclass(frozen=True)
class Ciphertext:
    nonce: bytes
    data: bytes  # ciphertext with the 16-byte GCM tag appended by cryptography


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")


def generate_nonce(counter: int | None = None) -> bytes:
    """Generate a 96-bit nonce. If counter is provided, uses 4-byte counter + 8-byte random prefix."""
    if counter is not None:
        return (counter & 0xFFFFFFFF).to_bytes(4, byteorder="big") + os.urandom(8)
    return os.urandom(NONCE_BYTES)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes, nonce: bytes | None = None) -> Ciphertext:
    _validate_key(key)
    if not isinstance(plaintext, bytes) or not isinstance(associated_data, bytes):
        raise TypeError("plaintext and associated_data must be bytes")
    if nonce is not None:
        if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
            raise ValueError(f"nonce must be {NONCE_BYTES} bytes")
    else:
        nonce = os.urandom(NONCE_BYTES)
    return Ciphertext(nonce=nonce, data=AESGCM(key).encrypt(nonce, plaintext, associated_data))


def decrypt(key: bytes, ciphertext: Ciphertext, associated_data: bytes) -> bytes:
    _validate_key(key)
    if not isinstance(ciphertext, Ciphertext) or len(ciphertext.nonce) != NONCE_BYTES:
        raise ValueError("invalid ciphertext envelope")
    try:
        return AESGCM(key).decrypt(ciphertext.nonce, ciphertext.data, associated_data)
    except InvalidTag as error:
        raise AuthenticationError("AES-GCM authentication failed") from error
