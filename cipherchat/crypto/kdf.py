"""Domain-separated session-key derivation."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cipherchat.protocol.limits import MAX_CONTEXT_LENGTH

DOMAIN = b"cipherchat-v1"


def derive_session_key(shared_secret: bytes, *, context: bytes, salt: bytes | None = None) -> bytes:
    """Derive a 32-byte AES-256 key from an ECDH secret and explicit context.

    Context should bind a session to application-level identifiers.  The fixed
    domain label prevents accidental cross-protocol key reuse.
    """
    if not isinstance(shared_secret, bytes) or len(shared_secret) != 32:
        raise ValueError("shared_secret must be a 32-byte X25519 output")
    if not isinstance(context, bytes) or not context:
        raise ValueError("context must be non-empty bytes")
    if len(context) > MAX_CONTEXT_LENGTH:
        raise ValueError(f"context length ({len(context)} bytes) exceeds maximum limit of {MAX_CONTEXT_LENGTH} bytes")
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError("salt must be bytes or None")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=DOMAIN + b"|" + context).derive(shared_secret)
