"""Pinned-key session establishment and bounded session replacement."""
from dataclasses import dataclass
from uuid import uuid4

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.kdf import derive_session_key
from cipherchat.crypto.key_exchange import derive_shared_secret, load_public_key, public_key_bytes
from cipherchat.security.attacks import verify_expected_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .limits import MAX_CONTEXT_LENGTH, MAX_ID_LENGTH
from .messages import ReceiverSession, SenderSession


@dataclass(frozen=True)
class SessionInfo:
    """Non-secret description of an established session."""
    session_id: str
    context: bytes


class SessionManager:
    """Owns the active directional sessions for one peer relationship.

    The caller supplies previously verified/pinned peer X25519 and Ed25519
    public keys. Every establishment verifies the presented exchange key before
    X25519 is performed. Rekeying invalidates existing session objects before
    installing a new pair.
    """
    def __init__(self, identity: Identity, peer_id: str, expected_peer_public_key: bytes,
                 expected_peer_signing_public_key: bytes):
        if not isinstance(peer_id, str) or not peer_id or len(peer_id) > MAX_ID_LENGTH:
            raise ValueError(f"peer_id must be non-empty string <= {MAX_ID_LENGTH} characters")
        self.identity = identity
        self.peer_id = peer_id
        self.expected_peer_public_key = expected_peer_public_key
        self.expected_peer_signing_public_key = expected_peer_signing_public_key
        self.sender: SenderSession | None = None
        self.receiver: ReceiverSession | None = None
        self.info: SessionInfo | None = None

    def establish(self, presented_peer_public_key: bytes, presented_peer_signing_public_key: bytes,
                  *, session_id: str, context: bytes) -> SessionInfo:
        if not isinstance(session_id, str) or not session_id or len(session_id) > MAX_ID_LENGTH:
            raise ValueError(f"session_id must be non-empty string <= {MAX_ID_LENGTH} characters")
        if not isinstance(context, bytes) or not context or len(context) > MAX_CONTEXT_LENGTH:
            raise ValueError(f"context must be non-empty bytes <= {MAX_CONTEXT_LENGTH} bytes")
        verify_expected_public_key(self.expected_peer_public_key, presented_peer_public_key)
        verify_expected_public_key(self.expected_peer_signing_public_key, presented_peer_signing_public_key)
        peer_public_key = load_public_key(presented_peer_public_key)
        key = derive_session_key(derive_shared_secret(self.identity.private_key, peer_public_key), context=context)
        self.invalidate()
        peer_signing_key = Ed25519PublicKey.from_public_bytes(presented_peer_signing_public_key)
        self.sender = SenderSession(key, session_id, self.identity.identity_id, self.identity.signing_private_key)
        self.receiver = ReceiverSession(key, session_id, self.peer_id, peer_signing_key)
        self.info = SessionInfo(session_id=session_id, context=context)
        return self.info

    def rekey(self, presented_peer_public_key: bytes, presented_peer_signing_public_key: bytes,
              *, context: bytes, session_id: str | None = None) -> SessionInfo:
        """Replace active sessions using a fresh session ID and HKDF context."""
        return self.establish(presented_peer_public_key, presented_peer_signing_public_key,
                              session_id=session_id or str(uuid4()), context=context)

    def invalidate(self) -> None:
        if self.sender is not None:
            self.sender.invalidate()
        if self.receiver is not None:
            self.receiver.invalidate()

    @property
    def public_key_bytes(self) -> bytes:
        return public_key_bytes(self.identity.public_key)
