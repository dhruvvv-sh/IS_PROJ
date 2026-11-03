"""Pinned-key establishment and authenticated fresh X25519 rekeying."""
from dataclasses import dataclass
from uuid import uuid4
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cipherchat.crypto.identity import Identity
from cipherchat.crypto.kdf import derive_session_key
from cipherchat.crypto.key_exchange import derive_shared_secret, generate_private_key, load_public_key, public_key_bytes
from cipherchat.security.attacks import verify_expected_public_key
from .limits import MAX_CONTEXT_LENGTH, MAX_ID_LENGTH
from .messages import DigitalSignatureError, ReceiverSession, SenderSession, ValidationError


@dataclass(frozen=True)
class SessionInfo:
    """Non-secret description of an established session."""
    session_id: str
    context: bytes
    local_exchange_public_key: bytes
    peer_exchange_public_key: bytes


@dataclass(frozen=True)
class RekeyOffer:
    """An ephemeral X25519 public key bound to pinned signing identities."""
    sender_id: str
    peer_id: str
    session_id: str
    context: bytes
    exchange_public_key: bytes
    signature: bytes

    def signing_bytes(self) -> bytes:
        fields = {
            "sender_id": self.sender_id,
            "peer_id": self.peer_id,
            "session_id": self.session_id,
            "context": self.context.hex(),
            "exchange_public_key": self.exchange_public_key.hex(),
        }
        return b"cipherchat:rekey-offer:v1\0" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


class SessionManager:
    """Owns the active directional sessions for one peer relationship.

    The caller supplies previously verified/pinned peer X25519 and Ed25519
    public keys. Initial establishment checks both pins. Rekeying verifies a
    signed fresh X25519 offer against the pinned Ed25519 key before replacing
    the existing session objects.
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
        self._pending_rekey: tuple[RekeyOffer, X25519PrivateKey] | None = None
        self._used_session_ids: set[str] = set()

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
        self.info = SessionInfo(session_id, context, public_key_bytes(self.identity.public_key), presented_peer_public_key)
        self._pending_rekey = None
        self._used_session_ids.add(session_id)
        return self.info

    def begin_rekey(self, *, session_id: str, context: bytes) -> RekeyOffer:
        """Create a new ephemeral key and sign its public half for the peer."""
        if self.info is None:
            raise ValidationError("establish a session before rekeying")
        if self._pending_rekey is not None:
            raise ValidationError("a rekey is already pending")
        if (not isinstance(session_id, str) or not session_id or len(session_id) > MAX_ID_LENGTH
                or session_id in self._used_session_ids):
            raise ValidationError("rekey requires a new valid session ID")
        if not isinstance(context, bytes) or not context or len(context) > MAX_CONTEXT_LENGTH:
            raise ValidationError("rekey requires a non-empty bounded context")
        ephemeral_private = generate_private_key()
        draft = RekeyOffer(self.identity.identity_id, self.peer_id, session_id, context,
                           public_key_bytes(ephemeral_private.public_key()), b"")
        offer = RekeyOffer(draft.sender_id, draft.peer_id, draft.session_id, draft.context,
                           draft.exchange_public_key, self.identity.signing_private_key.sign(draft.signing_bytes()))
        self._pending_rekey = (offer, ephemeral_private)
        return offer

    def finish_rekey(self, peer_offer: RekeyOffer) -> SessionInfo:
        """Verify the peer's signed ephemeral key before replacing old sessions."""
        if self._pending_rekey is None:
            raise ValidationError("no rekey is pending")
        if not isinstance(peer_offer, RekeyOffer):
            raise ValidationError("peer rekey offer is required")
        local_offer, ephemeral_private = self._pending_rekey
        if (peer_offer.sender_id != self.peer_id or peer_offer.peer_id != self.identity.identity_id
                or peer_offer.session_id != local_offer.session_id or peer_offer.context != local_offer.context):
            raise ValidationError("peer rekey offer does not match the agreed session")
        if peer_offer.exchange_public_key == self.info.peer_exchange_public_key:
            raise ValidationError("peer rekey offer reused the previous X25519 key")
        peer_public = load_public_key(peer_offer.exchange_public_key)
        try:
            Ed25519PublicKey.from_public_bytes(self.expected_peer_signing_public_key).verify(
                peer_offer.signature, peer_offer.signing_bytes()
            )
        except InvalidSignature as error:
            raise DigitalSignatureError("peer rekey offer signature is invalid") from error
        key = derive_session_key(derive_shared_secret(ephemeral_private, peer_public), context=local_offer.context)
        self.invalidate()
        signing_public = Ed25519PublicKey.from_public_bytes(self.expected_peer_signing_public_key)
        self.sender = SenderSession(key, local_offer.session_id, self.identity.identity_id, self.identity.signing_private_key)
        self.receiver = ReceiverSession(key, local_offer.session_id, self.peer_id, signing_public)
        self.info = SessionInfo(local_offer.session_id, local_offer.context,
                                local_offer.exchange_public_key, peer_offer.exchange_public_key)
        self._pending_rekey = None
        self._used_session_ids.add(local_offer.session_id)
        return self.info

    def invalidate(self) -> None:
        if self.sender is not None:
            self.sender.invalidate()
        if self.receiver is not None:
            self.receiver.invalidate()

    @property
    def public_key_bytes(self) -> bytes:
        return public_key_bytes(self.identity.public_key)


def rekey_pair(first: SessionManager, second: SessionManager, *, session_id: str | None = None,
               context: bytes) -> tuple[SessionInfo, SessionInfo]:
    """Coordinate the signed two-offer exchange for local demonstrations."""
    new_session_id = session_id or str(uuid4())
    first_offer = first.begin_rekey(session_id=new_session_id, context=context)
    second_offer = second.begin_rekey(session_id=new_session_id, context=context)
    first_info = first.finish_rekey(second_offer)
    second_info = second.finish_rekey(first_offer)
    return first_info, second_info
