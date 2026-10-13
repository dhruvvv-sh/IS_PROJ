"""Authenticated JSON protocol messages and strict replay protection."""
import base64
import json
from dataclasses import dataclass
from uuid import uuid4
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cipherchat.crypto.encryption import Ciphertext, decrypt, encrypt
from cipherchat.protocol.limits import (
    MAX_CONTEXT_LENGTH,
    MAX_CIPHERTEXT_SIZE,
    MAX_ID_LENGTH,
    MAX_JSON_MESSAGE_SIZE,
    MAX_JSON_REQUEST_SIZE,
    MAX_PLAINTEXT_SIZE,
)

PROTOCOL_VERSION = 2


class ProtocolError(Exception): pass
class ReplayError(ProtocolError): pass
class ValidationError(ProtocolError, ValueError): pass
class SessionInactiveError(ProtocolError): pass
class DigitalSignatureError(ProtocolError): pass


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (AttributeError, ValueError) as error:
        raise ValidationError(f"{field} is not canonical base64") from error


@dataclass(frozen=True)
class EncryptedMessage:
    protocol_version: int
    session_id: str
    sender_id: str
    message_id: str
    sequence_number: int
    nonce: bytes
    ciphertext: bytes
    signature: bytes

    def _wire_fields(self) -> dict[str, object]:
        return {"protocol_version": self.protocol_version, "session_id": self.session_id,
                "sender_id": self.sender_id, "message_id": self.message_id,
                "sequence_number": self.sequence_number, "nonce": _b64(self.nonce),
                "ciphertext": _b64(self.ciphertext)}

    def aad(self) -> bytes:
        """Canonical UTF-8 JSON over authenticated clear-text metadata."""
        meta = {"message_id": self.message_id, "protocol_version": self.protocol_version,
                "sender_id": self.sender_id, "sequence_number": self.sequence_number,
                "session_id": self.session_id}
        return json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict[str, object]:
        return {**self._wire_fields(), "signature": _b64(self.signature)}

    def signing_bytes(self) -> bytes:
        """Canonical, domain-separated bytes covered by the Ed25519 signature."""
        canonical = json.dumps(self._wire_fields(), sort_keys=True, separators=(",", ":"))
        return b"cipherchat:encrypted-message:v2\x00" + canonical.encode("utf-8")

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "EncryptedMessage":
        if not isinstance(raw, str):
            raise ValidationError("raw message must be a string")
        if len(raw.encode("utf-8")) > MAX_JSON_MESSAGE_SIZE:
            raise ValidationError(
                f"message JSON size ({len(raw.encode('utf-8'))} bytes) exceeds maximum limit of {MAX_JSON_MESSAGE_SIZE} bytes"
            )
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as error:
            raise ValidationError("invalid JSON message") from error
        required = {"protocol_version", "session_id", "sender_id", "message_id", "sequence_number", "nonce", "ciphertext", "signature"}
        if not isinstance(value, dict) or set(value) != required:
            raise ValidationError("message fields do not match protocol schema")
        msg = cls(value["protocol_version"], value["session_id"], value["sender_id"], value["message_id"],
                  value["sequence_number"], _unb64(value["nonce"], "nonce"), _unb64(value["ciphertext"], "ciphertext"),
                  _unb64(value["signature"], "signature"))
        msg.validate()
        return msg

    def validate(self) -> None:
        if self.protocol_version != PROTOCOL_VERSION or not all(isinstance(x, str) and x for x in (self.session_id, self.sender_id, self.message_id)):
            raise ValidationError("invalid protocol metadata")
        if any(len(x) > MAX_ID_LENGTH for x in (self.session_id, self.sender_id, self.message_id)):
            raise ValidationError(f"identifier length exceeds maximum allowed limit of {MAX_ID_LENGTH} characters")
        if isinstance(self.sequence_number, bool) or not isinstance(self.sequence_number, int) or self.sequence_number < 1:
            raise ValidationError("sequence_number must be a positive integer")
        if not all(isinstance(value, bytes) for value in (self.nonce, self.ciphertext, self.signature)):
            raise ValidationError("encrypted payload fields must be bytes")
        if len(self.nonce) != 12 or len(self.ciphertext) < 16 or len(self.signature) != 64:
            raise ValidationError("invalid encrypted payload")
        if len(self.ciphertext) > MAX_CIPHERTEXT_SIZE:
            raise ValidationError(
                f"ciphertext size ({len(self.ciphertext)} bytes) exceeds maximum limit of {MAX_CIPHERTEXT_SIZE} bytes"
            )


class SenderSession:
    def __init__(self, key: bytes, session_id: str, sender_id: str, signing_key: Ed25519PrivateKey,
                 max_plaintext_size: int = MAX_PLAINTEXT_SIZE):
        if not isinstance(session_id, str) or not session_id or len(session_id) > MAX_ID_LENGTH:
            raise ValidationError(f"session_id must be non-empty string <= {MAX_ID_LENGTH} characters")
        if not isinstance(sender_id, str) or not sender_id or len(sender_id) > MAX_ID_LENGTH:
            raise ValidationError(f"sender_id must be non-empty string <= {MAX_ID_LENGTH} characters")
        self.key, self.session_id, self.sender_id, self._next_sequence = key, session_id, sender_id, 1
        self.signing_key = signing_key
        self.max_plaintext_size = max_plaintext_size
        self._active = True

    def invalidate(self) -> None:
        """Permanently disable this key/session object after rekeying."""
        self._active = False

    def encrypt(self, plaintext: str) -> EncryptedMessage:
        if not self._active:
            raise SessionInactiveError("session has been invalidated")
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be str")
        plaintext_bytes = plaintext.encode("utf-8")
        if len(plaintext_bytes) > self.max_plaintext_size:
            raise ValidationError(
                f"plaintext size ({len(plaintext_bytes)} bytes) exceeds maximum limit of {self.max_plaintext_size} bytes"
            )
        msg_id, seq = str(uuid4()), self._next_sequence
        provisional = EncryptedMessage(PROTOCOL_VERSION, self.session_id, self.sender_id, msg_id, seq, b"", b"", b"")
        payload = encrypt(self.key, plaintext_bytes, provisional.aad())
        self._next_sequence += 1
        unsigned = EncryptedMessage(PROTOCOL_VERSION, self.session_id, self.sender_id, msg_id, seq, payload.nonce, payload.data, b"")
        return EncryptedMessage(PROTOCOL_VERSION, self.session_id, self.sender_id, msg_id, seq,
                                payload.nonce, payload.data, self.signing_key.sign(unsigned.signing_bytes()))


class ReceiverSession:
    """Strict in-order receiver. Production transports often need a sliding window."""
    def __init__(self, key: bytes, session_id: str, expected_sender_id: str, signing_public_key: Ed25519PublicKey):
        if not isinstance(session_id, str) or not session_id or len(session_id) > MAX_ID_LENGTH:
            raise ValidationError(f"session_id must be non-empty string <= {MAX_ID_LENGTH} characters")
        if not isinstance(expected_sender_id, str) or not expected_sender_id or len(expected_sender_id) > MAX_ID_LENGTH:
            raise ValidationError(f"expected_sender_id must be non-empty string <= {MAX_ID_LENGTH} characters")
        self.key, self.session_id, self.expected_sender_id, self.highest_sequence = key, session_id, expected_sender_id, 0
        self.signing_public_key = signing_public_key
        self._seen_message_ids: set[str] = set()
        self._active = True

    def invalidate(self) -> None:
        """Permanently disable this key/session object after rekeying."""
        self._active = False

    def decrypt(self, message: EncryptedMessage) -> str:
        if not self._active:
            raise SessionInactiveError("session has been invalidated")
        message.validate()
        try:
            self.signing_public_key.verify(message.signature, message.signing_bytes())
        except InvalidSignature as error:
            raise DigitalSignatureError("message signature is invalid") from error
        if message.session_id != self.session_id or message.sender_id != self.expected_sender_id:
            raise ValidationError("message session or sender does not match")
        if message.sequence_number <= self.highest_sequence:
            raise ReplayError("message sequence was already accepted")
        if message.message_id in self._seen_message_ids:
            raise ReplayError("message identifier was already accepted")
        plaintext = decrypt(self.key, Ciphertext(message.nonce, message.ciphertext), message.aad())
        self.highest_sequence = message.sequence_number
        self._seen_message_ids.add(message.message_id)
        return plaintext.decode("utf-8")
