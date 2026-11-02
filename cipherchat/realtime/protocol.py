"""Version 3 network envelope; the existing local version 2 stays intact."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREFIX = b"cipherchat:encrypted-message:v3\x00"
FIELDS = {"protocol_version", "session_id", "conversation_id", "sender_id", "receiver_id",
          "message_id", "sequence_number", "timestamp", "nonce", "ciphertext", "signature"}
AAD_FIELDS = ("protocol_version", "session_id", "conversation_id", "sender_id", "receiver_id",
              "message_id", "sequence_number", "timestamp")


class EnvelopeError(ValueError):
    pass


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def decode_base64(value: str, size: int | None = None) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise EnvelopeError("invalid base64 field") from error
    if size is not None and len(raw) != size:
        raise EnvelopeError("invalid binary field length")
    return raw


def unsigned(envelope: dict) -> dict:
    return {key: envelope[key] for key in FIELDS if key != "signature"}


def aad(envelope: dict) -> bytes:
    return canonical({key: envelope[key] for key in AAD_FIELDS})


def signing_bytes(envelope: dict) -> bytes:
    return PREFIX + canonical(unsigned(envelope))


def validate_envelope(envelope: dict, public_key: bytes, now: datetime | None = None, window_seconds: int = 300) -> None:
    if not isinstance(envelope, dict) or set(envelope) != FIELDS or len(canonical(envelope)) > 262144:
        raise EnvelopeError("invalid envelope schema or size")
    if envelope["protocol_version"] != 3:
        raise EnvelopeError("unsupported protocol version")
    for key in ("session_id", "conversation_id", "sender_id", "receiver_id", "message_id", "timestamp"):
        if not isinstance(envelope[key], str) or not envelope[key] or len(envelope[key]) > 256:
            raise EnvelopeError(f"invalid {key}")
    if envelope["sender_id"] == envelope["receiver_id"]:
        raise EnvelopeError("sender and receiver must differ")
    if envelope["conversation_id"] != "alice-bob" or not envelope["session_id"].startswith("alice-bob:"):
        raise EnvelopeError("unknown conversation or session")
    if {envelope["sender_id"], envelope["receiver_id"]} != {"alice", "bob"}:
        raise EnvelopeError("unknown conversation participants")
    if isinstance(envelope["sequence_number"], bool) or not isinstance(envelope["sequence_number"], int) or envelope["sequence_number"] < 1:
        raise EnvelopeError("invalid sequence number")
    try:
        if str(UUID(envelope["message_id"])) != envelope["message_id"]:
            raise ValueError()
        sent_at = datetime.fromisoformat(envelope["timestamp"].replace("Z", "+00:00"))
        if sent_at.tzinfo is None:
            raise ValueError()
    except ValueError as error:
        raise EnvelopeError("invalid message ID or timestamp") from error
    now = now or datetime.now(timezone.utc)
    if abs((now - sent_at).total_seconds()) > window_seconds:
        raise EnvelopeError("timestamp outside validity window")
    decode_base64(envelope["nonce"], 12)
    ciphertext = decode_base64(envelope["ciphertext"])
    if not 16 <= len(ciphertext) <= 65552:
        raise EnvelopeError("invalid ciphertext length")
    signature = decode_base64(envelope["signature"], 64)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signing_bytes(envelope))
    except (ValueError, InvalidSignature) as error:
        raise EnvelopeError("invalid Ed25519 signature") from error
