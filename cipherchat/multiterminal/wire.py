"""Small canonical control-message formats for the LAN lab."""
from __future__ import annotations

import json

from cipherchat.protocol.session import RekeyOffer


def control_bytes(incident: dict[str, object]) -> bytes:
    return b"cipherchat:lab-incident:v1\0" + json.dumps(incident, sort_keys=True, separators=(",", ":")).encode()


def join_bytes(role: str, public: dict[str, str], challenge: str) -> bytes:
    payload = {"role": role, "public": public, "challenge": challenge}
    return b"cipherchat:lab-join:v1\0" + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def offer_to_dict(offer: RekeyOffer) -> dict[str, str]:
    return {"sender_id": offer.sender_id, "peer_id": offer.peer_id,
            "session_id": offer.session_id, "context": offer.context.hex(),
            "exchange_public_key": offer.exchange_public_key.hex(),
            "signature": offer.signature.hex()}


def offer_from_dict(data: dict[str, object]) -> RekeyOffer:
    if not isinstance(data, dict):
        raise ValueError("invalid rekey offer")
    return RekeyOffer(str(data["sender_id"]), str(data["peer_id"]), str(data["session_id"]),
                      bytes.fromhex(data["context"]), bytes.fromhex(data["exchange_public_key"]),
                      bytes.fromhex(data["signature"]))
