"""LAN relay and Eva's local UI for the three-person teaching lab."""
from __future__ import annotations

import argparse
import base64
import json
from dataclasses import asdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from secrets import token_urlsafe
from threading import RLock, Thread
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cipherchat.crypto.key_exchange import generate_private_key, public_key_bytes
from cipherchat.protocol.limits import MAX_REQUEST_BODY_SIZE
from cipherchat.security.attacks import AttackType
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from .ui import LabUIHandler
from .wire import control_bytes, join_bytes


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class RelayState:
    def __init__(self) -> None:
        self.lock = RLock()
        self.peers: dict[str, dict[str, str]] = {}
        self.tokens: dict[str, str] = {}
        self.challenges: dict[str, str] = {}
        self.queues: dict[str, list[dict[str, object]]] = {"alice": [], "bob": []}
        self.status: dict[str, str] = {"alice": "WAITING", "bob": "WAITING"}
        self.session_id: str | None = None
        self.context: str | None = None
        self.last_packet: dict[str, object] | None = None
        self.last_incident_role: str | None = None
        self.pending_rekey_id: str | None = None
        self.pending_rekey_context: str | None = None
        self.rekey_offers: set[str] = set()
        self.attacks: list[dict[str, object]] = []
        self.events: list[dict[str, object]] = []
        self.evidence = EvidenceLog()
        self.revision = 0

    def _event(self, title: str, data: dict[str, object]) -> None:
        self.events.append({"timestamp": now(), "category": "RELAY", "step": "NET",
                            "title": title, "data": data, "explanation": "Eva's relay recorded a lab network event."})
        self.revision += 1

    def _require(self, role: str, token: str) -> None:
        if role not in {"alice", "bob"} or self.tokens.get(role) != token:
            raise ValueError("invalid participant token")

    def _new_session(self) -> None:
        if set(self.peers) != {"alice", "bob"}:
            raise ValueError("Alice and Bob must both connect first")
        self.session_id = str(uuid4())
        self.context = ("cipherchat-lab:" + self.session_id).encode().hex()
        self.last_packet = None
        self.last_incident_role = None
        self.pending_rekey_id = None
        self.pending_rekey_context = None
        self.rekey_offers.clear()
        self.attacks = []
        self.evidence = EvidenceLog()
        self.events = []
        self.revision += 1
        self.status = {"alice": "SECURE", "bob": "SECURE"}
        for role, peer_role in (("alice", "bob"), ("bob", "alice")):
            self.queues[role].clear()
            self.queues[role].append({"type": "session", "session_id": self.session_id,
                                      "context": self.context, "peer": self.peers[peer_role]})
        self._event("SESSION READY", {"session_id": self.session_id})

    def challenge(self, role: str) -> dict[str, str]:
        with self.lock:
            if role not in {"alice", "bob"}:
                raise ValueError("invalid participant role")
            nonce = token_urlsafe(32)
            self.challenges[role] = nonce
            return {"challenge": nonce}

    def join(self, role: str, public: dict[str, str], challenge: str, signature: str) -> dict[str, object]:
        with self.lock:
            if role not in {"alice", "bob"} or not isinstance(public, dict) or public.get("identity_id") != role:
                raise ValueError("invalid participant identity")
            for field in ("public_key", "signing_public_key"):
                if not isinstance(public.get(field), str) or len(public[field]) != 64:
                    raise ValueError("invalid participant public keys")
                bytes.fromhex(public[field])
            if not isinstance(challenge, str) or self.challenges.get(role) != challenge:
                raise ValueError("join challenge is missing or expired")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(public["signing_public_key"])).verify(
                    bytes.fromhex(signature), join_bytes(role, public, challenge))
            except (InvalidSignature, ValueError, TypeError) as error:
                raise ValueError("join signature is invalid") from error
            if role in self.peers and self.peers[role] != public:
                raise ValueError(f"{role} is already registered with a different identity")
            self.challenges.pop(role, None)
            self.peers[role] = public
            self.tokens[role] = token_urlsafe(32)
            self.queues[role].clear()
            self._event("PARTICIPANT CONNECTED", {"role": role})
            if len(self.peers) == 2:
                self._new_session()
            return {"token": self.tokens[role], "role": role}

    def poll(self, role: str, token: str) -> dict[str, object]:
        with self.lock:
            self._require(role, token)
            events = list(self.queues[role])
            self.queues[role].clear()
            return {"events": events}

    def send(self, role: str, token: str, envelope: dict[str, object]) -> dict[str, object]:
        with self.lock:
            self._require(role, token)
            recipient = "bob" if role == "alice" else "alice"
            if self.status[role] != "SECURE" or self.status[recipient] != "SECURE":
                raise ValueError("chat is not secure")
            if not isinstance(envelope, dict) or envelope.get("sender_id") != role or envelope.get("session_id") != self.session_id:
                raise ValueError("invalid encrypted envelope routing")
            packet = {"type": "message", "sender": role, "recipient": recipient, "envelope": envelope}
            self.queues[recipient].append(packet)
            self.last_packet = packet
            self._event("ENCRYPTED MESSAGE FORWARDED", {"sender": role, "recipient": recipient,
                                                        "message_id": envelope.get("message_id")})
            return {"queued": True}

    def attack(self, name: str) -> dict[str, object]:
        with self.lock:
            fields = {"ciphertext", "nonce", "sequence_number", "message_id", "session_id", "sender_id"}
            if name == "delete_evidence":
                if self.last_incident_role is None:
                    raise ValueError("Run a message attack and wait for evidence first")
                target = self.last_incident_role
                packet = {"type": "delete_evidence"}
            elif name == "key_substitution":
                if len(self.peers) != 2:
                    raise ValueError("Alice and Bob must connect first")
                if self.status["alice"] != "SECURE" or self.status["bob"] != "SECURE":
                    raise ValueError("Recover or reset the chat before another attack")
                target = "alice"
                fake_key = public_key_bytes(generate_private_key().public_key()).hex()
                packet = {"type": "key_substitution", "public_key": fake_key}
            else:
                if self.last_packet is None:
                    raise ValueError("Send a chat message before replay or tampering")
                target = str(self.last_packet["recipient"])
                if self.status["alice"] != "SECURE" or self.status["bob"] != "SECURE":
                    raise ValueError("Recover the chat before another message attack")
                envelope = dict(self.last_packet["envelope"])
                if name == "replay":
                    pass
                elif name.startswith("tamper_") and name.removeprefix("tamper_") in fields:
                    field = name.removeprefix("tamper_")
                    if field in {"ciphertext", "nonce"}:
                        raw = bytearray(base64.b64decode(envelope[field], validate=True))
                        raw[0] ^= 1
                        envelope[field] = base64.b64encode(raw).decode()
                    elif field == "sequence_number":
                        envelope[field] = int(envelope[field]) + 1
                    else:
                        envelope[field] = "mallory" if field == "sender_id" else f"altered-{uuid4()}"
                else:
                    raise ValueError("unsupported attack")
                packet = {"type": "message", "sender": self.last_packet["sender"],
                          "recipient": target, "envelope": envelope}
            attack_id = str(uuid4())
            packet["attack_id"] = attack_id
            packet["attack_name"] = name
            if name == "key_substitution":
                self.queues["alice"].append(dict(packet))
                self.queues["bob"].append(dict(packet))
            else:
                self.queues[target].append(packet)
            result = {"attack_id": attack_id, "attack_type": name.upper(), "classification": "PENDING",
                      "detected": False, "evidence_generated": False, "evidence_hash": None,
                      "recovery_state": "PENDING", "rekeyed": False, "detail": "Attack delivered to the participant; awaiting verification.",
                      "timestamp": now(), "target": target}
            self.attacks.append(result)
            self._event("ATTACK SENT", {"attack": name, "target": target, "attack_id": attack_id})
            return result

    def incident(self, role: str, token: str, signed: dict[str, object]) -> dict[str, object]:
        with self.lock:
            self._require(role, token)
            if not isinstance(signed, dict) or not isinstance(signed.get("incident"), dict):
                raise ValueError("invalid incident")
            incident = signed["incident"]
            if incident.get("reporter") != role:
                raise ValueError("incident reporter mismatch")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.peers[role]["signing_public_key"])).verify(
                    bytes.fromhex(signed["signature"]), control_bytes(incident))
            except (InvalidSignature, ValueError, KeyError, TypeError) as error:
                raise ValueError("incident signature is invalid") from error
            attack_type = AttackType.TAMPERING if incident["classification"] == "EVIDENCE_TAMPERING" else AttackType(incident["classification"])
            peer = "bob" if role == "alice" else "alice"
            self.queues[peer].append({"type": "incident", "signed": signed})
            self.status[role] = str(incident["recovery_state"])
            self.status[peer] = str(incident["recovery_state"])
            self.last_incident_role = role
            record = self.evidence.record(session_id=str(incident["session_id"]), attack_type=attack_type,
                                          description=f"{role} reported {incident['classification']}",
                                          message_id=incident.get("message_id"))
            for attack in reversed(self.attacks):
                if attack["attack_id"] == incident.get("attack_id"):
                    attack.update({"classification": incident["classification"], "detected": True,
                                   "evidence_generated": True, "evidence_hash": incident["evidence_hash"],
                                   "recovery_state": incident["recovery_state"], "detail": incident["detail"]})
                    break
            self._event("INCIDENT REPORTED", {"reporter": role, "classification": incident["classification"],
                                              "relay_evidence_hash": record.evidence_hash})
            return {"accepted": True}

    def rekey_offer(self, role: str, token: str, offer: dict[str, object]) -> dict[str, object]:
        with self.lock:
            self._require(role, token)
            if not isinstance(offer, dict) or offer.get("sender_id") != role:
                raise ValueError("invalid rekey offer routing")
            new_id, context = offer.get("session_id"), offer.get("context")
            if not isinstance(new_id, str) or not isinstance(context, str) or new_id == self.session_id:
                raise ValueError("rekey offer needs a new session and context")
            if self.pending_rekey_id is None:
                self.pending_rekey_id, self.pending_rekey_context = new_id, context
            elif (new_id, context) != (self.pending_rekey_id, self.pending_rekey_context):
                raise ValueError("rekey offers do not agree")
            self.rekey_offers.add(role)
            peer = "bob" if role == "alice" else "alice"
            self.queues[peer].append({"type": "rekey_offer", "offer": offer})
            self._event("REKEY OFFER FORWARDED", {"sender": role, "recipient": peer})
            return {"queued": True}

    def set_status(self, role: str, token: str, status: str) -> dict[str, object]:
        with self.lock:
            self._require(role, token)
            if status not in {"SECURE", "QUARANTINED", "BLOCKED", "REKEYING"}:
                raise ValueError("invalid status")
            self.status[role] = status
            if status == "SECURE":
                if self.status["alice"] == self.status["bob"] == "SECURE" and self.rekey_offers == {"alice", "bob"}:
                    self.session_id = self.pending_rekey_id
                    self.context = self.pending_rekey_context
                    self.pending_rekey_id = None
                    self.pending_rekey_context = None
                    self.rekey_offers.clear()
                    self.last_packet = None
                    self._event("REKEY COMMITTED", {"session_id": self.session_id})
                for attack in reversed(self.attacks):
                    if attack["recovery_state"] == "QUARANTINED":
                        attack.update({"recovery_state": "SECURE", "rekeyed": True})
                        break
            self._event("PARTICIPANT STATUS", {"role": role, "state": status})
            return {"accepted": True}

    def reset(self) -> dict[str, object]:
        with self.lock:
            self._new_session()
            return {"session_id": self.session_id}

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            checkpoint = self.evidence.checkpoint()
            return {"role": "eva", "revision": self.revision,
                    "recovery": {"state": "SECURE", "history": ["SECURE"]},
                    "session": {"session_id": self.session_id},
                    "participants": dict(self.status), "deliveries": [],
                    "attacks": [dict(item) for item in self.attacks],
                    "evidence": {"records": [asdict(item) for item in self.evidence.records],
                                 "checkpoint": asdict(checkpoint),
                                 "chain_valid": verify_evidence_chain(self.evidence.records, checkpoint)},
                    "events": list(self.events)}


class RelayHandler(BaseHTTPRequestHandler):
    state: RelayState

    def log_message(self, format: str, *args: object) -> None:
        if self.path != "/poll":
            super().log_message(format, *args)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._reply({"ready": True})
        else:
            self._reply({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > MAX_REQUEST_BODY_SIZE:
                raise ValueError("invalid request size")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("request must be a JSON object")
            route = self.path
            if route == "/challenge":
                result = self.state.challenge(data.get("role"))
            elif route == "/join":
                result = self.state.join(data.get("role"), data.get("public"),
                                         data.get("challenge"), data.get("signature"))
            elif route == "/poll":
                result = self.state.poll(data.get("role"), data.get("token"))
            elif route == "/send":
                result = self.state.send(data.get("role"), data.get("token"), data.get("envelope"))
            elif route == "/incident":
                result = self.state.incident(data.get("role"), data.get("token"), data.get("signed"))
            elif route == "/rekey-offer":
                result = self.state.rekey_offer(data.get("role"), data.get("token"), data.get("offer"))
            elif route == "/status":
                result = self.state.set_status(data.get("role"), data.get("token"), data.get("status"))
            elif route == "/reset":
                self.state._require(data.get("role"), data.get("token"))
                result = self.state.reset()
            else:
                self._reply({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            self._reply(result)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            self._reply({"error": str(error)}, HTTPStatus.BAD_REQUEST)

    def _reply(self, data: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


class EvaController:
    def __init__(self, relay: RelayState) -> None:
        self.relay = relay

    def snapshot(self) -> dict[str, object]:
        return self.relay.snapshot()

    def export_logs(self) -> dict[str, object]:
        return {"format": "cipherchat-lab-relay-v1", "exported_at": now(), **self.snapshot()}

    def attack(self, name: str) -> dict[str, object]:
        result = self.relay.attack(name)
        return {**self.snapshot(), "attack": result}

    def establish(self) -> dict[str, object]:
        self.relay.reset()
        return self.snapshot()

    def send(self, *_: object) -> dict[str, object]:
        raise ValueError("Eva cannot send as Alice or Bob")

    def recover(self) -> dict[str, object]:
        raise ValueError("recovery belongs to Alice and Bob")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Eva's CipherChat LAN relay and local attacker UI")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--ui-port", type=int, default=8000)
    parser.add_argument("--audit", type=Path, default=Path(".cipherchat-lab/eva-audit.json"))
    args = parser.parse_args()
    relay = RelayState()
    handler = type("LabRelayHandler", (RelayHandler,), {"state": relay})
    relay_server = ThreadingHTTPServer((args.host, args.port), handler)
    relay_thread = Thread(target=relay_server.serve_forever, daemon=True)
    relay_thread.start()
    ui_handler = type("EvaUIHandler", (LabUIHandler,), {
        "controller": EvaController(relay), "audit_logs": [], "live_log_path": args.audit,
        "last_persisted_revision": -1,
    })
    ui_server = ThreadingHTTPServer(("127.0.0.1", args.ui_port), ui_handler)
    print(f"Relay listening on {args.host}:{args.port}")
    print(f"Eva UI: http://127.0.0.1:{args.ui_port}")
    try:
        ui_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ui_server.server_close()
        relay_server.shutdown()
        relay_server.server_close()
        relay_thread.join()


if __name__ == "__main__":
    main()
