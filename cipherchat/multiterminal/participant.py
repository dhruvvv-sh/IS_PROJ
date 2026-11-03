"""Alice or Bob's local UI and encrypted LAN chat client."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Event, RLock, Thread
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cipherchat.crypto.identity import Identity
from cipherchat.protocol.limits import MAX_PLAINTEXT_SIZE
from cipherchat.protocol.messages import EncryptedMessage
from cipherchat.protocol.session import SessionManager
from cipherchat.security.attacks import AttackType, classify_failure, verify_expected_public_key
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.recovery import RecoveryMachine, RecoveryState
from .keys import load_identity, load_peer
from .ui import LabUIHandler
from .wire import control_bytes, join_bytes, offer_from_dict, offer_to_dict


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class ParticipantController:
    def __init__(self, role: str, identity: Identity, peer_public: dict[str, str], relay_url: str) -> None:
        if role not in {"alice", "bob"} or identity.identity_id != role:
            raise ValueError("invalid participant role or identity")
        self.role = role
        self.peer_role = "bob" if role == "alice" else "alice"
        self.identity = identity
        self.peer_public = peer_public
        self.relay_url = relay_url.rstrip("/")
        self.lock = RLock()
        self.stop_event = Event()
        self.session: SessionManager | None = None
        self.session_id: str | None = None
        self.recovery = RecoveryMachine()
        self.evidence = EvidenceLog()
        self.deliveries: list[dict[str, object]] = []
        self.attacks: list[dict[str, object]] = []
        self.events: list[dict[str, object]] = []
        self.revision = 0
        self.connection_error: str | None = None
        public = identity.public_material()
        challenge = self._request("/challenge", {"role": role})["challenge"]
        joined = self._request("/join", {"role": role, "public": public, "challenge": challenge,
                                          "signature": identity.signing_private_key.sign(
                                              join_bytes(role, public, challenge)).hex()})
        self.token = joined["token"]
        self.poll_thread = Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()

    def _request(self, route: str, data: dict[str, object]) -> dict[str, object]:
        raw = json.dumps(data).encode()
        request = Request(self.relay_url + route, data=raw, method="POST",
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=3) as response:
                return json.load(response)
        except HTTPError as error:
            try:
                message = json.load(error).get("error", str(error))
            except (ValueError, OSError):
                message = str(error)
            raise ValueError(f"relay: {message}") from error
        except URLError as error:
            raise ValueError(f"relay unavailable: {error.reason}") from error

    def _auth(self, **data: object) -> dict[str, object]:
        return {"role": self.role, "token": self.token, **data}

    def _event(self, category: str, title: str, data: dict[str, object], explanation: str) -> None:
        self.events.append({"timestamp": now(), "category": category, "step": "NET", "title": title,
                            "data": data, "explanation": explanation})
        self.revision += 1

    def _poll_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                batch = self._request("/poll", self._auth())
                with self.lock:
                    if self.connection_error:
                        self.connection_error = None
                        self._event("NETWORK", "RELAY RECONNECTED", {}, "The relay connection is available again.")
                    for item in batch["events"]:
                        try:
                            self._handle(item)
                        except (ValueError, KeyError, TypeError) as error:
                            self._event("NETWORK", "NETWORK EVENT REJECTED", {"error": str(error)},
                                        "An invalid relay event was rejected; later events can still be processed.")
            except (OSError, URLError, ValueError, KeyError, TypeError) as error:
                with self.lock:
                    message = str(error)
                    if self.connection_error != message:
                        self.connection_error = message
                        self._event("NETWORK", "RELAY UNAVAILABLE", {"error": message},
                                    "Message delivery is paused until the relay returns.")
            self.stop_event.wait(0.2)

    def _handle(self, item: dict[str, object]) -> None:
        kind = item.get("type")
        if kind == "session":
            self._handle_session(item)
        elif kind == "message":
            self._handle_message(item)
        elif kind == "key_substitution":
            self._handle_key_substitution(item)
        elif kind == "delete_evidence":
            self._handle_evidence_deletion(item)
        elif kind == "incident":
            self._handle_incident(item)
        elif kind == "rekey_offer":
            self._handle_rekey_offer(item)

    def _handle_session(self, item: dict[str, object]) -> None:
        presented = item["peer"]
        if presented["identity_id"] != self.peer_role:
            raise ValueError("relay presented the wrong peer identity")
        verify_expected_public_key(bytes.fromhex(self.peer_public["public_key"]), bytes.fromhex(presented["public_key"]))
        verify_expected_public_key(bytes.fromhex(self.peer_public["signing_public_key"]),
                                   bytes.fromhex(presented["signing_public_key"]))
        manager = SessionManager(self.identity, self.peer_role, bytes.fromhex(self.peer_public["public_key"]),
                                 bytes.fromhex(self.peer_public["signing_public_key"]))
        manager.establish(bytes.fromhex(presented["public_key"]), bytes.fromhex(presented["signing_public_key"]),
                          session_id=item["session_id"], context=bytes.fromhex(item["context"]))
        if self.session is not None:
            self.session.invalidate()
        self.session = manager
        self.session_id = item["session_id"]
        self.recovery = RecoveryMachine()
        self.evidence = EvidenceLog()
        self.deliveries = []
        self.attacks = []
        self.events = []
        self._event("SESSION", "SESSION CREATED", {"session_id": self.session_id,
                                                    "peer_public_key": presented["public_key"],
                                                    "peer_signing_public_key": presented["signing_public_key"]},
                    "Pinned peer keys matched; an encrypted session is ready.")

    def send(self, plaintext: str, sender_id: str = "alice") -> dict[str, object]:
        with self.lock:
            if sender_id != self.role:
                raise ValueError(f"this UI can send only as {self.role}")
            if self.session is None or self.recovery.state is not RecoveryState.SECURE or self.connection_error:
                raise ValueError("chat is waiting, quarantined, blocked, or disconnected")
            if not isinstance(plaintext, str) or not plaintext.strip():
                raise ValueError("message must not be empty")
            if len(plaintext.encode()) > MAX_PLAINTEXT_SIZE:
                raise ValueError("message exceeds the maximum size")
            message = self.session.sender.encrypt(plaintext)
            self._request("/send", self._auth(envelope=message.to_dict()))
            self._append_delivery(message, plaintext, self.role, self.peer_role)
            self._event("TRANSMISSION", "MESSAGE TRANSMITTED", {"raw_protocol_message": message.to_dict()},
                        "The encrypted and signed envelope was sent to Eva's relay.")
            return {**self.snapshot(), "message": message.to_dict(), "plaintext": plaintext}

    def _append_delivery(self, message: EncryptedMessage, plaintext: str, sender: str, recipient: str) -> None:
        self.deliveries.append({"timestamp": now(), "sender": sender, "recipient": recipient,
                                "plaintext": plaintext, "message_id": message.message_id,
                                "sequence_number": message.sequence_number, "session_id": message.session_id,
                                "aad_sha256": hashlib.sha256(message.aad()).hexdigest(),
                                "envelope_sha256": hashlib.sha256(message.to_json().encode()).hexdigest(),
                                "signature": message.to_dict()["signature"], "signature_verified": True,
                                "wire_message": message.to_dict()})
        self.revision += 1

    def _handle_message(self, item: dict[str, object]) -> None:
        if self.session is None or self.recovery.state is not RecoveryState.SECURE:
            return
        envelope = item["envelope"]
        message = None
        try:
            message = EncryptedMessage.from_json(json.dumps(envelope))
            plaintext = self.session.receiver.decrypt(message)
        except Exception as error:
            classification = classify_failure(error)
            if classification is AttackType.UNKNOWN:
                classification = AttackType.INVALID_AUTHENTICATION
            self._record_failure(classification, item, message, type(error).__name__)
            return
        self._append_delivery(message, plaintext, self.peer_role, self.role)
        self._event("RECEPTION", "MESSAGE ACCEPTED", {"message_id": message.message_id,
                                                       "sequence_number": message.sequence_number},
                    "The pinned signature, session binding, and ciphertext authentication passed.")

    def _quarantine_or_block(self, block: bool) -> None:
        if self.recovery.state is RecoveryState.SECURE:
            self.recovery.report_violation()
        if block and self.recovery.state is RecoveryState.QUARANTINED:
            self.recovery.begin_verification()
            self.recovery.verification_failed()
        if self.session:
            self.session.invalidate()
        self.revision += 1

    def _record_failure(self, classification: AttackType, item: dict[str, object],
                        message: EncryptedMessage | None, detail: str, *, block: bool = False,
                        classification_label: str | None = None) -> None:
        label = classification_label or classification.value
        record = self.evidence.record(session_id=self.session_id, attack_type=classification,
                                      description=f"Rejected {item.get('attack_name', 'message')}: {detail}",
                                      message_id=message.message_id if message else None,
                                      sequence_number=message.sequence_number if message else None)
        self._quarantine_or_block(block)
        attack_name = str(item.get("attack_name", "message"))
        result = {"timestamp": now(), "attack_type": attack_name.upper(),
                  "classification": label, "detected": True,
                  "evidence_generated": True, "evidence_hash": record.evidence_hash,
                  "recovery_state": self.recovery.state.value, "rekeyed": False,
                  "detail": detail, "attack_id": item.get("attack_id")}
        self.attacks.append(result)
        self._event("RECOVERY", "SECURITY VIOLATION DETECTED", result,
                    "The live chat stopped sending while the incident is handled.")
        incident = {"reporter": self.role, "classification": label,
                    "recovery_state": self.recovery.state.value, "session_id": self.session_id,
                    "message_id": record.message_id, "evidence_hash": record.evidence_hash,
                    "attack_id": item.get("attack_id"), "detail": detail}
        signed = {"incident": incident,
                  "signature": self.identity.signing_private_key.sign(control_bytes(incident)).hex()}
        self._request("/incident", self._auth(signed=signed))

    def _handle_key_substitution(self, item: dict[str, object]) -> None:
        try:
            verify_expected_public_key(bytes.fromhex(self.peer_public["public_key"]), bytes.fromhex(item["public_key"]))
        except Exception as error:
            self._record_failure(AttackType.KEY_SUBSTITUTION, item, None, type(error).__name__, block=True)

    def _handle_evidence_deletion(self, item: dict[str, object]) -> None:
        if not self.evidence.records:
            raise ValueError("no local evidence exists to test deletion")
        checkpoint = self.evidence.checkpoint()
        if verify_evidence_chain(self.evidence.records[:-1], checkpoint):
            raise ValueError("deletion was not detected")
        self._record_failure(AttackType.TAMPERING, item, None, "EvidenceDeletionDetected",
                             block=True, classification_label="EVIDENCE_TAMPERING")

    def _handle_incident(self, item: dict[str, object]) -> None:
        signed = item["signed"]
        incident = signed["incident"]
        if incident.get("reporter") != self.peer_role or incident.get("session_id") != self.session_id:
            raise ValueError("incident did not match the pinned peer or session")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.peer_public["signing_public_key"])).verify(
                bytes.fromhex(signed["signature"]), control_bytes(incident))
        except InvalidSignature as error:
            raise ValueError("peer incident signature is invalid") from error
        classification = str(incident["classification"])
        block = classification in {"KEY_SUBSTITUTION", "EVIDENCE_TAMPERING"}
        attack_type = AttackType.TAMPERING if classification == "EVIDENCE_TAMPERING" else AttackType(classification)
        self.evidence.record(session_id=self.session_id, attack_type=attack_type,
                             description=f"Pinned peer reported {classification}",
                             message_id=incident.get("message_id"))
        self._quarantine_or_block(block)
        self._event("RECOVERY", "PEER INCIDENT VERIFIED", {"classification": classification,
                                                           "state": self.recovery.state.value},
                    "The peer's signed incident synchronized the chat recovery state.")

    def recover(self) -> dict[str, object]:
        with self.lock:
            if self.recovery.state is not RecoveryState.QUARANTINED or self.session is None:
                raise ValueError("only a quarantined chat can be rekeyed")
            self.recovery.begin_verification()
            self.recovery.verification_succeeded()
            new_id = str(uuid4())
            context = ("cipherchat-lab-rekey:" + new_id).encode()
            offer = self.session.begin_rekey(session_id=new_id, context=context)
            self._request("/rekey-offer", self._auth(offer=offer_to_dict(offer)))
            self._event("REKEY", "REKEY OFFER SENT", {"session_id": new_id,
                                                       "exchange_public_key": offer.exchange_public_key.hex()},
                        "A fresh signed X25519 public key was sent to the peer.")
            return self.snapshot()

    def _handle_rekey_offer(self, item: dict[str, object]) -> None:
        if self.session is None:
            return
        offer = offer_from_dict(item["offer"])
        own_offer = None
        if self.recovery.state is RecoveryState.QUARANTINED:
            self.recovery.begin_verification()
            self.recovery.verification_succeeded()
            own_offer = self.session.begin_rekey(session_id=offer.session_id, context=offer.context)
        elif self.recovery.state is not RecoveryState.REKEYING:
            raise ValueError("rekey offer arrived outside recovery")
        old_id = self.session_id
        old_public = self.session.info.local_exchange_public_key
        self.session.finish_rekey(offer)
        if own_offer is not None:
            self._request("/rekey-offer", self._auth(offer=offer_to_dict(own_offer)))
        self._request("/status", self._auth(status="SECURE"))
        self.session_id = offer.session_id
        self.recovery.rekey_complete()
        self._event("REKEY", "LIVE CHAT REKEYED", {"old_session_id": old_id,
                                                   "new_session_id": self.session_id,
                                                   "fresh_x25519": self.session.info.local_exchange_public_key != old_public},
                    "The old session was invalidated and a fresh signed X25519 exchange completed.")

    def attack(self, *_: object) -> dict[str, object]:
        raise ValueError("attacker controls are available only in Eva's UI")

    def establish(self) -> dict[str, object]:
        self._request("/reset", self._auth())
        return self.snapshot()

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            checkpoint = self.evidence.checkpoint()
            sender = self.session.sender if self.session else None
            return {"role": self.role, "revision": self.revision,
                    "connection_error": self.connection_error,
                    "recovery": {"state": self.recovery.state.value if self.session else "WAITING",
                                 "history": [state.value for state in self.recovery.history]},
                    "session": {"session_id": self.session_id,
                                "key_exchange": "X25519", "kdf": "HKDF-SHA-256", "encryption": "AES-256-GCM",
                                "session_key": sender.key.hex() if sender else None},
                    "deliveries": list(self.deliveries), "attacks": list(self.attacks),
                    "evidence": {"records": [asdict(record) for record in self.evidence.records],
                                 "checkpoint": asdict(checkpoint),
                                 "chain_valid": verify_evidence_chain(self.evidence.records, checkpoint)},
                    "events": list(self.events)}

    def export_logs(self) -> dict[str, object]:
        result = self.snapshot()
        result["session"].pop("session_key", None)
        return {"format": "cipherchat-lab-participant-v1", "exported_at": now(), **result}

    def close(self) -> None:
        self.stop_event.set()
        self.poll_thread.join(timeout=4)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Alice or Bob's local CipherChat LAN UI")
    parser.add_argument("--role", choices=("alice", "bob"), required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--peer", type=Path, required=True)
    parser.add_argument("--relay", required=True, help="Eva's relay URL, such as http://192.168.1.10:8765")
    parser.add_argument("--ui-port", type=int, default=8000)
    parser.add_argument("--audit", type=Path)
    args = parser.parse_args()
    peer_role = "bob" if args.role == "alice" else "alice"
    controller = ParticipantController(args.role, load_identity(args.identity, args.role),
                                       load_peer(args.peer, peer_role), args.relay)
    audit_path = args.audit or args.identity.parent / f"{args.role}-audit.json"
    handler = type("ParticipantUIHandler", (LabUIHandler,), {
        "controller": controller, "audit_logs": [], "live_log_path": audit_path,
        "last_persisted_revision": -1,
    })
    server = ThreadingHTTPServer(("127.0.0.1", args.ui_port), handler)
    print(f"{args.role.title()} UI: http://127.0.0.1:{args.ui_port}")
    print(f"Relay: {args.relay}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        controller.close()


if __name__ == "__main__":
    main()
