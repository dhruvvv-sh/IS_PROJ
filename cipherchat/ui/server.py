"""Local-only HTTP server exposing CipherChat execution traces for the demo UI."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from time import perf_counter_ns
from urllib.parse import urlparse
from uuid import uuid4

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.limits import (
    MAX_CONTEXT_LENGTH,
    MAX_CIPHERTEXT_SIZE,
    MAX_ID_LENGTH,
    MAX_JSON_MESSAGE_SIZE,
    MAX_REQUEST_BODY_SIZE,
    MAX_PLAINTEXT_SIZE,
)
from cipherchat.protocol.messages import ProtocolError
from cipherchat.protocol.session import SessionManager, rekey_pair
from cipherchat.security.attacks import AttackType
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.recovery import RecoveryMachine, RecoveryState
from cipherchat.security.simulator import AttackSimulator

STATIC_DIR = Path(__file__).with_name("static")
LIVE_LOG_PATH = Path(__file__).resolve().parents[2] / "security_test_results" / "attack_simulation.json"


def _write_live_logs(controller: "DemonstrationController", audit_logs: list[dict[str, object]], path: Path) -> None:
    """Atomically persist the current port-8000 demonstration and request history."""
    payload = controller.export_logs()
    payload["http_audit_logs"] = list(audit_logs)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary_path.replace(path)


@dataclass(frozen=True)
class ObservationEvent:
    timestamp: str
    category: str
    step: str
    title: str
    data: dict[str, object]
    explanation: str


def _event(category: str, step: str, title: str, data: dict[str, object], explanation: str) -> ObservationEvent:
    return ObservationEvent(datetime.now(timezone.utc).isoformat(timespec="milliseconds"), category, step, title, data, explanation)


class DemonstrationController:
    """Stateful local demo facade; all cryptographic values originate in Python."""
    def __init__(self) -> None:
        self.alice: Identity | None = None
        self.bob: Identity | None = None
        self.alice_sessions: SessionManager | None = None
        self.bob_sessions: SessionManager | None = None
        self.session_id: str | None = None
        self.events: list[ObservationEvent] = []
        self.deliveries: list[dict[str, object]] = []
        self.attacks: list[dict[str, object]] = []
        self.pending_attack_index: int | None = None
        self.evidence = EvidenceLog()
        self.recovery = RecoveryMachine()
        self.establish()

    def establish(self) -> dict[str, object]:
        self.alice, self.bob = Identity.create("alice"), Identity.create("bob")
        self.alice_sessions = SessionManager(self.alice, self.bob.identity_id, public_key_bytes(self.bob.public_key), self.bob.signing_public_key_bytes)
        self.bob_sessions = SessionManager(self.bob, self.alice.identity_id, public_key_bytes(self.alice.public_key), self.alice.signing_public_key_bytes)
        self.session_id = str(uuid4())
        self.deliveries = []
        self.attacks = []
        self.pending_attack_index = None
        self.evidence = EvidenceLog()
        self.recovery = RecoveryMachine()
        context = b"cipherchat-ui-demo:" + self.session_id.encode()
        self.alice_sessions.establish(public_key_bytes(self.bob.public_key), self.bob.signing_public_key_bytes, session_id=self.session_id, context=context)
        self.bob_sessions.establish(public_key_bytes(self.alice.public_key), self.alice.signing_public_key_bytes, session_id=self.session_id, context=context)
        sender = self.alice_sessions.sender
        assert sender is not None
        self.events = [
            _event("SESSION", "01", "SESSION CREATED", {"session_id": self.session_id}, "A fresh local demonstration session is ready."),
            _event("KEY_EXCHANGE", "02", "X25519 COMPLETE", {
                "alice_public_key": public_key_bytes(self.alice.public_key).hex(),
                "bob_public_key": public_key_bytes(self.bob.public_key).hex(),
                "alice_signing_public_key": self.alice.signing_public_key_bytes.hex(),
                "bob_signing_public_key": self.bob.signing_public_key_bytes.hex(),
                "private_keys": "NOT DISPLAYED",
            }, "Pinned X25519 and Ed25519 public keys are exchanged; private identity keys remain hidden."),
            _event("KDF", "03", "HKDF SESSION KEY DERIVED", {
                "algorithm": "HKDF-SHA-256", "domain": "cipherchat-v1",
                "session_key": sender.key.hex(), "label": "LOCAL DEMONSTRATION VALUE",
            }, "The ECDH output is processed by HKDF before use as an AES key."),
        ]
        return self.snapshot()

    def snapshot(self) -> dict[str, object]:
        sender = self.alice_sessions.sender if self.alice_sessions else None
        checkpoint = self.evidence.checkpoint()
        return {
            "demonstration_mode": True,
            "recovery": {"state": self.recovery.state.value,
                         "history": [state.value for state in self.recovery.history]},
            "session": {
                "session_id": self.session_id, "key_exchange": "X25519", "kdf": "HKDF-SHA-256",
                "encryption": "AES-256-GCM", "session_key": sender.key.hex() if sender else None,
                "alice_public_key": public_key_bytes(self.alice.public_key).hex() if self.alice else None,
                "bob_public_key": public_key_bytes(self.bob.public_key).hex() if self.bob else None,
                "alice_signing_public_key": self.alice.signing_public_key_bytes.hex() if self.alice else None,
                "bob_signing_public_key": self.bob.signing_public_key_bytes.hex() if self.bob else None,
                "private_keys": "NOT DISPLAYED",
            },
            "deliveries": self.deliveries,
            "attacks": self.attacks,
            "evidence": {
                "records": [asdict(record) for record in self.evidence.records],
                "checkpoint": asdict(checkpoint),
                "chain_valid": verify_evidence_chain(self.evidence.records, checkpoint),
            },
            "events": [asdict(event) for event in self.events],
        }

    def export_logs(self) -> dict[str, object]:
        """Export comprehensive demonstration audit logs in JSON format."""
        sender = self.alice_sessions.sender if self.alice_sessions else None
        checkpoint = self.evidence.checkpoint()
        return {
            "format": "cipherchat-demonstration-logs-v1",
            "exported_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "session_id": self.session_id,
            "recovery": {"state": self.recovery.state.value,
                         "history": [state.value for state in self.recovery.history]},
            "system_limits": {
                "max_plaintext_size": MAX_PLAINTEXT_SIZE,
                "max_ciphertext_size": MAX_CIPHERTEXT_SIZE,
                "max_request_body_size": MAX_REQUEST_BODY_SIZE,
                "max_json_message_size": MAX_JSON_MESSAGE_SIZE,
                "max_id_length": MAX_ID_LENGTH,
                "max_context_length": MAX_CONTEXT_LENGTH,
            },
            "session": {
                "session_id": self.session_id, "key_exchange": "X25519", "kdf": "HKDF-SHA-256",
                "encryption": "AES-256-GCM", "session_key": sender.key.hex() if sender else None,
                "alice_public_key": public_key_bytes(self.alice.public_key).hex() if self.alice else None,
                "bob_public_key": public_key_bytes(self.bob.public_key).hex() if self.bob else None,
                "alice_signing_public_key": self.alice.signing_public_key_bytes.hex() if self.alice else None,
                "bob_signing_public_key": self.bob.signing_public_key_bytes.hex() if self.bob else None,
            },
            "deliveries": self.deliveries,
            "attacks": self.attacks,
            "evidence": self.evidence.to_dict(),
            "events": [asdict(event) for event in self.events],
        }

    def send(self, plaintext: str, sender_id: str = "alice") -> dict[str, object]:
        if self.recovery.state is not RecoveryState.SECURE:
            raise ValueError(f"chat is {self.recovery.state.value.lower()}; sending is disabled")
        if not isinstance(plaintext, str) or not plaintext.strip():
            raise ValueError("message must not be empty")
        encoded_pt = plaintext.encode("utf-8")
        if len(encoded_pt) > MAX_PLAINTEXT_SIZE:
            raise ValueError(f"message size ({len(encoded_pt)} bytes) exceeds maximum limit of {MAX_PLAINTEXT_SIZE} bytes")
        if sender_id not in {"alice", "bob"}:
            raise ValueError("sender must be alice or bob")
        if len(sender_id) > MAX_ID_LENGTH:
            raise ValueError(f"sender exceeds maximum length of {MAX_ID_LENGTH} characters")
        assert self.alice_sessions and self.bob_sessions
        if sender_id == "alice":
            sender, receiver = self.alice_sessions.sender, self.bob_sessions.receiver
            recipient_id = "bob"
        else:
            sender, receiver = self.bob_sessions.sender, self.alice_sessions.receiver
            recipient_id = "alice"
        assert sender and receiver
        message = sender.encrypt(plaintext)
        aad = message.aad()
        accepted = receiver.decrypt(message)
        envelope_sha256 = hashlib.sha256(message.to_json().encode("utf-8")).hexdigest()
        self.deliveries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "sender": sender_id, "recipient": recipient_id, "plaintext": accepted,
            "message_id": message.message_id, "sequence_number": message.sequence_number,
            "session_id": message.session_id, "aad_sha256": hashlib.sha256(aad).hexdigest(),
            "envelope_sha256": envelope_sha256, "signature": message.to_dict()["signature"],
            "signature_verified": True, "wire_message": message.to_dict(),
        })
        sender_name, recipient_name = sender_id.title(), recipient_id.title()
        self.events.extend([
            _event("MESSAGE", "04", "MESSAGE CREATED", {"sender": sender_name, "recipient": recipient_name, "plaintext": plaintext, "message_id": message.message_id, "sequence_number": message.sequence_number}, "A random UUID and monotonically increasing sequence identify this message."),
            _event("AAD", "05", "CANONICAL AAD CONSTRUCTED", {"aad_json": json.loads(aad), "aad_utf8": aad.decode("utf-8")}, "AAD authenticates routing and replay metadata without encrypting it."),
            _event("ENCRYPTION", "06", "AES-256-GCM ENCRYPTION", {"algorithm": "AES-256-GCM", "nonce": message.nonce.hex(), "ciphertext": message.ciphertext[:-16].hex(), "authentication_tag": message.ciphertext[-16:].hex(), "ciphertext_and_tag": message.ciphertext.hex(), "session_key": sender.key.hex(), "label": "LOCAL DEMONSTRATION VALUES"}, "A fresh nonce and the session key protect the plaintext and authenticate the AAD."),
            _event("SIGNATURE", "07", "ED25519 SIGNATURE CREATED", {"algorithm": "Ed25519", "signature": message.signature.hex(), "signed_bytes_sha256": hashlib.sha256(message.signing_bytes()).hexdigest()}, "The sender signs the complete canonical encrypted envelope with its private identity key."),
            _event("TRANSMISSION", "08", "MESSAGE TRANSMITTED", {"raw_protocol_message": message.to_dict(), "raw_json": message.to_json()}, "The serialized protocol message carries metadata, nonce, ciphertext, and signature."),
            _event("RECEPTION", "09", f"{recipient_name.upper()} RECEIVED MESSAGE", {"session_id": message.session_id, "sender_id": message.sender_id}, f"{recipient_name} passed the received object to the real protocol receiver."),
            _event("SIGNATURE", "10", "ED25519 SIGNATURE VERIFIED", {"signature_valid": True, "expected_sender": sender_id}, "The receiver verified authorship against the sender's pinned Ed25519 public key before decryption."),
            _event("VALIDATION", "11", "REPLAY AND SESSION VALIDATION", {"session_valid": True, "sender_valid": True, "message_id": message.message_id, "sequence_number": message.sequence_number, "replay_result": "NOT PREVIOUSLY ACCEPTED"}, "The receiver checks its session binding and replay caches before accepting the message."),
            _event("DECRYPTION", "12", "AES-GCM AUTHENTICATION AND DECRYPTION", {"authentication": "VALID", "plaintext_recovered": accepted}, "The GCM tag authenticated the ciphertext and AAD before plaintext was returned."),
            _event("MESSAGE", "13", "MESSAGE ACCEPTED", {"message_id": message.message_id, "sequence_number": message.sequence_number}, f"{recipient_name} accepted the signed, authenticated, non-replayed message."),
        ])
        return {**self.snapshot(), "message": message.to_dict(), "plaintext": accepted}

    def attack(self, name: str) -> dict[str, object]:
        if not isinstance(name, str) or len(name) > MAX_ID_LENGTH:
            raise ValueError("unsupported attack")
        if name == "delete_evidence":
            return self._simulate_evidence_deletion()
        if self.recovery.state is not RecoveryState.SECURE:
            raise ValueError(f"chat is {self.recovery.state.value.lower()}; recover or start a new session first")
        simulator = AttackSimulator()
        if name == "replay": result = simulator.simulate_replay()
        elif name == "key_substitution": result = simulator.simulate_key_substitution()
        elif name.startswith("tamper_"):
            field = name.removeprefix("tamper_")
            if field not in {"ciphertext", "nonce", "sequence_number", "message_id", "session_id", "sender_id"}:
                raise ValueError("unsupported tampering field")
            result = simulator.simulate_tampering(field)  # actual controlled attack simulator
        else:
            raise ValueError("unsupported attack")
        evidence_record = self.evidence.record(
            session_id=self.session_id,
            attack_type=result.classification,
            description=f"Controlled UI test rejected {result.attack_type.value}: {result.detail}",
            message_id=result.message_id,
            sequence_number=result.sequence_number,
        )
        checkpoint = self.evidence.checkpoint()
        if result.detected:
            self.recovery.report_violation()
            assert self.alice_sessions and self.bob_sessions
            self.alice_sessions.invalidate()
            self.bob_sessions.invalidate()
            if result.classification is AttackType.KEY_SUBSTITUTION:
                self.recovery.begin_verification()
                self.recovery.verification_failed()
        result_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "attack_type": result.attack_type.value, "classification": result.classification.value,
            "detected": result.detected, "session_id": self.session_id, "simulator_session_id": result.session_id,
            "message_id": result.message_id,
            "sequence_number": result.sequence_number, "evidence_generated": result.evidence_generated,
            "evidence_hash": evidence_record.evidence_hash,
            "simulator_evidence_hash": result.evidence_hash,
            "checkpoint_valid": verify_evidence_chain(self.evidence.records, checkpoint),
            "recovery_state": self.recovery.state.value, "recovery_history": [state.value for state in self.recovery.history],
            "rekeyed": False, "old_session_invalidated": result.detected,
            "simulator_recovery_state": result.recovery_state.value,
            "detail": result.detail,
        }
        self.attacks.append(result_data)
        if self.recovery.state is RecoveryState.QUARANTINED:
            self.pending_attack_index = len(self.attacks) - 1
        self.events.extend([
            _event("ATTACK", "12", "ATTACKER INTERCEPTED", {"attack": result.attack_type.value, "detail": result.detail, "message_id": result.message_id, "sequence_number": result.sequence_number}, "A controlled local attack scenario ran through the existing backend simulator."),
            _event("VALIDATION", "13", "SECURITY VIOLATION DETECTED", {"classification": result.classification.value, "detected": result.detected}, "The displayed classification is produced by the protocol's actual failure path."),
            _event("EVIDENCE", "14", "INCIDENT EVIDENCE GENERATED", {"incident_id": evidence_record.incident_id, "evidence_hash": evidence_record.evidence_hash, "previous_evidence_hash": evidence_record.previous_evidence_hash, "checkpoint_valid": verify_evidence_chain(self.evidence.records, checkpoint), "session_id": result.session_id, "message_id": result.message_id, "sequence_number": result.sequence_number}, "The controller appended a real hash-chained incident record and verified the complete chain against its checkpoint."),
            _event("RECOVERY", "15", "RECOVERY STATE TRANSITIONS", {"history": [state.value for state in self.recovery.history], "current_state": self.recovery.state.value}, "The live chat entered quarantine; a failed key substitution blocks it."),
            _event("SESSION", "16", "CHAT SENDING DISABLED", {"state": self.recovery.state.value, "old_session_invalidated": result.detected}, "Alice and Bob cannot send on the invalidated session."),
        ])
        return {**self.snapshot(), "attack": result_data}

    def recover(self) -> dict[str, object]:
        if self.recovery.state is not RecoveryState.QUARANTINED:
            raise ValueError("only a quarantined chat can be verified and rekeyed")
        assert self.alice and self.bob and self.alice_sessions and self.bob_sessions
        old_session_id = self.session_id
        old_key = self.alice_sessions.sender.key if self.alice_sessions.sender else None
        self.recovery.begin_verification()
        self.recovery.verification_succeeded()
        new_session_id = str(uuid4())
        context = b"cipherchat-ui-rekey:" + new_session_id.encode()
        old_alice_exchange_public_key = self.alice_sessions.info.local_exchange_public_key
        old_bob_exchange_public_key = self.bob_sessions.info.local_exchange_public_key
        rekey_pair(self.alice_sessions, self.bob_sessions, session_id=new_session_id, context=context)
        self.session_id = new_session_id
        self.recovery.rekey_complete()
        assert self.alice_sessions.sender
        rekey_data = {
            "old_session_id": old_session_id, "new_session_id": new_session_id,
            "key_changed": self.alice_sessions.sender.key != old_key,
            "fresh_x25519": (
                self.alice_sessions.info.local_exchange_public_key != old_alice_exchange_public_key
                and self.bob_sessions.info.local_exchange_public_key != old_bob_exchange_public_key
            ),
            "alice_exchange_public_key": self.alice_sessions.info.local_exchange_public_key.hex(),
            "bob_exchange_public_key": self.bob_sessions.info.local_exchange_public_key.hex(),
            "state": self.recovery.state.value,
        }
        if self.pending_attack_index is not None:
            self.attacks[self.pending_attack_index].update({
                "rekeyed": True, "recovery_state": self.recovery.state.value,
                "recovery_history": [state.value for state in self.recovery.history],
                "new_session_id": new_session_id,
            })
            self.pending_attack_index = None
        self.events.append(_event("REKEY", "16", "LIVE CHAT REKEYED", rekey_data,
                                  "Both chat directions now use a new session ID and derived key; sending is enabled."))
        return {**self.snapshot(), "rekey": rekey_data}

    def _simulate_evidence_deletion(self) -> dict[str, object]:
        if not self.evidence.records:
            raise ValueError("Run a message attack first to create an evidence record")
        checkpoint = self.evidence.checkpoint()
        removed = self.evidence.records[-1]
        altered_copy = self.evidence.records[:-1]
        detected = not verify_evidence_chain(altered_copy, checkpoint)
        if detected:
            if self.recovery.state is RecoveryState.SECURE:
                self.recovery.report_violation()
            if self.recovery.state is RecoveryState.QUARANTINED:
                self.recovery.begin_verification()
                self.recovery.verification_failed()
            assert self.alice_sessions and self.bob_sessions
            self.alice_sessions.invalidate()
            self.bob_sessions.invalidate()
            self.pending_attack_index = None
        record = self.evidence.record(
            session_id=self.session_id,
            attack_type=AttackType.TAMPERING,
            description="Controlled deletion of an evidence record from an isolated copy; trusted checkpoint rejected the copy",
            message_id=removed.message_id,
            sequence_number=removed.sequence_number,
        )
        result_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "attack_type": "EVIDENCE_DELETION", "classification": "EVIDENCE_TAMPERING",
            "detected": detected, "session_id": self.session_id,
            "message_id": removed.message_id, "sequence_number": removed.sequence_number,
            "evidence_generated": True, "evidence_hash": record.evidence_hash,
            "checkpoint_valid": verify_evidence_chain(self.evidence.records, self.evidence.checkpoint()),
            "altered_copy_valid": not detected,
            "original_record_count": checkpoint.record_count,
            "altered_copy_count": len(altered_copy),
            "removed_incident_id": removed.incident_id,
            "recovery_state": self.recovery.state.value,
            "recovery_history": [state.value for state in self.recovery.history],
            "rekeyed": False, "old_session_invalidated": detected,
            "detail": "A record was removed from an isolated copy. The checkpoint detected the missing record and blocked the chat; the live evidence remains intact.",
        }
        self.attacks.append(result_data)
        self.events.extend([
            _event("ATTACK", "12", "EVIDENCE DELETION SIMULATED", {
                "removed_incident_id": removed.incident_id,
                "original_record_count": checkpoint.record_count,
                "altered_copy_count": len(altered_copy),
            }, "The attacker removed the latest record from an isolated copy of the evidence chain."),
            _event("VALIDATION", "13", "CHECKPOINT REJECTED DELETION", {
                "detected": detected,
                "trusted_checkpoint": asdict(checkpoint),
                "altered_copy_valid": not detected,
            }, "The copied chain can be internally valid after tail deletion, but its count and tip no longer match the saved checkpoint."),
            _event("EVIDENCE", "14", "DELETION ATTEMPT RECORDED", {
                "incident_id": record.incident_id,
                "evidence_hash": record.evidence_hash,
                "live_chain_valid": result_data["checkpoint_valid"],
            }, "The live evidence chain retained its records and recorded this simulation."),
            _event("RECOVERY", "15", "CHAT BLOCKED AFTER EVIDENCE DELETION", {
                "state": self.recovery.state.value,
                "history": result_data["recovery_history"],
                "old_session_invalidated": detected,
            }, "The chat cannot send or rekey after evidence integrity fails; start a new session."),
        ])
        return {**self.snapshot(), "attack": result_data}


class _Handler(SimpleHTTPRequestHandler):
    controller = DemonstrationController()
    audit_logs: list[dict[str, object]] = []
    live_log_path = LIVE_LOG_PATH
    live_log_lock = Lock()

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _log_request_json(self, method: str, path: str, status_code: int, duration_ms: float, client_ip: str, error: str | None = None) -> None:
        with self.live_log_lock:
            self.audit_logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "method": method,
                "path": path,
                "status_code": int(status_code),
                "duration_ms": round(duration_ms, 3),
                "client_ip": client_ip,
                "error": error,
            })
            _write_live_logs(self.controller, self.audit_logs, self.live_log_path)

    def do_GET(self) -> None:
        start_time = perf_counter_ns()
        parsed = urlparse(self.path)
        client_ip = self.client_address[0] if self.client_address else "unknown"
        if parsed.path == "/api/state":
            self._json(self.controller.snapshot())
            self._log_request_json("GET", parsed.path, HTTPStatus.OK, (perf_counter_ns() - start_time) / 1_000_000, client_ip)
            return
        if parsed.path == "/api/reset":
            self._json(self.controller.establish())
            self._log_request_json("GET", parsed.path, HTTPStatus.OK, (perf_counter_ns() - start_time) / 1_000_000, client_ip)
            return
        if parsed.path == "/api/logs":
            self._json(self.controller.export_logs())
            self._log_request_json("GET", parsed.path, HTTPStatus.OK, (perf_counter_ns() - start_time) / 1_000_000, client_ip)
            return
        if parsed.path == "/api/audit-logs":
            self._json({"audit_logs": self.audit_logs})
            self._log_request_json("GET", parsed.path, HTTPStatus.OK, (perf_counter_ns() - start_time) / 1_000_000, client_ip)
            return
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        start_time = perf_counter_ns()
        parsed = urlparse(self.path)
        client_ip = self.client_address[0] if self.client_address else "unknown"

        content_length_str = self.headers.get("Content-Length")
        if content_length_str is None:
            self._json({"error": "Content-Length header required"}, status=HTTPStatus.LENGTH_REQUIRED)
            self._log_request_json("POST", parsed.path, HTTPStatus.LENGTH_REQUIRED, (perf_counter_ns() - start_time) / 1_000_000, client_ip, "missing Content-Length")
            return

        try:
            length = int(content_length_str)
            if length < 0:
                raise ValueError("Negative Content-Length")
        except ValueError:
            self._json({"error": "invalid Content-Length"}, status=HTTPStatus.BAD_REQUEST)
            self._log_request_json("POST", parsed.path, HTTPStatus.BAD_REQUEST, (perf_counter_ns() - start_time) / 1_000_000, client_ip, "invalid Content-Length")
            return

        if length > MAX_REQUEST_BODY_SIZE:
            self._json(
                {"error": f"request body size ({length} bytes) exceeds maximum limit of {MAX_REQUEST_BODY_SIZE} bytes"},
                status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            self._log_request_json("POST", parsed.path, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, (perf_counter_ns() - start_time) / 1_000_000, client_ip, "request body too large")
            return

        try:
            body_bytes = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body_bytes or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("request payload must be a JSON object")

            if parsed.path == "/api/send":
                response = self.controller.send(payload.get("message", ""), payload.get("sender", "alice"))
            elif parsed.path == "/api/attack":
                response = self.controller.attack(payload.get("attack", ""))
            elif parsed.path == "/api/recover":
                response = self.controller.recover()
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                self._log_request_json("POST", parsed.path, HTTPStatus.NOT_FOUND, (perf_counter_ns() - start_time) / 1_000_000, client_ip, "endpoint not found")
                return

            self._json(response)
            self._log_request_json("POST", parsed.path, HTTPStatus.OK, (perf_counter_ns() - start_time) / 1_000_000, client_ip)
        except (ValueError, json.JSONDecodeError, ProtocolError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            self._log_request_json("POST", parsed.path, HTTPStatus.BAD_REQUEST, (perf_counter_ns() - start_time) / 1_000_000, client_ip, str(error))

    def _json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def translate_path(self, path: str) -> str:
        if path.startswith("/api/"): return str(STATIC_DIR / "index.html")
        return str(STATIC_DIR / path.lstrip("/"))


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8000), _Handler)
    with _Handler.live_log_lock:
        _write_live_logs(_Handler.controller, _Handler.audit_logs, _Handler.live_log_path)
    print("CipherChat local demonstration UI: http://127.0.0.1:8000")
    print(f"Live JSON log: {LIVE_LOG_PATH}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == "__main__": main()
