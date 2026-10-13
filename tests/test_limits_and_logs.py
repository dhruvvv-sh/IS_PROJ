import json
from dataclasses import replace
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from uuid import uuid4
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.kdf import derive_session_key
from cipherchat.crypto.key_exchange import generate_private_key, public_key_bytes
from cipherchat.protocol.limits import (
    MAX_CONTEXT_LENGTH,
    MAX_CIPHERTEXT_SIZE,
    MAX_ID_LENGTH,
    MAX_JSON_MESSAGE_SIZE,
    MAX_REQUEST_BODY_SIZE,
    MAX_PLAINTEXT_SIZE,
)
from cipherchat.protocol.messages import (
    EncryptedMessage,
    PROTOCOL_VERSION,
    ReceiverSession,
    SenderSession,
    ValidationError,
)
from cipherchat.protocol.session import SessionManager
from cipherchat.security.attacks import AttackType
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.simulator import AttackSimulator
from cipherchat.ui.server import DemonstrationController, _Handler


def make_sessions(key: bytes = b"k" * 32, session_id: str = "sess-1", sender_id: str = "alice"):
    signing_key = Ed25519PrivateKey.generate()
    sender = SenderSession(key, session_id, sender_id, signing_key)
    receiver = ReceiverSession(key, session_id, sender_id, signing_key.public_key())
    return sender, receiver


# --- Tests for Plaintext Size Limits ---

def test_plaintext_within_limit_succeeds():
    sender, receiver = make_sessions()
    msg = sender.encrypt("A" * 1000)
    assert receiver.decrypt(msg) == "A" * 1000


def test_plaintext_exceeding_limit_is_rejected():
    sender, _ = make_sessions()
    oversized = "X" * (MAX_PLAINTEXT_SIZE + 1)
    with pytest.raises(ValidationError, match="plaintext size"):
        sender.encrypt(oversized)


def test_custom_plaintext_limit():
    signing_key = Ed25519PrivateKey.generate()
    sender = SenderSession(b"k" * 32, "sess", "alice", signing_key, max_plaintext_size=10)
    sender.encrypt("1234567890")  # exactly 10 bytes: ok
    with pytest.raises(ValidationError):
        sender.encrypt("12345678901")  # 11 bytes: fails


# --- Tests for Ciphertext Size Limits ---

def test_ciphertext_exceeding_limit_is_rejected():
    sender, receiver = make_sessions()
    valid_msg = sender.encrypt("test")
    # Forge a message with oversized ciphertext
    oversized_ciphertext = b"C" * (MAX_CIPHERTEXT_SIZE + 1)
    tampered = replace(valid_msg, ciphertext=oversized_ciphertext)
    with pytest.raises(ValidationError, match="ciphertext size"):
        tampered.validate()
    with pytest.raises(ValidationError):
        receiver.decrypt(tampered)


def test_ciphertext_too_short_is_rejected():
    sender, _ = make_sessions()
    valid_msg = sender.encrypt("test")
    short = replace(valid_msg, ciphertext=b"too_short")
    with pytest.raises(ValidationError, match="invalid encrypted payload"):
        short.validate()


# --- Tests for JSON Request & Message Size Limits ---

def test_encrypted_message_from_json_oversized_is_rejected():
    huge_json = '{"a": "' + ("A" * (MAX_JSON_MESSAGE_SIZE + 10)) + '"}'
    with pytest.raises(ValidationError, match="JSON size"):
        EncryptedMessage.from_json(huge_json)


def test_http_request_body_size_limit():
    controller = DemonstrationController()
    # Mock HTTP request exceeding MAX_REQUEST_BODY_SIZE
    class FakeSocket:
        def makefile(self, *args, **kwargs):
            return BytesIO()

    handler = _Handler.__new__(_Handler)
    handler.controller = controller
    handler.client_address = ("127.0.0.1", 12345)
    handler.headers = {"Content-Length": str(MAX_REQUEST_BODY_SIZE + 500)}
    handler.path = "/api/send"
    handler.rfile = BytesIO(b"X" * (MAX_REQUEST_BODY_SIZE + 500))

    sent_responses = []
    def fake_json(payload, status=HTTPStatus.OK):
        sent_responses.append((payload, status))

    handler._json = fake_json
    handler.do_POST()

    assert len(sent_responses) == 1
    payload, status = sent_responses[0]
    assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert "exceeds maximum limit" in payload["error"]


def test_http_missing_content_length_rejected():
    handler = _Handler.__new__(_Handler)
    handler.controller = DemonstrationController()
    handler.client_address = ("127.0.0.1", 12345)
    handler.headers = {}
    handler.path = "/api/send"
    sent_responses = []
    handler._json = lambda p, status=HTTPStatus.OK: sent_responses.append((p, status))
    handler.do_POST()
    assert sent_responses[0][1] == HTTPStatus.LENGTH_REQUIRED


# --- Tests for ID and Session Context Length Limits ---

def test_oversized_identity_id_rejected():
    with pytest.raises(ValueError, match="identity_id"):
        Identity.create("I" * (MAX_ID_LENGTH + 1))


def test_oversized_peer_id_in_session_manager_rejected():
    alice = Identity.create("alice")
    bob = Identity.create("bob")
    with pytest.raises(ValueError, match="peer_id"):
        SessionManager(alice, "P" * (MAX_ID_LENGTH + 1), public_key_bytes(bob.public_key), bob.signing_public_key_bytes)


def test_oversized_session_id_rejected():
    alice = Identity.create("alice")
    bob = Identity.create("bob")
    manager = SessionManager(alice, "bob", public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
    with pytest.raises(ValueError, match="session_id"):
        manager.establish(
            public_key_bytes(bob.public_key), bob.signing_public_key_bytes,
            session_id="S" * (MAX_ID_LENGTH + 1), context=b"ctx",
        )


def test_oversized_context_rejected_in_session_and_kdf():
    alice = Identity.create("alice")
    bob = Identity.create("bob")
    manager = SessionManager(alice, "bob", public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
    oversized_context = b"C" * (MAX_CONTEXT_LENGTH + 1)
    with pytest.raises(ValueError, match="context"):
        manager.establish(
            public_key_bytes(bob.public_key), bob.signing_public_key_bytes,
            session_id="valid-session", context=oversized_context,
        )
    with pytest.raises(ValueError, match="context"):
        derive_session_key(b"x" * 32, context=oversized_context)


def test_oversized_ids_rejected_in_sender_and_receiver():
    signing_key = Ed25519PrivateKey.generate()
    oversized_id = "A" * (MAX_ID_LENGTH + 1)
    with pytest.raises(ValidationError):
        SenderSession(b"k" * 32, oversized_id, "alice", signing_key)
    with pytest.raises(ValidationError):
        SenderSession(b"k" * 32, "sess", oversized_id, signing_key)
    with pytest.raises(ValidationError):
        ReceiverSession(b"k" * 32, oversized_id, "alice", signing_key.public_key())
    with pytest.raises(ValidationError):
        ReceiverSession(b"k" * 32, "sess", oversized_id, signing_key.public_key())


def test_oversized_ids_rejected_in_evidence_log():
    log = EvidenceLog()
    oversized_id = "A" * (MAX_ID_LENGTH + 1)
    with pytest.raises(ValueError, match="session_id"):
        log.record(session_id=oversized_id, attack_type=AttackType.REPLAY, description="test")
    with pytest.raises(ValueError, match="message_id"):
        log.record(session_id="s", attack_type=AttackType.REPLAY, description="test", message_id=oversized_id)


# --- Tests for JSON Log Storage and Integrity ---

def test_evidence_log_json_serialization_and_export(tmp_path: Path):
    log = EvidenceLog()
    log.record(session_id="s1", attack_type=AttackType.REPLAY, description="replay test", message_id="m1", sequence_number=1)
    log.record(session_id="s1", attack_type=AttackType.TAMPERING, description="tamper test", message_id="m2", sequence_number=2)

    data = log.to_dict()
    assert data["format"] == "cipherchat-evidence-log-v1"
    assert data["record_count"] == 2
    assert data["chain_valid"] is True
    assert len(data["records"]) == 2
    assert "tip_evidence_hash" in data
    assert "checkpoint" in data

    json_str = log.to_json()
    parsed = json.loads(json_str)
    assert parsed["record_count"] == 2

    # Test file export
    json_file = tmp_path / "evidence_audit.json"
    exported_path = log.export_json(json_file)
    assert exported_path.exists()
    file_data = json.loads(exported_path.read_text(encoding="utf-8"))
    assert file_data["record_count"] == 2
    assert file_data["chain_valid"] is True

    # Test round trip from JSON
    restored = EvidenceLog.from_json(json_str)
    assert len(restored.records) == 2
    assert verify_evidence_chain(restored.records, restored.checkpoint()) is True


def test_attack_simulator_json_export(tmp_path: Path):
    sim = AttackSimulator()
    report = sim.run_all()
    report_dict = report.to_dict()
    assert report_dict["format"] == "cipherchat-simulation-report-v1"
    assert "metrics" in report_dict
    assert report_dict["metrics"]["total_attacks"] == 8
    assert len(report_dict["results"]) == 8

    # Test file export
    out_file = tmp_path / "simulation.json"
    exported = report.export_json(out_file)
    assert exported.exists()
    loaded = json.loads(exported.read_text(encoding="utf-8"))
    assert loaded["metrics"]["detection_rate"] == 1.0


def test_ui_controller_export_logs_contains_all_relevant_info():
    controller = DemonstrationController()
    controller.send("Hello Alice and Bob")
    controller.attack("replay")

    logs = controller.export_logs()
    assert logs["format"] == "cipherchat-demonstration-logs-v1"
    assert "exported_at" in logs
    assert "session_id" in logs
    assert "system_limits" in logs
    assert logs["system_limits"]["max_plaintext_size"] == MAX_PLAINTEXT_SIZE
    assert logs["system_limits"]["max_ciphertext_size"] == MAX_CIPHERTEXT_SIZE
    assert logs["system_limits"]["max_request_body_size"] == MAX_REQUEST_BODY_SIZE
    assert logs["system_limits"]["max_id_length"] == MAX_ID_LENGTH
    assert logs["system_limits"]["max_context_length"] == MAX_CONTEXT_LENGTH

    assert len(logs["deliveries"]) >= 1
    assert len(logs["evidence"]["records"]) >= 1
    assert logs["evidence"]["chain_valid"] is True
    assert len(logs["events"]) > 0


def test_ui_server_audit_logging():
    handler = _Handler.__new__(_Handler)
    handler.controller = DemonstrationController()
    handler.audit_logs = []
    handler.client_address = ("127.0.0.1", 54321)
    sent = []
    handler._json = lambda p, status=HTTPStatus.OK: sent.append((p, status))

    handler.path = "/api/state"
    handler.do_GET()
    assert len(handler.audit_logs) == 1
    assert handler.audit_logs[0]["method"] == "GET"
    assert handler.audit_logs[0]["path"] == "/api/state"
    assert handler.audit_logs[0]["status_code"] == 200
    assert "duration_ms" in handler.audit_logs[0]
    assert handler.audit_logs[0]["client_ip"] == "127.0.0.1"

    handler.path = "/api/audit-logs"
    handler.do_GET()
    assert sent[-1][0]["audit_logs"] == handler.audit_logs
