import os
import json
import base64
import pytest
from fastapi.testclient import TestClient

from cipherchat.crypto.encryption import generate_nonce, encrypt, decrypt, Ciphertext
from cipherchat.crypto.identity import Identity
from cipherchat.protocol.messages import ReceiverSession, SenderSession, EncryptedMessage, ReplayError
from cipherchat.realtime import server
from cipherchat.realtime.server import _hash_password, _verify_password
from cipherchat.security.evidence import EvidenceLog, AttackType
from cipherchat.ui.server import DemonstrationController
from tests.test_realtime import MemoryDatabase, envelope_for


def test_password_hashing():
    pw = "super-secret-password-123"
    hashed = _hash_password(pw)
    assert hashed.startswith("pbkdf2_sha256$100000$")

    os.environ["CIPHERCHAT_ALICE_PASSWORD"] = hashed
    assert _verify_password("alice", pw) is True
    assert _verify_password("alice", "wrong-password") is False

    # Plaintext backward compatibility test
    os.environ["CIPHERCHAT_BOB_PASSWORD"] = "plain-bob-password"
    assert _verify_password("bob", "plain-bob-password") is True
    assert _verify_password("bob", "wrong-password") is False


def test_bounded_replay_cache():
    alice = Identity.create("alice")
    sender = SenderSession(b"k" * 32, "test-sess", "alice", alice.signing_private_key)
    # Instantiate with small replay cache limit for testing
    receiver = ReceiverSession(b"k" * 32, "test-sess", "alice", alice.signing_public_key, max_replay_cache=3)

    msg1 = sender.encrypt("msg1")
    msg2 = sender.encrypt("msg2")
    msg3 = sender.encrypt("msg3")

    assert receiver.decrypt(msg1) == "msg1"
    assert receiver.decrypt(msg2) == "msg2"
    assert receiver.decrypt(msg3) == "msg3"
    assert len(receiver._seen_message_ids) == 3

    # Sending a 4th message should evict the oldest message id from the seen cache
    msg4 = sender.encrypt("msg4")
    assert receiver.decrypt(msg4) == "msg4"
    assert len(receiver._seen_message_ids) == 3
    assert msg1.message_id not in receiver._seen_message_ids
    assert msg4.message_id in receiver._seen_message_ids


def test_generate_nonce_and_encryption():
    nonce1 = generate_nonce(counter=1)
    nonce2 = generate_nonce(counter=2)
    assert len(nonce1) == 12 and len(nonce2) == 12
    assert nonce1 != nonce2
    # Verify counter in the first 4 bytes
    assert int.from_bytes(nonce1[:4], byteorder="big") == 1
    assert int.from_bytes(nonce2[:4], byteorder="big") == 2

    # Encrypt with explicit nonce
    key = b"x" * 32
    ct = encrypt(key, b"hello counter", b"aad", nonce=nonce1)
    assert ct.nonce == nonce1
    assert decrypt(key, ct, b"aad") == b"hello counter"


def test_evidence_description_sanitization():
    log = EvidenceLog()
    long_desc = "A" * 1500
    rec = log.record(session_id="sess-1", attack_type=AttackType.TAMPERING, description=long_desc)
    assert len(rec.description) < 1500
    assert "[TRUNCATED]" in rec.description


def test_ui_session_key_redacted():
    controller = DemonstrationController()
    snap = controller.snapshot()
    session_key = snap["session"]["session_key"]
    assert "[REDACTED]" in session_key
    assert "sha256:" in session_key

    exported = controller.export_logs()
    assert "[REDACTED]" in exported["session"]["session_key"]


def test_realtime_health_endpoint(monkeypatch):
    database = MemoryDatabase()
    monkeypatch.setattr(server, "Database", lambda config: database)
    server._database.cache_clear()
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")
    monkeypatch.setenv("CIPHERCHAT_SESSION_SECRET", "s" * 40)

    with TestClient(server.app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert r.json()["database"] == "connected"


def test_realtime_token_refresh_and_history_pagination(monkeypatch):
    database = MemoryDatabase()
    monkeypatch.setattr(server, "Database", lambda config: database)
    server._database.cache_clear()
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")
    monkeypatch.setenv("CIPHERCHAT_SESSION_SECRET", "s" * 40)
    monkeypatch.setenv("CIPHERCHAT_ALICE_PASSWORD", "alice-password")
    monkeypatch.setenv("CIPHERCHAT_BOB_PASSWORD", "bob-password")
    monkeypatch.setenv("CIPHERCHAT_MALLORY_PASSWORD", "mallory-password")

    alice, bob = Identity.create("alice"), Identity.create("bob")
    with TestClient(server.app) as client:
        # Login Alice
        r = client.post("/api/login", json={"username": "alice", "password": "alice-password"})
        assert r.status_code == 200
        alice_cookie = {"cipherchat_session": r.cookies["cipherchat_session"]}

        # Refresh token
        ref = client.post("/api/refresh", cookies=alice_cookie)
        assert ref.status_code == 200
        assert ref.json()["refreshed"] is True
        new_cookie = {"cipherchat_session": ref.cookies["cipherchat_session"]}

        # Me endpoint with refreshed cookie
        me_resp = client.get("/api/me", cookies=new_cookie)
        assert me_resp.status_code == 200
        assert me_resp.json()["username"] == "alice"

        # Register identities
        client.post("/api/identity", cookies=new_cookie, json={
            "exchange_public": alice.public_material()["public_key"],
            "signing_public": alice.signing_public_key_bytes.hex(),
        })

        # Send multiple messages
        for i in range(1, 6):
            env = envelope_for(alice, bob, sequence=i)
            res = client.post("/api/send", cookies=new_cookie, json={"envelope": env})
            assert res.status_code == 200

        # Test pagination on history
        paged = client.get("/api/history?limit=2&offset=1", cookies=new_cookie).json()
        assert len(paged["messages"]) == 2
        assert paged["total"] == 5
        assert paged["limit"] == 2
        assert paged["offset"] == 1


def test_realtime_oversized_request_rejected(monkeypatch):
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")
    monkeypatch.setenv("CIPHERCHAT_SESSION_SECRET", "s" * 40)
    with TestClient(server.app) as client:
        # Giant body exceeding normal bounds
        huge_payload = {"huge": "X" * (1024 * 1024 * 10)}  # 10MB
        r = client.post("/api/login", json=huge_payload)
        # Should be rejected with 400 or 401
        assert r.status_code in (400, 401, 413)
