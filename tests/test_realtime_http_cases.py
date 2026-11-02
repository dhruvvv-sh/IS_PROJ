"""HTTP chat and attack-console behavior without a live MySQL service."""
import base64
from datetime import datetime, timedelta, timezone

import pytest
import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.kdf import derive_session_key
from cipherchat.crypto.key_exchange import derive_shared_secret
from cipherchat.realtime import server
from cipherchat.realtime.protocol import aad
from tests.test_realtime import MemoryDatabase, envelope_for


@pytest.fixture
def lab(monkeypatch):
    database = MemoryDatabase()
    monkeypatch.setattr(server, "Database", lambda config: database)
    server._database.cache_clear()
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")
    monkeypatch.setenv("CIPHERCHAT_SESSION_SECRET", "t" * 40)
    for role in ("alice", "bob", "mallory"):
        monkeypatch.setenv(f"CIPHERCHAT_{role.upper()}_PASSWORD", f"{role}-password")
    alice, bob = Identity.create("alice"), Identity.create("bob")
    with TestClient(server.app) as client:
        cookies = {}
        for role in ("alice", "bob", "mallory"):
            response = client.post("/api/login", json={"username": role, "password": f"{role}-password"})
            assert response.status_code == 200
            cookies[role] = {"cipherchat_session": response.cookies["cipherchat_session"]}
        client.cookies.clear()
        for role, identity in (("alice", alice), ("bob", bob)):
            response = client.post("/api/identity", cookies=cookies[role], json={
                "exchange_public": identity.public_material()["public_key"],
                "signing_public": identity.signing_public_key_bytes.hex()})
            assert response.status_code == 200
        yield client, cookies, database, alice, bob
    server._database.cache_clear()


def post(client, cookies, role, path, payload):
    return client.post(path, cookies=cookies[role], json=payload)


def test_both_directions_delivery_and_ciphertext_only(lab):
    client, cookies, db, alice, bob = lab
    sent = []
    for role in ("alice", "bob"):
        envelope = envelope_for(alice, bob, sender=role, plaintext=f"secret from {role}".encode())
        sent.append(envelope)
        response = post(client, cookies, role, "/api/send", {"envelope": envelope})
        assert response.json() == {"accepted": True, "reason": "accepted", "delivery_status": "QUEUED"}
        recipient = "bob" if role == "alice" else "alice"
        history = client.get("/api/history", cookies=cookies[recipient]).json()["messages"]
        assert history[-1]["envelope"] == envelope
        assert "secret from" not in str(history)
        assert post(client, cookies, role, "/api/delivered", {"message_id": envelope["message_id"]}).status_code == 403
        assert post(client, cookies, recipient, "/api/delivered", {"message_id": envelope["message_id"]}).json() == {"ok": True}
        assert db.message(envelope["message_id"])["delivery_status"] == "DELIVERED"
        key = derive_session_key(derive_shared_secret(alice.private_key, bob.public_key),
                                 context=b"cipherchat-realtime:alice-bob:1")
        assert AESGCM(key).decrypt(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ciphertext"]),
                                   aad(envelope)) == f"secret from {role}".encode()
    assert client.get("/api/sequence", cookies=cookies["alice"]).json()["highest_sequence"] == 1
    assert client.get("/api/sequence", cookies=cookies["bob"]).json()["highest_sequence"] == 1
    assert len(client.get("/api/history", cookies=cookies["mallory"]).json()["messages"]) == 2
    assert client.get("/api/dashboard", cookies=cookies["alice"]).json()["stats"]["messages_delivered"] == 2


@pytest.mark.parametrize("attack,event_type,quarantines", [
    ("replay", "REPLAY", True),
    ("tamper", "TAMPERING", True),
    ("impersonate", "IMPERSONATION", True),
    ("stale", "TIMESTAMP_REJECTED", True),
    ("eavesdrop", "EAVESDROP", False),
    ("key_substitution", "KEY_SUBSTITUTION", True),
])
def test_every_attack_command(lab, attack, event_type, quarantines):
    client, cookies, db, alice, bob = lab
    envelope = envelope_for(alice, bob)
    assert post(client, cookies, "alice", "/api/send", {"envelope": envelope}).json()["accepted"]
    result = post(client, cookies, "mallory", "/api/mallory/attack",
                  {"attack": attack, "message_id": envelope["message_id"]})
    assert result.status_code == 200
    payload = result.json()
    if attack == "eavesdrop":
        assert payload["wrong_key_rejected"] is True
        assert payload["plaintext_access"] is False
        assert payload["original"]["message_id"] == envelope["message_id"]
    else:
        assert payload["accepted"] is False
        if attack != "key_substitution":
            assert payload["event_type"] == event_type
    assert any(row["event_type"] == event_type for row in db.events())
    assert db.chat_state()["state"] == ("QUARANTINED" if quarantines else "SECURE")
    assert len(db.saved) == 1
    if quarantines:
        assert post(client, cookies, "bob", "/api/send", {"envelope": envelope_for(alice, bob, sequence=2)}).json()["accepted"] is False
        recovery = post(client, cookies, "bob", "/api/rekey", {}).json()
        if attack == "key_substitution":
            assert recovery["chat"]["state"] == "BLOCKED"
            assert recovery["verified"] is False
            return
        assert recovery["chat"]["state"] == "SECURE"
        assert recovery["chat"]["session_id"] == "alice-bob:2"
        assert [e["detail"]["state"] for e in reversed(db.events()) if e["event_type"] == "RECOVERY_STATE"] == [
            "SUSPECTED_ATTACK", "QUARANTINED", "VERIFYING", "REKEYING", "SECURE"]
        next_message = envelope_for(alice, bob, sequence=2, session_id="alice-bob:2")
        assert post(client, cookies, "alice", "/api/send", {"envelope": next_message}).json()["accepted"]


def test_eavesdrop_uses_selected_capture(lab):
    client, cookies, _, alice, bob = lab
    first = envelope_for(alice, bob, sequence=1)
    second = envelope_for(alice, bob, sequence=2)
    for envelope in (first, second):
        assert post(client, cookies, "alice", "/api/send", {"envelope": envelope}).json()["accepted"]
    result = post(client, cookies, "mallory", "/api/mallory/attack",
                  {"attack": "eavesdrop", "message_id": first["message_id"]}).json()
    assert result["original"]["message_id"] == first["message_id"]
    assert post(client, cookies, "mallory", "/api/mallory/attack",
                {"attack": "eavesdrop", "message_id": "missing"}).status_code == 404


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "sender_id", "receiver_id",
                                    "sequence_number", "timestamp", "message_id"])
def test_each_tamper_field_rejected(lab, field):
    client, cookies, db, alice, bob = lab
    envelope = envelope_for(alice, bob)
    assert post(client, cookies, "alice", "/api/send", {"envelope": envelope}).json()["accepted"]
    result = post(client, cookies, "mallory", "/api/mallory/attack",
                  {"attack": "tamper", "field": field, "message_id": envelope["message_id"]})
    assert result.status_code == 200
    assert result.json()["accepted"] is False
    assert result.json()["event_type"] in {"TAMPERING", "INVALID_MESSAGE", "TIMESTAMP_REJECTED", "AUTHENTICATION_FAILURE"}
    assert len(db.saved) == 1
    assert db.chat_state()["state"] == "QUARANTINED"


def test_valid_signature_for_wrong_session_is_rejected(lab):
    client, cookies, db, alice, bob = lab
    envelope = envelope_for(alice, bob, session_id="alice-bob:999")
    result = post(client, cookies, "alice", "/api/send", {"envelope": envelope}).json()
    assert result["accepted"] is False
    assert result["reason"] == "session changed; refresh chat"
    assert db.saved == {}


def test_preexisting_blocked_chat_can_migrate_to_new_recovery_flow(lab):
    client, cookies, db, alice, bob = lab
    db.event("CHAT_BLOCKED", "mallory", None, {"reason": "older deployment"})
    assert db.chat_state()["incident_type"] == "LEGACY_BLOCK"
    result = post(client, cookies, "alice", "/api/rekey", {}).json()
    assert result["verified"] is True
    assert result["chat"]["state"] == "SECURE"
    assert post(client, cookies, "alice", "/api/send", {
        "envelope": envelope_for(alice, bob, session_id="alice-bob:2")}).json()["accepted"]


@pytest.mark.parametrize("mutation,expected", [
    ({"ciphertext": "bad-base64"}, "TAMPERING"),
    ({"nonce": "AA=="}, "INVALID_MESSAGE"),
    ({"signature": "AA=="}, "INVALID_MESSAGE"),
    ({"session_id": "alice-bob:999"}, "TAMPERING"),
    ({"receiver_id": "alice"}, "INVALID_MESSAGE"),
    ({"sequence_number": 0}, "INVALID_MESSAGE"),
])
def test_malformed_envelopes_are_rejected_without_storage(lab, mutation, expected):
    client, cookies, db, alice, bob = lab
    envelope = {**envelope_for(alice, bob), **mutation}
    result = post(client, cookies, "alice", "/api/send", {"envelope": envelope}).json()
    assert result["accepted"] is False
    assert result["event_type"] == expected
    assert db.saved == {}


def test_expired_timestamp_duplicate_sequence_and_role_permissions(lab):
    client, cookies, db, alice, bob = lab
    old = envelope_for(alice, bob, timestamp=datetime.now(timezone.utc) - timedelta(minutes=10))
    assert post(client, cookies, "alice", "/api/send", {"envelope": old}).json()["event_type"] == "TIMESTAMP_REJECTED"
    assert db.chat_state()["state"] == "QUARANTINED"
    assert post(client, cookies, "alice", "/api/rekey", {}).json()["chat"]["state"] == "SECURE"
    first = envelope_for(alice, bob, session_id="alice-bob:2")
    assert post(client, cookies, "alice", "/api/send", {"envelope": first}).json()["accepted"]
    assert post(client, cookies, "alice", "/api/send", {"envelope": envelope_for(alice, bob, sequence=1, session_id="alice-bob:2")}).json()["event_type"] == "REPLAY"
    assert db.chat_state()["state"] == "QUARANTINED"
    assert post(client, cookies, "mallory", "/api/send", {"envelope": first}).status_code == 403
    assert post(client, cookies, "mallory", "/api/rekey", {}).status_code == 403
    assert post(client, cookies, "alice", "/api/mallory/attack", {"attack": "replay", "message_id": first["message_id"]}).status_code == 403
    assert client.get("/api/history").status_code == 401


def test_explicit_role_takeover_replaces_only_the_previous_session(lab):
    client, cookies, db, _, _ = lab
    assert client.post("/api/login", json={"username": "bob", "password": "wrong",
                                            "replace_existing": True}).status_code == 401
    assert client.get("/api/me", cookies=cookies["bob"]).status_code == 200
    assert client.post("/api/login", json={"username": "bob", "password": "bob-password"}).status_code == 409
    replacement = client.post("/api/login", json={"username": "bob", "password": "bob-password",
                                                     "replace_existing": True})
    assert replacement.status_code == 200
    new_cookie = {"cipherchat_session": replacement.cookies["cipherchat_session"]}
    assert client.get("/api/me", cookies=cookies["bob"]).status_code == 401
    assert client.get("/api/me", cookies=new_cookie).json()["username"] == "bob"
    assert db.presence()["bob"] is True
    assert client.post("/api/logout", cookies=new_cookie).status_code == 200
    assert db.presence()["bob"] is False
    assert client.post("/api/login", json={"username": "bob", "password": "bob-password"}).status_code == 200


def test_new_browser_rotation_starts_new_session_and_preserves_key_audit(lab):
    client, cookies, db, alice, bob = lab
    old = envelope_for(alice, bob, sender="bob")
    assert post(client, cookies, "bob", "/api/send", {"envelope": old}).json()["accepted"]
    assert post(client, cookies, "mallory", "/api/identity/rotate", {}).status_code == 403
    next_bob = Identity.create("bob")
    request = {"exchange_public": next_bob.public_material()["public_key"],
               "signing_public": next_bob.signing_public_key_bytes.hex()}
    assert post(client, cookies, "bob", "/api/identity/rotate", request).status_code == 400
    result = post(client, cookies, "bob", "/api/identity/rotate", {**request, "confirm_new_browser": True})
    assert result.status_code == 200
    assert result.json()["chat"]["session_id"] == "alice-bob:2"
    assert result.json()["new_fingerprint"] != result.json()["old_fingerprint"]
    assert db.identity("bob")["signing_public"] == next_bob.signing_public_key_bytes.hex()
    assert any(row["kind"] == "KEY_ROTATED" for row in db.audit)
    assert db.message(old["message_id"])["envelope"] == old
    from cipherchat.realtime.protocol import validate_envelope
    from cipherchat.realtime.protocol import EnvelopeError
    with pytest.raises(EnvelopeError):
        validate_envelope(old, next_bob.signing_public_key_bytes)
    new = envelope_for(alice, next_bob, sender="bob", sequence=2, session_id="alice-bob:2")
    assert post(client, cookies, "bob", "/api/send", {"envelope": new}).json()["accepted"] is True


@pytest.mark.parametrize("path,payload,expected_status", [
    ("/api/login", [], 400),
    ("/api/login", {"username": [], "password": "x"}, 401),
    ("/api/send", [], 400),
    ("/api/delivered", [], 400),
    ("/api/delivered", {"message_id": []}, 400),
    ("/api/mallory/attack", [], 400),
])
def test_malformed_requests_return_json_errors(lab, path, payload, expected_status):
    client, cookies, _, _, _ = lab
    role = "mallory" if path == "/api/mallory/attack" else "alice"
    response = post(client, cookies, role, path, payload)
    assert response.status_code == expected_status
    assert response.headers["content-type"].startswith("application/json")


def test_destructive_demo_is_gated_and_audit_failure_blocks_chat(lab, monkeypatch):
    client, cookies, db, alice, bob = lab
    first = envelope_for(alice, bob)
    assert post(client, cookies, "alice", "/api/send", {"envelope": first}).json()["accepted"]
    target = db.audit_rows()[0]["number"]
    request = {"attack": "delete_record", "record_number": target}
    assert post(client, cookies, "mallory", "/api/mallory/attack", request).status_code == 403
    monkeypatch.setenv("CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO", "1")
    response = post(client, cookies, "mallory", "/api/mallory/attack", request)
    assert response.status_code == 200
    assert response.json()["chat_blocked"] is True
    assert client.get("/api/dashboard", cookies=cookies["alice"]).json()["audit_valid"] is False
    next_message = envelope_for(alice, bob, sequence=2)
    assert post(client, cookies, "alice", "/api/send", {"envelope": next_message}).json()["event_type"] == "AUDIT_FAILURE"
    assert post(client, cookies, "alice", "/api/rekey", {}).status_code == 409


def test_central_backend_rejects_direct_browsers(lab, monkeypatch):
    client, cookies, _, _, _ = lab
    monkeypatch.setenv("CIPHERCHAT_CENTRAL_ONLY", "1")
    monkeypatch.setenv("CIPHERCHAT_PROXY_SECRET", "s" * 40)
    assert client.get("/").status_code == 404
    assert client.get("/static/app.js").status_code == 404
    assert client.get("/api/me", cookies=cookies["alice"]).status_code == 403
    response = client.get("/api/me", cookies=cookies["alice"],
                          headers={"x-cipherchat-proxy-secret": "s" * 40})
    assert response.status_code == 200
    assert response.json()["username"] == "alice"


def test_vercel_proxy_forwards_api_cookie_and_hides_proxy_secret(monkeypatch):
    seen = {}

    def responder(request: httpx.Request):
        seen["url"] = str(request.url)
        seen["headers"] = dict(request.headers)
        seen["body"] = request.content
        return httpx.Response(200, json={"username": "alice"},
                              headers={"set-cookie": "cipherchat_session=test; HttpOnly; Secure; SameSite=Strict"})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(server.httpx, "AsyncClient",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(responder), **kwargs))
    monkeypatch.setenv("CIPHERCHAT_API_UPSTREAM_URL", "https://alice-api.example.com")
    monkeypatch.setenv("CIPHERCHAT_PROXY_SECRET", "s" * 40)
    with TestClient(server.app) as client:
        response = client.post("/api/login", json={"username": "alice", "password": "not-used-by-proxy"},
                               headers={"origin": "https://cipherchat-delta.vercel.app",
                                        "host": "cipherchat-delta.vercel.app"})
        assert response.status_code == 200
        assert response.json() == {"username": "alice"}
        assert response.cookies.get("cipherchat_session") == "test"
        assert client.post("/api/login", json={}, headers={"origin": "https://evil.example"}).status_code == 403
        assert client.get("/").status_code == 200
    assert seen["url"] == "https://alice-api.example.com/api/login"
    assert seen["headers"]["x-cipherchat-proxy-secret"] == "s" * 40
    assert "origin" not in seen["headers"]
    assert b'"username":"alice"' in seen["body"]
