import base64
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.kdf import derive_session_key
from cipherchat.crypto.key_exchange import derive_shared_secret
from cipherchat.realtime.database import AuditFailure
from cipherchat.realtime.protocol import EnvelopeError, aad, signing_bytes, validate_envelope
from cipherchat.realtime import server


def envelope_for(alice, bob, sequence=1, timestamp=None, plaintext=b"hello", session_id="alice-bob:1"):
    item = {"protocol_version": 3, "session_id": session_id, "conversation_id": "alice-bob",
            "sender_id": "alice", "receiver_id": "bob", "message_id": str(uuid4()),
            "sequence_number": sequence,
            "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(timespec="milliseconds")}
    key = derive_session_key(derive_shared_secret(alice.private_key, bob.public_key),
                             context=f"cipherchat-realtime:{session_id}".encode())
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad(item))
    item["nonce"] = base64.b64encode(nonce).decode()
    item["ciphertext"] = base64.b64encode(ciphertext).decode()
    item["signature"] = base64.b64encode(alice.signing_private_key.sign(signing_bytes(item))).decode()
    return item


def test_v3_envelope_signs_all_routing_replay_and_ciphertext_fields():
    alice, bob = Identity.create("alice"), Identity.create("bob")
    good = envelope_for(alice, bob)
    validate_envelope(good, alice.signing_public_key_bytes)
    for field, value in (("receiver_id", "mallory"), ("sender_id", "mallory"),
                         ("conversation_id", "other"), ("session_id", "other"),
                         ("sequence_number", 2), ("message_id", str(uuid4())),
                         ("timestamp", datetime.now(timezone.utc).isoformat()),
                         ("nonce", base64.b64encode(os.urandom(12)).decode()),
                         ("ciphertext", base64.b64encode(b"changed ciphertext" + b"x" * 16).decode())):
        with pytest.raises(EnvelopeError):
            validate_envelope({**good, field: value}, alice.signing_public_key_bytes)
    with pytest.raises(EnvelopeError, match="timestamp"):
        validate_envelope(envelope_for(alice, bob, timestamp=datetime.now(timezone.utc) - timedelta(hours=1)),
                          alice.signing_public_key_bytes)
    assert b"hello" not in str(good).encode()


class MemoryDatabase:
    def __init__(self):
        self.identities = {}
        self.saved = {}
        self.highest = {}
        self.security_events = []
        self.audit = []
        self.failed = False

    def migrate(self):
        pass

    def verify(self):
        if self.failed:
            raise AuditFailure("deleted audit record")
        return {"record_count": len(self.audit), "record_hash": "0" * 64}

    def identity(self, who):
        return self.identities.get(who)

    def register_identity(self, who, exchange, signing):
        value = {"exchange_public": exchange.hex(), "signing_public": signing.hex()}
        if who in self.identities and self.identities[who] != value:
            raise ValueError("registered public key mismatch")
        self.identities[who] = value
        self.audit.append({"number": len(self.audit) + 1, "kind": "KEY_REGISTERED", "record_hash": "a" * 64})

    def event(self, event_type, actor, message_id, detail):
        self.security_events.append({"timestamp": "now", "event_type": event_type, "actor": actor,
                                     "message_id": message_id, "detail": detail})
        self.audit.append({"number": len(self.audit) + 1, "kind": "SECURITY_EVENT", "record_hash": "b" * 64})

    def chat_state(self):
        generation, blocked = 1, False
        for row in self.security_events:
            if row["event_type"] == "CHAT_BLOCKED":
                blocked = True
            elif row["event_type"] == "CHAT_REKEYED":
                generation, blocked = row["detail"]["generation"], False
        return {"generation": generation, "session_id": f"alice-bob:{generation}", "blocked": blocked}

    def accept(self, item):
        key = (item["sender_id"], item["conversation_id"])
        if item["message_id"] in self.saved or item["sequence_number"] <= self.highest.get(key, 0):
            return False, "duplicate message ID or stale sequence"
        self.highest[key] = item["sequence_number"]
        self.saved[item["message_id"]] = {"envelope": item, "delivery_status": "QUEUED"}
        self.audit.append({"number": len(self.audit) + 1, "kind": "ENCRYPTED_MESSAGE", "record_hash": "c" * 64})
        return True, "accepted"

    def message(self, message_id):
        return self.saved.get(message_id)

    def mark_delivered(self, message_id):
        self.saved[message_id]["delivery_status"] = "DELIVERED"

    def pending(self, username):
        return [row["envelope"] for row in self.saved.values()
                if row["envelope"]["receiver_id"] == username and row["delivery_status"] == "QUEUED"]

    def highest_sequence(self, username):
        return self.highest.get((username, "alice-bob"), 0)

    def messages(self, username):
        return list(self.saved.values())

    def captured(self):
        return list(self.saved.values())

    def events(self):
        return list(reversed(self.security_events))

    def stats(self):
        return {"messages_sent": len(self.saved), "messages_delivered": sum(row["delivery_status"] == "DELIVERED" for row in self.saved.values()),
                "signatures_verified": len(self.saved),
                "signature_failures": sum(row["event_type"] == "TAMPERING" and "signature" in row["detail"].get("reason", "") for row in self.security_events),
                "events": {kind: sum(row["event_type"] == kind for row in self.security_events)
                           for kind in {row["event_type"] for row in self.security_events}}, "audit": self.verify()}

    def audit_rows(self):
        return list(self.audit)

    def delete_audit_row_for_demo(self, number):
        self.audit = [row for row in self.audit if row["number"] != number]
        self.failed = True


def test_authenticated_http_replay_tamper_impersonation_and_rekey(monkeypatch):
    database = MemoryDatabase()
    monkeypatch.setattr(server, "Database", lambda config: database)
    for name in ("ALICE", "BOB", "MALLORY"):
        monkeypatch.setenv(f"CIPHERCHAT_{name}_PASSWORD", name.lower() + "-password")
    monkeypatch.setenv("CIPHERCHAT_SESSION_SECRET", "0" * 40)
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")
    monkeypatch.setenv("CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO", "1")
    alice, bob = Identity.create("alice"), Identity.create("bob")
    with TestClient(server.app) as client:
        cookies = {}
        for name in ("alice", "bob", "mallory"):
            response = client.post("/api/login", json={"username": name, "password": name + "-password"})
            assert response.status_code == 200
            cookies[name] = {"cipherchat_session": response.cookies["cipherchat_session"]}
        client.cookies.clear()
        assert client.post("/api/login", json={"username": "alice", "password": "wrong"}).status_code == 401
        assert client.get("/api/me").status_code == 401
        for name, identity in (("alice", alice), ("bob", bob)):
            response = client.post("/api/identity", cookies=cookies[name], json={
                "exchange_public": identity.public_material()["public_key"],
                "signing_public": identity.signing_public_key_bytes.hex()})
            assert response.status_code == 200
        assert client.post("/api/identity", cookies=cookies["mallory"], json={}).status_code == 403
        item = envelope_for(alice, bob)
        assert client.post("/api/send", cookies=cookies["mallory"], json={"envelope": item}).status_code == 403
        assert client.post("/api/send", cookies=cookies["alice"], json={"envelope": []}).json()["event_type"] == "INVALID_MESSAGE"
        assert client.post("/api/send", cookies=cookies["alice"], json={"envelope": item}).json()["accepted"] is True
        assert client.get("/api/history", cookies=cookies["bob"]).json()["messages"][0]["envelope"] == item
        assert client.get("/api/sequence", cookies=cookies["alice"]).json()["highest_sequence"] == 1
        assert client.post("/api/delivered", cookies=cookies["bob"], json={"message_id": item["message_id"]}).json()["ok"]
        assert database.saved[item["message_id"]]["delivery_status"] == "DELIVERED"
        assert client.post("/api/mallory/attack", cookies=cookies["mallory"], json={"attack": "eavesdrop"}).json()["wrong_key_rejected"]
        assert client.post("/api/mallory/attack", cookies=cookies["mallory"], json={"attack": "key_substitution"}).json()["accepted"] is False
        for attack, expected in (("replay", "REPLAY"), ("tamper", "TAMPERING"), ("impersonate", "IMPERSONATION"), ("stale", "INVALID_MESSAGE")):
            if database.chat_state()["blocked"]:
                assert client.post("/api/rekey", cookies=cookies["alice"]).json()["chat"]["blocked"] is False
            response = client.post("/api/mallory/attack", cookies=cookies["mallory"], json={"attack": attack, "message_id": item["message_id"]})
            assert response.status_code == 200
            assert response.json()["event_type"] == expected
            assert response.json()["accepted"] is False
        assert client.get("/api/dashboard", cookies=cookies["alice"]).json()["chat"]["blocked"] is False
        assert client.post("/api/rekey", cookies=cookies["mallory"]).status_code == 403
        new = envelope_for(alice, bob, sequence=2, session_id=database.chat_state()["session_id"])
        assert client.post("/api/send", cookies=cookies["alice"], json={"envelope": new}).json()["accepted"] is True
        assert client.get("/api/history", cookies=cookies["bob"]).json()["messages"][-1]["envelope"] == new
