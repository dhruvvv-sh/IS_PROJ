"""Opt-in live MySQL test; requires an otherwise empty disposable demo database."""
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.realtime.database import AuditFailure, Config, Database, GENESIS
from cipherchat.realtime import server
from tests.test_realtime import envelope_for


@pytest.mark.skipif(os.getenv("CIPHERCHAT_TEST_MYSQL") != "1", reason="set CIPHERCHAT_TEST_MYSQL=1 for live MySQL integration test")
def test_mysql_browser_handoff_keeps_one_session_and_audits_key_rotation():
    db = Database(Config.from_env())
    db.migrate()
    conn = db.connect()
    try:
        cur = conn.cursor()
        for table in ("cc_audit_records", "cc_messages", "cc_message_state", "cc_users", "cc_security_events", "cc_role_sessions"):
            cur.execute("SELECT COUNT(*) FROM " + table)
            assert cur.fetchone()[0] == 0, "live test requires an empty disposable demo database"
    finally:
        conn.close()
    alice, old_bob, new_bob = Identity.create("alice"), Identity.create("bob"), Identity.create("bob")
    try:
        db.register_identity("alice", public_key_bytes(alice.public_key), alice.signing_public_key_bytes)
        db.register_identity("bob", public_key_bytes(old_bob.public_key), old_bob.signing_public_key_bytes)
        assert db.claim_session("bob", "a" * 64)
        assert not db.claim_session("bob", "b" * 64)
        assert db.claim_session("bob", "b" * 64, replace_existing=True)
        assert not db.touch_session("bob", "a" * 64)
        assert db.touch_session("bob", "b" * 64)
        detail = db.rotate_identity("bob", public_key_bytes(new_bob.public_key), new_bob.signing_public_key_bytes)
        assert detail["generation"] == 2
        assert db.chat_state()["session_id"] == "alice-bob:2"
        assert db.identity("bob")["signing_public"] == new_bob.signing_public_key_bytes.hex()
        assert db.verify()["record_count"] == 4
        old_message = envelope_for(alice, old_bob, sender="bob")
        assert db.accept(old_message)[0] is False
        new_message = envelope_for(alice, new_bob, sender="bob", session_id="alice-bob:2")
        assert db.accept(new_message)[0] is True
        assert db.verify()["record_count"] == 5
        db.release_session("bob", "b" * 64)
        assert db.presence()["bob"] is False
    finally:
        conn = db.connect()
        try:
            cur = conn.cursor()
            for table in ("cc_role_sessions", "cc_security_events", "cc_messages", "cc_message_state", "cc_users", "cc_audit_records"):
                cur.execute("DELETE FROM " + table)
            cur.execute("UPDATE cc_audit_head SET record_count=0, record_hash=%s WHERE singleton=1", (GENESIS,))
            conn.commit()
        finally:
            conn.close()


@pytest.mark.skipif(os.getenv("CIPHERCHAT_TEST_MYSQL") != "1", reason="set CIPHERCHAT_TEST_MYSQL=1 for live MySQL integration test")
def test_mysql_replay_survives_restart_concurrent_sequence_and_audit_tamper(tmp_path: Path):
    database = Database(Config.from_env())
    database.migrate()
    conn = database.connect()
    try:
        cur = conn.cursor()
        for table in ("cc_audit_records", "cc_messages", "cc_message_state", "cc_users", "cc_security_events", "cc_role_sessions"):
            cur.execute("SELECT COUNT(*) FROM " + table)
            assert cur.fetchone()[0] == 0, "live test requires an empty disposable demo database"
    finally:
        conn.close()
    alice, bob = Identity.create("alice"), Identity.create("bob")
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(lambda token: database.claim_session("bob", token), ("a" * 64, "b" * 64)))
        assert sum(claims) == 1
        winner = ("a" * 64, "b" * 64)[claims.index(True)]
        loser = ("b" * 64, "a" * 64)[claims.index(True)]
        assert database.presence()["bob"] is True
        assert database.touch_session("bob", winner) is True
        assert database.touch_session("bob", loser) is False
        database.release_session("bob", loser)
        assert database.presence()["bob"] is True
        database.release_session("bob", winner)
        assert database.presence()["bob"] is False
        assert database.claim_session("bob", "c" * 64) is True
        database.release_session("bob", "c" * 64)
        first = envelope_for(alice, bob, sequence=1)
        assert database.accept(first)[0] is True
        checkpoint = tmp_path / "trusted.checkpoint.json"
        database.checkpoint(checkpoint)
        restarted = Database(Config.from_env())
        assert restarted.accept(first)[0] is False
        assert restarted.accept(envelope_for(alice, bob, sequence=1))[0] is False
        assert restarted.accept(envelope_for(alice, bob, sequence=2))[0] is True
        anchored = Database(replace(Config.from_env(), checkpoint=checkpoint))
        assert anchored.verify()["record_count"] == 2
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(restarted.accept, [envelope_for(alice, bob, sequence=3), envelope_for(alice, bob, sequence=3)]))
        assert sum(accepted for accepted, _ in outcomes) == 1
        assert restarted.verify()["record_count"] == 3
        restarted.register_identity("alice", public_key_bytes(alice.public_key), alice.signing_public_key_bytes)
        restarted.register_identity("bob", public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
        restarted.mark_delivered(first["message_id"])
        restarted.event("TEST_REJECTION", "mallory", first["message_id"], {"reason": "test"})
        assert restarted.verify()["record_count"] == 7
        conn = restarted.connect()
        try:
            cur = conn.cursor()
            for statement, params in (
                ("DELETE FROM cc_messages WHERE message_id = %s", (first["message_id"],)),
                ("UPDATE cc_messages SET delivery_status = 'QUEUED' WHERE message_id = %s", (first["message_id"],)),
                ("UPDATE cc_message_state SET highest_sequence = 99 WHERE sender_id = 'alice'", ()),
                ("UPDATE cc_users SET exchange_public = %s WHERE username = 'alice'", (b"x" * 32,)),
                ("UPDATE cc_security_events SET event_type = 'ALTERED' WHERE actor = 'mallory'", ()),
            ):
                cur.execute(statement, params)
                with pytest.raises(AuditFailure):
                    restarted._verify(cur)
                conn.rollback()
            cur.execute("DELETE FROM cc_audit_records WHERE number = %s", (3,))
            with pytest.raises(AuditFailure):
                restarted._verify(cur)
        finally:
            conn.rollback()
            conn.close()
        assert anchored.verify()["record_count"] == 7
    finally:
        conn = database.connect()
        try:
            cur = conn.cursor()
            for table in ("cc_role_sessions", "cc_security_events", "cc_messages", "cc_message_state", "cc_users", "cc_audit_records"):
                cur.execute("DELETE FROM " + table)
            cur.execute("UPDATE cc_audit_head SET record_count=0, record_hash=%s WHERE singleton=1", (GENESIS,))
            conn.commit()
        finally:
            conn.close()


@pytest.mark.skipif(os.getenv("CIPHERCHAT_TEST_MYSQL") != "1", reason="set CIPHERCHAT_TEST_MYSQL=1 for live MySQL integration test")
def test_mysql_http_chat_and_every_mallory_command(monkeypatch):
    """Exercise all attack endpoints against transactional storage in a disposable schema."""
    db = Database(Config.from_env())
    db.migrate()
    conn = db.connect()
    try:
        cur = conn.cursor()
        for table in ("cc_audit_records", "cc_messages", "cc_message_state", "cc_users", "cc_security_events", "cc_role_sessions"):
            cur.execute("SELECT COUNT(*) FROM " + table)
            assert cur.fetchone()[0] == 0, "live test requires an empty disposable demo database"
    finally:
        conn.close()
    monkeypatch.setenv("CIPHERCHAT_SESSION_SECRET", "m" * 40)
    monkeypatch.setenv("CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO", "1")
    for role in ("alice", "bob", "mallory"):
        monkeypatch.setenv(f"CIPHERCHAT_{role.upper()}_PASSWORD", f"{role}-password")
    server._database.cache_clear()
    alice, bob = Identity.create("alice"), Identity.create("bob")
    try:
        with TestClient(server.app) as client:
            cookies = {}
            for role in ("alice", "bob", "mallory"):
                response = client.post("/api/login", json={"username": role, "password": f"{role}-password"})
                assert response.status_code == 200
                cookies[role] = {"cipherchat_session": response.cookies["cipherchat_session"]}
            client.cookies.clear()
            assert client.post("/api/login", json={"username": "bob", "password": "bob-password"}).status_code == 409
            for role, identity in (("alice", alice), ("bob", bob)):
                assert client.post("/api/identity", cookies=cookies[role], json={
                    "exchange_public": identity.public_material()["public_key"],
                    "signing_public": identity.signing_public_key_bytes.hex()}).status_code == 200
            generation = 1
            for sequence, (attack, event_type, quarantines) in enumerate((
                ("eavesdrop", "EAVESDROP", False),
                ("stale", "TIMESTAMP_REJECTED", True),
                ("replay", "REPLAY", True),
                ("tamper", "TAMPERING", True),
                ("impersonate", "IMPERSONATION", True),
                ("key_substitution", "KEY_SUBSTITUTION", True),
            ), start=1):
                envelope = envelope_for(alice, bob, sequence=sequence, session_id=f"alice-bob:{generation}")
                sent = client.post("/api/send", cookies=cookies["alice"], json={"envelope": envelope})
                assert sent.status_code == 200 and sent.json()["accepted"] is True
                assert client.get("/api/history", cookies=cookies["bob"]).json()["messages"][-1]["envelope"] == envelope
                assert client.post("/api/delivered", cookies=cookies["bob"],
                                   json={"message_id": envelope["message_id"]}).status_code == 200
                assert db.message(envelope["message_id"])["delivery_status"] == "DELIVERED"
                result = client.post("/api/mallory/attack", cookies=cookies["mallory"],
                                     json={"attack": attack, "message_id": envelope["message_id"]})
                assert result.status_code == 200
                if attack == "eavesdrop":
                    assert result.json()["plaintext_access"] is False
                elif attack == "key_substitution":
                    assert result.json()["accepted"] is False
                else:
                    assert result.json()["event_type"] == event_type
                    assert result.json()["accepted"] is False
                assert any(event["event_type"] == event_type for event in db.events())
                assert db.chat_state()["state"] == ("QUARANTINED" if quarantines else "SECURE")
                if quarantines:
                    response = client.post("/api/rekey", cookies=cookies["bob"])
                    assert response.status_code == 200
                    if attack == "key_substitution":
                        assert response.json()["chat"]["state"] == "BLOCKED"
                        continue
                    generation += 1
                    assert response.json()["chat"]["generation"] == generation
            assert db.verify()["record_count"] > 0
            conn = db.connect()
            try:
                cur = conn.cursor()
                for table, expected in (("cc_messages", 6), ("cc_role_sessions", 3)):
                    cur.execute("SELECT COUNT(*) FROM " + table)
                    assert cur.fetchone()[0] == expected
                cur.execute("SELECT envelope FROM cc_messages")
                assert all(b"hello" not in (row[0].encode() if isinstance(row[0], str) else row[0])
                           for row in cur.fetchall())
                cur.execute("SELECT detail_json FROM cc_security_events")
                assert all(b"hello" not in (row[0].encode() if isinstance(row[0], str) else row[0])
                           for row in cur.fetchall())
                cur.execute("SELECT COUNT(*) FROM cc_security_events")
                assert cur.fetchone()[0] >= 6
            finally:
                conn.close()
            record_number = db.audit_rows()[-1]["number"]
            deleted = client.post("/api/mallory/attack", cookies=cookies["mallory"],
                                  json={"attack": "delete_record", "record_number": record_number})
            assert deleted.status_code == 200 and deleted.json()["chat_blocked"] is True
            assert client.get("/api/dashboard", cookies=cookies["alice"]).json()["audit_valid"] is False
    finally:
        server._database.cache_clear()
        conn = db.connect()
        try:
            cur = conn.cursor()
            for table in ("cc_role_sessions", "cc_security_events", "cc_messages", "cc_message_state", "cc_users", "cc_audit_records"):
                cur.execute("DELETE FROM " + table)
            cur.execute("UPDATE cc_audit_head SET record_count=0, record_hash=%s WHERE singleton=1", (GENESIS,))
            conn.commit()
        finally:
            conn.close()
