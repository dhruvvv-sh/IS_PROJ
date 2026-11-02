"""Opt-in live MySQL test; requires an otherwise empty disposable demo database."""
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.realtime.database import AuditFailure, Config, Database, GENESIS
from tests.test_realtime import envelope_for


@pytest.mark.skipif(os.getenv("CIPHERCHAT_TEST_MYSQL") != "1", reason="set CIPHERCHAT_TEST_MYSQL=1 for live MySQL integration test")
def test_mysql_replay_survives_restart_concurrent_sequence_and_audit_tamper(tmp_path: Path):
    database = Database(Config.from_env())
    database.migrate()
    conn = database.connect()
    try:
        cur = conn.cursor()
        for table in ("cc_audit_records", "cc_messages", "cc_message_state", "cc_users", "cc_security_events"):
            cur.execute("SELECT COUNT(*) FROM " + table)
            assert cur.fetchone()[0] == 0, "live test requires an empty disposable demo database"
    finally:
        conn.close()
    alice, bob = Identity.create("alice"), Identity.create("bob")
    try:
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
            for table in ("cc_security_events", "cc_messages", "cc_message_state", "cc_users", "cc_audit_records"):
                cur.execute("DELETE FROM " + table)
            cur.execute("UPDATE cc_audit_head SET record_count=0, record_hash=%s WHERE singleton=1", (GENESIS,))
            conn.commit()
        finally:
            conn.close()
