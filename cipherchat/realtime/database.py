"""Transactional MySQL persistence and a checkpointable SHA-256 audit chain."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import mysql.connector

from .protocol import canonical
from cipherchat.security.recovery import RecoveryMachine, RecoveryState

GENESIS = "0" * 64


class AuditFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    database: str
    user: str
    password: str
    checkpoint: Path | None = None

    @classmethod
    def from_env(cls):
        return cls(os.getenv("CIPHERCHAT_MYSQL_HOST", "localhost"), int(os.getenv("CIPHERCHAT_MYSQL_PORT", "3306")),
                   os.getenv("CIPHERCHAT_MYSQL_DATABASE", "cipherchat"), os.getenv("CIPHERCHAT_MYSQL_USER", "cipheruser"),
                   os.environ["CIPHERCHAT_MYSQL_PASSWORD"],
                   Path(os.environ["CIPHERCHAT_AUDIT_CHECKPOINT"]) if os.getenv("CIPHERCHAT_AUDIT_CHECKPOINT") else None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _digest(number: int, timestamp: str, kind: str, payload: dict, previous: str) -> str:
    return hashlib.sha256(canonical({"number": number, "timestamp": timestamp, "kind": kind,
                                     "payload": payload, "previous_hash": previous})).hexdigest()


def _payload(value):
    return json.loads(value) if isinstance(value, (str, bytes)) else value


class Database:
    def __init__(self, config: Config):
        self.config = config
        self._pool = None

    def _get_pool(self):
        if self._pool is None:
            try:
                import mysql.connector.pooling
                self._pool = mysql.connector.pooling.MySQLConnectionPool(
                    pool_name="cipherchat_pool",
                    pool_size=5,
                    host=self.config.host,
                    port=self.config.port,
                    database=self.config.database,
                    user=self.config.user,
                    password=self.config.password,
                    autocommit=False,
                    connection_timeout=5,
                )
            except Exception:
                self._pool = False
        return self._pool if self._pool is not False else None

    def connect(self):
        pool = self._get_pool()
        if pool is not None:
            try:
                conn = pool.get_connection()
            except Exception:
                conn = mysql.connector.connect(host=self.config.host, port=self.config.port, database=self.config.database,
                                               user=self.config.user, password=self.config.password, autocommit=False,
                                               connection_timeout=5)
        else:
            conn = mysql.connector.connect(host=self.config.host, port=self.config.port, database=self.config.database,
                                           user=self.config.user, password=self.config.password, autocommit=False,
                                           connection_timeout=5)
        cur = conn.cursor()
        cur.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
        cur.close()
        return conn

    def migrate(self):
        conn = self.connect()
        try:
            cur = conn.cursor()
            for statement in (
                """CREATE TABLE IF NOT EXISTS cc_audit_records (
                    number BIGINT UNSIGNED PRIMARY KEY, timestamp VARCHAR(40) NOT NULL, kind VARCHAR(24) NOT NULL,
                    payload_json JSON NOT NULL, previous_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                    record_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL) ENGINE=InnoDB""",
                """CREATE TABLE IF NOT EXISTS cc_audit_head (
                    singleton TINYINT PRIMARY KEY, record_count BIGINT UNSIGNED NOT NULL,
                    record_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL) ENGINE=InnoDB""",
                """CREATE TABLE IF NOT EXISTS cc_users (
                    username VARCHAR(32) PRIMARY KEY, exchange_public BINARY(32) NOT NULL,
                    signing_public BINARY(32) NOT NULL, registered_at VARCHAR(40) NOT NULL) ENGINE=InnoDB""",
                """CREATE TABLE IF NOT EXISTS cc_messages (
                    message_id CHAR(36) PRIMARY KEY, conversation_id VARCHAR(64) NOT NULL,
                    sender_id VARCHAR(32) NOT NULL, receiver_id VARCHAR(32) NOT NULL,
                    sequence_number BIGINT UNSIGNED NOT NULL, signed_timestamp VARCHAR(40) NOT NULL,
                    received_at VARCHAR(40) NOT NULL, envelope JSON NOT NULL,
                    delivery_status VARCHAR(16) NOT NULL,
                    UNIQUE KEY uq_sender_conversation_sequence (sender_id, conversation_id, sequence_number),
                    KEY ix_receiver_status (receiver_id, delivery_status)) ENGINE=InnoDB""",
                """CREATE TABLE IF NOT EXISTS cc_message_state (
                    sender_id VARCHAR(32) NOT NULL, conversation_id VARCHAR(64) NOT NULL,
                    highest_sequence BIGINT UNSIGNED NOT NULL,
                    PRIMARY KEY (sender_id, conversation_id)) ENGINE=InnoDB""",
                """CREATE TABLE IF NOT EXISTS cc_security_events (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, timestamp VARCHAR(40) NOT NULL,
                    event_type VARCHAR(40) NOT NULL, actor VARCHAR(32) NOT NULL,
                    message_id VARCHAR(64) NULL, detail_json JSON NOT NULL,
                    KEY ix_events_time (id)) ENGINE=InnoDB""",
                """CREATE TABLE IF NOT EXISTS cc_role_sessions (
                    username VARCHAR(32) PRIMARY KEY,
                    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                    last_seen DOUBLE NOT NULL) ENGINE=InnoDB""",
            ):
                cur.execute(statement)
            cur.execute("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'cc_messages' AND COLUMN_NAME = 'audit_number'", (self.config.database,))
            if not cur.fetchone()[0]:
                # Audit order is immutable, unlike timestamps that may tie or move backwards.
                cur.execute("ALTER TABLE cc_messages ADD COLUMN audit_number BIGINT UNSIGNED NULL")
            cur.execute("SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'cc_messages' AND COLUMN_NAME = 'audit_number'", (self.config.database,))
            if cur.fetchone()[0] == "YES":
                cur.execute("""UPDATE cc_messages m JOIN cc_audit_records a
                    ON a.kind = 'ENCRYPTED_MESSAGE' AND JSON_UNQUOTE(JSON_EXTRACT(a.payload_json, '$.message_id')) = m.message_id
                    SET m.audit_number = a.number""")
                cur.execute("ALTER TABLE cc_messages MODIFY audit_number BIGINT UNSIGNED NOT NULL, ADD UNIQUE KEY ix_message_audit (audit_number)")
            cur.execute("INSERT IGNORE INTO cc_audit_head VALUES (1, 0, %s)", (GENESIS,))
            conn.commit()
        finally:
            conn.close()

    def _anchor(self):
        if self.config.checkpoint is None:
            return None
        return json.loads(self.config.checkpoint.read_text(encoding="utf-8"))

    def _verify(self, cur):
        cur.execute("SELECT record_count, record_hash FROM cc_audit_head WHERE singleton = 1 FOR UPDATE")
        head = cur.fetchone()
        if head is None:
            raise AuditFailure("audit head missing")
        cur.execute("SELECT number, timestamp, kind, payload_json, previous_hash, record_hash FROM cc_audit_records ORDER BY number")
        previous = GENESIS
        count = 0
        anchor = self._anchor()
        anchor_tip = GENESIS if anchor and anchor["record_count"] == 0 else None
        expected_messages = {}
        expected_order = {}
        expected_users = {}
        expected_events = []
        for number, timestamp, kind, raw, prior, digest in cur.fetchall():
            count += 1
            payload = _payload(raw)
            if number != count or prior != previous or digest != _digest(number, timestamp, kind, payload, prior):
                raise AuditFailure(f"audit chain invalid at record {count}")
            previous = digest
            if anchor and count == anchor["record_count"]:
                anchor_tip = digest
            if kind == "ENCRYPTED_MESSAGE" and payload.get("protocol_version") == 3:
                expected_messages[payload["message_id"]] = {"envelope": payload, "delivery_status": "QUEUED"}
                expected_order[payload["message_id"]] = number
            elif kind == "DELIVERY_ACK":
                message = expected_messages.get(payload.get("message_id"))
                if not message or payload.get("status") != "DELIVERED":
                    raise AuditFailure("invalid delivery audit record")
                message["delivery_status"] = "DELIVERED"
            elif kind == "KEY_REGISTERED":
                expected_users[payload["username"]] = (payload["exchange_public"], payload["signing_public"])
            elif kind == "KEY_ROTATED":
                old_keys = expected_users.get(payload["username"])
                if old_keys is None or hashlib.sha256(bytes.fromhex(old_keys[1])).hexdigest() != payload["old_fingerprint"]:
                    raise AuditFailure("invalid identity rotation record")
                expected_users[payload["username"]] = (payload["exchange_public"], payload["signing_public"])
            elif kind == "SECURITY_EVENT":
                expected_events.append(payload)
        if (count, previous) != (int(head[0]), head[1]):
            raise AuditFailure("audit head differs from records")
        if anchor and (count < anchor["record_count"] or anchor_tip != anchor["record_hash"]):
            raise AuditFailure("audit differs from independently saved checkpoint")
        cur.execute("SELECT message_id, conversation_id, sender_id, receiver_id, sequence_number, signed_timestamp, envelope, delivery_status FROM cc_messages")
        actual_messages = {}
        for message_id, conversation, sender, receiver, sequence, signed_time, raw_envelope, status in cur.fetchall():
            envelope = _payload(raw_envelope)
            if (conversation, sender, receiver, sequence, signed_time) != (envelope.get("conversation_id"), envelope.get("sender_id"), envelope.get("receiver_id"), envelope.get("sequence_number"), envelope.get("timestamp")):
                raise AuditFailure("message columns differ from encrypted envelope")
            actual_messages[message_id] = {"envelope": envelope, "delivery_status": status}
        if actual_messages != expected_messages:
            raise AuditFailure("message table differs from audited envelopes or delivery status")
        cur.execute("SELECT message_id, audit_number FROM cc_messages")
        if dict(cur.fetchall()) != expected_order:
            raise AuditFailure("message order differs from audit trail")
        cur.execute("SELECT username, exchange_public, signing_public FROM cc_users")
        actual_users = {name: (bytes(exchange).hex(), bytes(signing).hex()) for name, exchange, signing in cur.fetchall()}
        if actual_users != expected_users:
            raise AuditFailure("registered public keys differ from audit trail")
        cur.execute("SELECT sender_id, conversation_id, highest_sequence FROM cc_message_state")
        actual_state = {(sender, conversation): int(sequence) for sender, conversation, sequence in cur.fetchall()}
        expected_state = {}
        for entry in expected_messages.values():
            envelope = entry["envelope"]
            key = (envelope["sender_id"], envelope["conversation_id"])
            expected_state[key] = max(expected_state.get(key, 0), envelope["sequence_number"])
        if actual_state != expected_state:
            raise AuditFailure("replay counters differ from audited messages")
        cur.execute("SELECT timestamp, event_type, actor, message_id, detail_json FROM cc_security_events ORDER BY id")
        actual_events = [{"timestamp": t, "event_type": k, "actor": a, "message_id": m, "detail": _payload(detail)}
                         for t, k, a, m, detail in cur.fetchall()]
        if actual_events != expected_events:
            raise AuditFailure("security events differ from audit trail")
        return {"record_count": count, "record_hash": previous}

    def verify(self):
        conn = self.connect()
        try:
            return self._verify(conn.cursor())
        finally:
            conn.close()

    def checkpoint(self, path: Path):
        value = self.verify()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(temporary, path)
        path.chmod(0o600)
        return value

    def _append_audit(self, cur, kind: str, payload: dict) -> int:
        cur.execute("SELECT record_count, record_hash FROM cc_audit_head WHERE singleton = 1 FOR UPDATE")
        head = cur.fetchone()
        if head is None:
            raise AuditFailure("audit head missing")
        current_count = int(head[0])
        previous_hash = head[1]
        if current_count > 0:
            cur.execute("SELECT record_hash FROM cc_audit_records WHERE number = %s", (current_count,))
            tip = cur.fetchone()
            if tip is None or tip[0] != previous_hash:
                raise AuditFailure("audit head differs from records")
        number = current_count + 1
        timestamp = _now()
        digest = _digest(number, timestamp, kind, payload, previous_hash)
        cur.execute("INSERT INTO cc_audit_records VALUES (%s, %s, %s, %s, %s, %s)",
                    (number, timestamp, kind, canonical(payload).decode(), previous_hash, digest))
        cur.execute("UPDATE cc_audit_head SET record_count = %s, record_hash = %s WHERE singleton = 1", (number, digest))
        return number

    def identity(self, username: str) -> dict[str, str] | None:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT exchange_public, signing_public FROM cc_users WHERE username = %s", (username,))
            row = cur.fetchone()
            return {"exchange_public": bytes(row[0]).hex(), "signing_public": bytes(row[1]).hex()} if row else None
        finally:
            conn.close()

    def claim_session(self, username: str, token_hash: str, lease_seconds: int = 30,
                      replace_existing: bool = False) -> bool:
        """Atomically reserve one live browser session for a role."""
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("INSERT IGNORE INTO cc_role_sessions VALUES (%s, '', 0)", (username,))
            cur.execute("SELECT token_hash, last_seen FROM cc_role_sessions WHERE username = %s FOR UPDATE", (username,))
            row = cur.fetchone()
            now = time.time()
            if row and float(row[1]) > now - lease_seconds and not replace_existing:
                conn.rollback()
                return False
            cur.execute("UPDATE cc_role_sessions SET token_hash = %s, last_seen = %s WHERE username = %s",
                        (token_hash, now, username))
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def touch_session(self, username: str, token_hash: str, lease_seconds: int = 30) -> bool:
        conn = self.connect()
        try:
            cur = conn.cursor()
            now = time.time()
            cur.execute("""UPDATE cc_role_sessions SET last_seen = %s
                WHERE username = %s AND token_hash = %s AND last_seen > %s""",
                (now, username, token_hash, now - lease_seconds))
            active = cur.rowcount == 1
            conn.commit()
            return active
        finally:
            conn.close()

    def release_session(self, username: str, token_hash: str) -> None:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM cc_role_sessions WHERE username = %s AND token_hash = %s", (username, token_hash))
            conn.commit()
        finally:
            conn.close()

    def presence(self, lease_seconds: int = 30) -> dict[str, bool]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT username FROM cc_role_sessions WHERE last_seen > %s", (time.time() - lease_seconds,))
            active = {row[0] for row in cur.fetchall()}
            return {username: username in active for username in ("alice", "bob", "mallory")}
        finally:
            conn.close()

    def register_identity(self, username: str, exchange: bytes, signing: bytes) -> None:
        if username not in {"alice", "bob"} or len(exchange) != 32 or len(signing) != 32:
            raise ValueError("invalid identity registration")
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT exchange_public, signing_public FROM cc_users WHERE username = %s FOR UPDATE", (username,))
            row = cur.fetchone()
            if row:
                if bytes(row[0]) != exchange or bytes(row[1]) != signing:
                    raise ValueError("registered public key mismatch; key substitution rejected")
            else:
                self._append_audit(cur, "KEY_REGISTERED", {"username": username, "exchange_public": exchange.hex(), "signing_public": signing.hex()})
                cur.execute("INSERT INTO cc_users VALUES (%s, %s, %s, %s)", (username, exchange, signing, _now()))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def rotate_identity(self, username: str, exchange: bytes, signing: bytes) -> dict[str, object]:
        """Move a role to a new browser and invalidate the previous chat session."""
        if username not in {"alice", "bob"} or len(exchange) != 32 or len(signing) != 32:
            raise ValueError("invalid identity rotation")
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT record_count FROM cc_audit_head WHERE singleton = 1 FOR UPDATE")
            if cur.fetchone() is None:
                raise AuditFailure("audit head missing")
            self._verify(cur)
            state = self._chat_state(cur)
            if state["state"] != "SECURE":
                raise ValueError("finish security recovery before moving this role")
            cur.execute("SELECT exchange_public, signing_public FROM cc_users WHERE username = %s FOR UPDATE", (username,))
            row = cur.fetchone()
            if not row:
                raise ValueError("identity is not registered")
            if bytes(row[0]) == exchange and bytes(row[1]) == signing:
                raise ValueError("new browser must generate a different identity")
            old_fingerprint = hashlib.sha256(bytes(row[1])).hexdigest()
            new_fingerprint = hashlib.sha256(signing).hexdigest()
            self._append_audit(cur, "KEY_ROTATED", {"username": username, "exchange_public": exchange.hex(),
                                                     "signing_public": signing.hex(), "old_fingerprint": old_fingerprint})
            cur.execute("UPDATE cc_users SET exchange_public = %s, signing_public = %s, registered_at = %s WHERE username = %s",
                        (exchange, signing, _now(), username))
            timestamp = _now()
            detail = {"username": username, "old_fingerprint": old_fingerprint,
                      "new_fingerprint": new_fingerprint, "generation": state["generation"] + 1,
                      "reason": "explicit new-browser identity rotation"}
            event = {"timestamp": timestamp, "event_type": "CHAT_REKEYED", "actor": username,
                     "message_id": None, "detail": detail}
            self._append_audit(cur, "SECURITY_EVENT", event)
            cur.execute("INSERT INTO cc_security_events (timestamp, event_type, actor, message_id, detail_json) VALUES (%s, %s, %s, %s, %s)",
                        (timestamp, "CHAT_REKEYED", username, None, canonical(detail).decode()))
            conn.commit()
            return detail
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def event(self, event_type: str, actor: str, message_id: str | None, detail: dict) -> None:
        if not isinstance(message_id, str) or len(message_id) > 64:
            message_id = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            timestamp = _now()
            self._append_audit(cur, "SECURITY_EVENT", {"timestamp": timestamp, "event_type": event_type,
                                                       "actor": actor, "message_id": message_id, "detail": detail})
            cur.execute("INSERT INTO cc_security_events (timestamp, event_type, actor, message_id, detail_json) VALUES (%s, %s, %s, %s, %s)",
                        (timestamp, event_type, actor, message_id, canonical(detail).decode()))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def accept(self, envelope: dict, idempotent: bool = False) -> tuple[bool, str]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            # A single admission lock also prevents concurrent first-use
            # INSERT IGNORE operations from deadlocking on the state row.
            cur.execute("SELECT record_count FROM cc_audit_head WHERE singleton = 1 FOR UPDATE")
            if cur.fetchone() is None:
                raise AuditFailure("audit head missing")
            if idempotent:
                cur.execute("SELECT envelope FROM cc_messages WHERE message_id = %s", (envelope["message_id"],))
                existing = cur.fetchone()
                if existing and _payload(existing[0]) == envelope:
                    conn.rollback()
                    return True, "already accepted"
            state = self._chat_state(cur)
            if state["blocked"] or envelope["session_id"] != state["session_id"]:
                conn.rollback()
                return False, "chat blocked or session changed"
            sender, conversation, number = envelope["sender_id"], envelope["conversation_id"], envelope["sequence_number"]
            cur.execute("SELECT highest_sequence FROM cc_message_state WHERE sender_id = %s AND conversation_id = %s FOR UPDATE", (sender, conversation))
            state_row = cur.fetchone()
            highest = int(state_row[0]) if state_row else 0
            cur.execute("SELECT 1 FROM cc_messages WHERE message_id = %s", (envelope["message_id"],))
            if cur.fetchone() or number <= highest:
                conn.rollback()
                return False, "duplicate message ID or stale sequence"
            timestamp = _now()
            audit_number = self._append_audit(cur, "ENCRYPTED_MESSAGE", envelope)
            cur.execute("""INSERT INTO cc_messages
                (message_id, conversation_id, sender_id, receiver_id, sequence_number, signed_timestamp, received_at, envelope, audit_number, delivery_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'QUEUED')""",
                (envelope["message_id"], conversation, sender, envelope["receiver_id"], number,
                 envelope["timestamp"], timestamp, canonical(envelope).decode(), audit_number))
            if state_row:
                cur.execute("UPDATE cc_message_state SET highest_sequence = %s WHERE sender_id = %s AND conversation_id = %s",
                            (number, sender, conversation))
            else:
                cur.execute("INSERT INTO cc_message_state VALUES (%s, %s, %s)", (sender, conversation, number))
            conn.commit()
            return True, "accepted"
        except mysql.connector.IntegrityError:
            conn.rollback()
            return False, "duplicate message ID or sequence"
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def mark_delivered(self, message_id: str) -> None:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT delivery_status FROM cc_messages WHERE message_id = %s FOR UPDATE", (message_id,))
            row = cur.fetchone()
            if not row or row[0] == "DELIVERED":
                conn.rollback()
                return
            self._append_audit(cur, "DELIVERY_ACK", {"message_id": message_id, "status": "DELIVERED"})
            cur.execute("UPDATE cc_messages SET delivery_status = 'DELIVERED' WHERE message_id = %s", (message_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def message(self, message_id: str) -> dict[str, object] | None:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT envelope, delivery_status FROM cc_messages WHERE message_id = %s", (message_id,))
            row = cur.fetchone()
            return {"envelope": _payload(row[0]), "delivery_status": row[1]} if row else None
        finally:
            conn.close()

    def pending(self, username: str) -> list[dict[str, object]]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT envelope FROM cc_messages WHERE receiver_id = %s AND delivery_status = 'QUEUED' ORDER BY received_at, message_id", (username,))
            return [_payload(row[0]) for row in cur.fetchall()]
        finally:
            conn.close()

    def highest_sequence(self, username: str) -> int:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT highest_sequence FROM cc_message_state WHERE sender_id = %s AND conversation_id = 'alice-bob'", (username,))
            row = cur.fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def _chat_state(self, cur):
        cur.execute("SELECT event_type, detail_json FROM cc_security_events WHERE event_type IN ('CHAT_BLOCKED', 'CHAT_REKEYED', 'RECOVERY_STATE') ORDER BY id")
        generation, recovery, incident_type = 1, RecoveryState.SECURE, None
        for event_type, raw in cur.fetchall():
            if event_type == "CHAT_BLOCKED":
                recovery = RecoveryState.BLOCKED
                incident_type = "LEGACY_BLOCK"
            elif event_type == "CHAT_REKEYED":
                generation = int(_payload(raw)["generation"])
                recovery, incident_type = RecoveryState.SECURE, None
            else:
                detail = _payload(raw)
                recovery = RecoveryState(detail["state"])
                if recovery is RecoveryState.SUSPECTED_ATTACK:
                    incident_type = detail.get("incident_type")
                elif recovery is RecoveryState.SECURE:
                    generation = int(detail["generation"])
                    incident_type = None
        return {"session_id": f"alice-bob:{generation}", "generation": generation,
                "state": recovery.value, "blocked": recovery is not RecoveryState.SECURE,
                "incident_type": incident_type}

    def recovery_transition(self, actor: str, message_id: str | None, expected: RecoveryState,
                            transitions: tuple[RecoveryState, ...], detail: dict | None = None) -> bool:
        """Persist each permitted FSM step and its evidence under one admission lock."""
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT record_count FROM cc_audit_head WHERE singleton = 1 FOR UPDATE")
            if cur.fetchone() is None:
                raise AuditFailure("audit head missing")
            state = self._chat_state(cur)
            if state["state"] != expected.value:
                conn.rollback()
                return False
            machine = RecoveryMachine()
            machine.state = expected
            for target in transitions:
                machine.transition(target)
                payload = {**(detail or {}), "state": target.value, "session_id": state["session_id"]}
                if target is RecoveryState.SECURE:
                    payload["generation"] = state["generation"] + 1
                timestamp = _now()
                event = {"timestamp": timestamp, "event_type": "RECOVERY_STATE", "actor": actor,
                         "message_id": message_id, "detail": payload}
                self._append_audit(cur, "SECURITY_EVENT", event)
                cur.execute("INSERT INTO cc_security_events (timestamp, event_type, actor, message_id, detail_json) VALUES (%s, %s, %s, %s, %s)",
                            (timestamp, "RECOVERY_STATE", actor, message_id, canonical(payload).decode()))
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def chat_state(self) -> dict[str, object]:
        conn = self.connect()
        try:
            return self._chat_state(conn.cursor())
        finally:
            conn.close()

    def messages(self, username: str) -> list[dict[str, object]]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT envelope, delivery_status FROM cc_messages WHERE sender_id = %s OR receiver_id = %s ORDER BY received_at, message_id", (username, username))
            return [{"envelope": _payload(raw), "delivery_status": status} for raw, status in cur.fetchall()]
        finally:
            conn.close()

    def history_page(self, username: str, limit: int = 50, offset: int = 0) -> dict:
        """Bounded, stable oldest-first history shared by the three lab roles."""
        if username not in {"alice", "bob", "mallory"} or not 1 <= limit <= 100 or offset < 0:
            raise ValueError("invalid history request")
        where = "" if username == "mallory" else " WHERE sender_id = %s OR receiver_id = %s"
        params = () if username == "mallory" else (username, username)
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM cc_messages" + where, params)
            total = int(cur.fetchone()[0])
            cur.execute("SELECT envelope, delivery_status FROM cc_messages" + where +
                        " ORDER BY audit_number LIMIT %s OFFSET %s", (*params, limit, offset))
            return {"messages": [{"envelope": _payload(raw), "delivery_status": status} for raw, status in cur.fetchall()],
                    "total": total, "offset": offset, "limit": limit}
        finally:
            conn.close()

    def start_new_run(self, expected_session: str) -> dict:
        """Operator-only fresh context; preserve all messages and incident evidence."""
        conn = self.connect()
        try:
            cur = conn.cursor()
            self._verify(cur)
            state = self._chat_state(cur)
            if state["session_id"] != expected_session:
                raise ValueError("session changed; verify the current session before starting a run")
            detail = {"generation": state["generation"] + 1, "previous_session": expected_session,
                      "reason": "operator explicitly started a fresh laboratory run"}
            timestamp = _now()
            event = {"timestamp": timestamp, "event_type": "CHAT_REKEYED", "actor": "operator",
                     "message_id": None, "detail": detail}
            self._append_audit(cur, "SECURITY_EVENT", event)
            cur.execute("INSERT INTO cc_security_events (timestamp, event_type, actor, message_id, detail_json) VALUES (%s, %s, %s, %s, %s)",
                        (timestamp, "CHAT_REKEYED", "operator", None, canonical(detail).decode()))
            conn.commit()
            return {**detail, "session_id": f"alice-bob:{detail['generation']}"}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def captured(self) -> list[dict[str, object]]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT envelope, delivery_status FROM cc_messages ORDER BY received_at DESC, message_id DESC LIMIT 100")
            return [{"envelope": _payload(raw), "delivery_status": status} for raw, status in cur.fetchall()]
        finally:
            conn.close()

    def events(self) -> list[dict[str, object]]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT timestamp, event_type, actor, message_id, detail_json FROM cc_security_events ORDER BY id DESC LIMIT 100")
            return [{"timestamp": t, "event_type": k, "actor": a, "message_id": m, "detail": _payload(d)}
                    for t, k, a, m, d in cur.fetchall()]
        finally:
            conn.close()

    def stats(self) -> dict[str, object]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            audit = self._verify(cur)
            cur.execute("SELECT delivery_status, COUNT(*) FROM cc_messages GROUP BY delivery_status")
            statuses = dict(cur.fetchall())
            cur.execute("SELECT event_type, COUNT(*) FROM cc_security_events GROUP BY event_type")
            events = dict(cur.fetchall())
            cur.execute("""SELECT COUNT(*) FROM cc_security_events WHERE event_type = 'TAMPERING'
                AND JSON_UNQUOTE(JSON_EXTRACT(detail_json, '$.reason')) LIKE '%signature%'""")
            signature_failures = int(cur.fetchone()[0])
            return {"messages_sent": sum(statuses.values()), "messages_delivered": statuses.get("DELIVERED", 0),
                    "signatures_verified": sum(statuses.values()), "signature_failures": signature_failures,
                    "events": events, "audit": audit}
        finally:
            conn.close()

    def audit_rows(self) -> list[dict[str, object]]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            self._verify(cur)
            cur.execute("SELECT number, timestamp, kind, previous_hash, record_hash FROM cc_audit_records ORDER BY number DESC LIMIT 100")
            return [{"number": n, "timestamp": t, "kind": k, "previous_hash": p, "record_hash": h}
                    for n, t, k, p, h in cur.fetchall()]
        finally:
            conn.close()

    def delete_audit_row_for_demo(self, number: int) -> None:
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise ValueError("invalid audit record number")
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM cc_audit_records WHERE number = %s", (number,))
            if cur.rowcount != 1:
                conn.rollback()
                raise ValueError("audit record does not exist")
            conn.commit()
        finally:
            conn.close()
