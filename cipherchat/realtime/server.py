"""Stateless HTTP relay for Vercel; browser keys stay in IndexedDB."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .database import AuditFailure, Config, Database
from .protocol import EnvelopeError, aad, decode_base64, validate_envelope
from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.security.attacks import KeySubstitutionError, verify_expected_public_key

STATIC = Path(__file__).with_name("static")
USERS = {"alice", "bob", "mallory"}


def _secret() -> bytes:
    value = os.getenv("CIPHERCHAT_SESSION_SECRET")
    if not value or len(value) < 32:
        raise RuntimeError("set CIPHERCHAT_SESSION_SECRET to at least 32 characters")
    return value.encode()


def _password(username: str) -> str:
    value = os.getenv(f"CIPHERCHAT_{username.upper()}_PASSWORD")
    if not value:
        raise RuntimeError(f"set CIPHERCHAT_{username.upper()}_PASSWORD")
    return value


def _token(username: str) -> str:
    payload = json.dumps({"user": username, "exp": int(time.time()) + 8 * 3600, "nonce": secrets.token_hex(16)},
                         sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    mac = hmac.new(_secret(), encoded.encode(), hashlib.sha256).hexdigest()
    return encoded + "." + mac


def _user(token: str | None) -> str | None:
    if not token:
        return None
    try:
        encoded, mac = token.split(".", 1)
        expected = hmac.new(_secret(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        return data["user"] if data["user"] in USERS and int(data["exp"]) > time.time() else None
    except (ValueError, KeyError, TypeError):
        return None


def _http_user(request: Request) -> str:
    token = request.cookies.get("cipherchat_session")
    username = _user(token)
    if not username or not _db(request).touch_session(username, _token_hash(token)):
        raise HTTPException(401, "session expired or replaced; log in again")
    return username


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    host = request.headers.get("host")
    if origin and origin not in {f"http://{host}", f"https://{host}"}:
        raise HTTPException(403, "cross-origin request rejected")


app = FastAPI(title="CipherChat HTTP laboratory")
STATIC.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@lru_cache(maxsize=1)
def _database() -> Database:
    database = Database(Config.from_env())
    database.migrate()
    return database


def _db(request: Request) -> Database:
    return _database()


def _check(db: Database):
    try:
        db.verify()
    except Exception as error:
        raise HTTPException(409, f"chat blocked: audit integrity failure: {error}") from error


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/login")
async def login(request: Request):
    _same_origin(request)
    data = await request.json()
    username = data.get("username", "")
    if username not in USERS or not hmac.compare_digest(str(data.get("password", "")), _password(username)):
        raise HTTPException(401, "invalid credentials")
    token = _token(username)
    if not _db(request).claim_session(username, _token_hash(token)):
        raise HTTPException(409, f"{username.capitalize()} is already online. Log out there or wait 30 seconds after closing that browser.")
    from fastapi.responses import JSONResponse
    response = JSONResponse({"username": username})
    response.set_cookie("cipherchat_session", token, httponly=True, samesite="strict",
                        secure=os.getenv("CIPHERCHAT_COOKIE_SECURE") == "1", max_age=8 * 3600)
    return response


@app.post("/api/logout")
def logout(request: Request):
    _same_origin(request)
    token = request.cookies.get("cipherchat_session")
    username = _user(token)
    if username:
        _db(request).release_session(username, _token_hash(token))
    from fastapi.responses import JSONResponse
    response = JSONResponse({"ok": True})
    response.delete_cookie("cipherchat_session")
    return response


@app.get("/api/me")
def me(request: Request):
    username = _http_user(request)
    return {"username": username, "chat": _db(request).chat_state(), "presence": _db(request).presence()}


@app.get("/api/identity/{username}")
def identity(username: str, request: Request):
    _http_user(request)
    if username not in {"alice", "bob"}:
        raise HTTPException(404, "unknown identity")
    return {"username": username, "keys": _db(request).identity(username)}


@app.post("/api/identity")
async def register(request: Request):
    _same_origin(request)
    username = _http_user(request)
    if username == "mallory":
        raise HTTPException(403, "Mallory cannot register a chat identity")
    db = _db(request)
    _check(db)
    data = await request.json()
    try:
        exchange = bytes.fromhex(data["exchange_public"])
        signing = bytes.fromhex(data["signing_public"])
        db.register_identity(username, exchange, signing)
    except (ValueError, KeyError) as error:
        if "mismatch" in str(error):
            db.event("KEY_SUBSTITUTION", username, None, {"reason": str(error)})
        raise HTTPException(409, str(error)) from error
    return {"username": username, "keys": db.identity(username)}


@app.get("/api/history")
def history(request: Request):
    username = _http_user(request)
    return {"messages": _db(request).captured() if username == "mallory" else _db(request).messages(username)}


@app.get("/api/sequence")
def sequence(request: Request):
    username = _http_user(request)
    if username == "mallory":
        raise HTTPException(403, "Mallory is not a chat sender")
    return {"highest_sequence": _db(request).highest_sequence(username)}


@app.get("/api/dashboard")
def dashboard(request: Request):
    _http_user(request)
    db = _db(request)
    audit_valid = True
    try:
        _check(db)
        stats = db.stats()
    except HTTPException:
        audit_valid = False
        stats = {"audit": {"valid": False}}
    return {"chat": db.chat_state(), "presence": db.presence(), "audit_valid": audit_valid,
            "stats": stats, "events": db.events()}


@app.get("/api/mallory/audit")
def mallory_audit(request: Request):
    if _http_user(request) != "mallory":
        raise HTTPException(403, "Mallory role required")
    db = _db(request)
    _check(db)
    return {"records": db.audit_rows()}


def _classify(error: str) -> str:
    if "signature" in error or "ciphertext" in error or "schema" in error:
        return "TAMPERING"
    if "timestamp" in error:
        return "TIMESTAMP_REJECTED"
    return "INVALID_MESSAGE"


def _submit(db: Database, actor: str, envelope: dict, simulated: bool = False) -> dict:
    try:
        _check(db)
        state = db.chat_state()
        if state["blocked"]:
            return {"accepted": False, "reason": "chat blocked; Alice or Bob can start a new chat", "event_type": "CHAT_BLOCKED"}
        if not isinstance(envelope, dict):
            db.event("INVALID_MESSAGE", actor, None, {"reason": "envelope must be an object"})
            return {"accepted": False, "reason": "envelope must be an object", "event_type": "INVALID_MESSAGE"}
        if not simulated and actor != envelope.get("sender_id"):
            db.event("IMPERSONATION", actor, envelope.get("message_id"), {"reason": "authenticated actor differs from claimed sender"})
            db.event("CHAT_BLOCKED", actor, envelope.get("message_id"), {"reason": "impersonation attempt"})
            return {"accepted": False, "reason": "authenticated sender mismatch", "event_type": "IMPERSONATION"}
        sender = envelope.get("sender_id")
        keys = db.identity(sender) if sender in {"alice", "bob"} else None
        if not keys:
            db.event("AUTHENTICATION_FAILURE", actor, envelope.get("message_id"), {"reason": "sender has no registered key"})
            return {"accepted": False, "reason": "sender key not registered", "event_type": "AUTHENTICATION_FAILURE"}
        try:
            validate_envelope(envelope, bytes.fromhex(keys["signing_public"]),
                              window_seconds=int(os.getenv("CIPHERCHAT_TIMESTAMP_WINDOW_SECONDS", "300")))
            if envelope["session_id"] != state["session_id"]:
                raise EnvelopeError("session changed; refresh chat")
        except (EnvelopeError, ValueError, KeyError, TypeError) as error:
            reason = str(error)
            event_type = _classify(reason)
            db.event(event_type, actor, envelope.get("message_id"), {"reason": reason, "claimed_sender": sender})
            if event_type == "TAMPERING":
                db.event("CHAT_BLOCKED", actor, envelope.get("message_id"), {"reason": reason})
            return {"accepted": False, "reason": reason, "event_type": event_type}
        accepted, reason = db.accept(envelope)
        if not accepted:
            db.event("REPLAY", actor, envelope["message_id"],
                     {"reason": reason, "verified_sender": sender,
                      "attempted_timestamp": envelope["timestamp"],
                      "sequence_number": envelope["sequence_number"]})
            db.event("CHAT_BLOCKED", actor, envelope["message_id"], {"reason": reason})
            return {"accepted": False, "reason": reason, "event_type": "REPLAY"}
        return {"accepted": True, "reason": "accepted", "delivery_status": "QUEUED"}
    except HTTPException as error:
        return {"accepted": False, "reason": error.detail, "event_type": "AUDIT_FAILURE"}
    except Exception as error:
        return {"accepted": False, "reason": f"database failure: {error}", "event_type": "DATABASE_FAILURE"}


@app.post("/api/send")
async def send(request: Request):
    _same_origin(request)
    username = _http_user(request)
    if username == "mallory":
        raise HTTPException(403, "Mallory cannot send chat messages")
    data = await request.json()
    return _submit(_db(request), username, data.get("envelope"))


@app.post("/api/delivered")
async def delivered(request: Request):
    _same_origin(request)
    username = _http_user(request)
    data = await request.json()
    db = _db(request)
    _check(db)
    row = db.message(data.get("message_id", ""))
    if not row or row["envelope"]["receiver_id"] != username:
        raise HTTPException(403, "message is not addressed to this user")
    db.mark_delivered(data["message_id"])
    return {"ok": True}


@app.post("/api/rekey")
def rekey(request: Request):
    _same_origin(request)
    username = _http_user(request)
    if username == "mallory":
        raise HTTPException(403, "Alice or Bob required")
    db = _db(request)
    _check(db)
    state = db.chat_state()
    if not state["blocked"]:
        raise HTTPException(409, "chat is already active")
    db.event("CHAT_REKEYED", username, None, {"generation": state["generation"] + 1,
                                               "reason": "new session after security incident"})
    return {"chat": db.chat_state()}


@app.post("/api/mallory/attack")
async def mallory_attack(request: Request):
    _same_origin(request)
    if _http_user(request) != "mallory":
        raise HTTPException(403, "Mallory role required")
    db = _db(request)
    _check(db)
    data = await request.json()
    attack = data.get("attack")
    if attack == "delete_record":
        if os.getenv("CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO") != "1":
            raise HTTPException(403, "record deletion is disabled; set CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO=1 for a controlled lab")
        number = data.get("record_number")
        if not isinstance(number, int) or isinstance(number, bool):
            raise HTTPException(400, "select an audit record number")
        record = next((item for item in db.audit_rows() if item["number"] == number), None)
        if not record:
            raise HTTPException(404, "audit record not found")
        db.event("EVIDENCE_DELETE_ATTEMPT", "mallory", None, {"record_number": number, "record_hash": record["record_hash"]})
        db.delete_audit_row_for_demo(number)
        try:
            db.verify()
        except AuditFailure as error:
            return {"attack": attack, "accepted": False, "deleted_record": record,
                    "audit_valid": False, "chat_blocked": True, "reason": str(error)}
        raise HTTPException(500, "deletion unexpectedly left the chain valid")
    if attack == "eavesdrop":
        captured = db.captured()
        if not captured:
            raise HTTPException(404, "no captured message")
        envelope = captured[0]["envelope"]
        wrong_key_rejected = False
        try:
            AESGCM(os.urandom(32)).decrypt(decode_base64(envelope["nonce"]), decode_base64(envelope["ciphertext"]), aad(envelope))
        except InvalidTag:
            wrong_key_rejected = True
        db.event("EAVESDROP", "mallory", envelope["message_id"], {"ciphertext": envelope["ciphertext"], "wrong_key_rejected": wrong_key_rejected})
        return {"attack": attack, "original": envelope, "observed_ciphertext": envelope["ciphertext"],
                "wrong_key_rejected": wrong_key_rejected, "plaintext_access": False}
    if attack == "key_substitution":
        registered = db.identity("alice")
        if not registered:
            raise HTTPException(404, "Alice has not registered a key")
        mallory = Identity.create("mallory")
        presented = public_key_bytes(mallory.public_key)
        try:
            verify_expected_public_key(bytes.fromhex(registered["exchange_public"]), presented)
        except KeySubstitutionError as error:
            db.event("KEY_SUBSTITUTION", "mallory", None, {"reason": str(error), "presented_public_key": presented.hex()})
            return {"attack": attack, "accepted": False, "reason": str(error),
                    "expected_public_key": registered["exchange_public"], "presented_public_key": presented.hex()}
        raise HTTPException(500, "substitution unexpectedly passed")
    source_id = data.get("message_id")
    row = db.message(source_id) if isinstance(source_id, str) else None
    if not row:
        raise HTTPException(404, "captured message not found")
    original = row["envelope"]
    modified = dict(original)
    if attack == "tamper":
        field = data.get("field", "ciphertext")
        if field not in {"ciphertext", "nonce", "sender_id", "receiver_id", "sequence_number", "timestamp", "message_id"}:
            raise HTTPException(400, "unsupported tamper field")
        if field in {"ciphertext", "nonce"}:
            raw = bytearray(decode_base64(modified[field]))
            raw[0] ^= 1
            modified[field] = base64.b64encode(raw).decode()
        elif field == "sequence_number":
            modified[field] += 1
        elif field == "message_id":
            from uuid import uuid4
            modified[field] = str(uuid4())
        else:
            modified[field] = "mallory-modified"
    elif attack == "impersonate":
        from uuid import uuid4
        modified["sender_id"] = "alice"
        modified["message_id"] = str(uuid4())
        # Mallory has no Alice credentials, so use the normal actor binding.
    elif attack not in {"replay", "stale"}:
        raise HTTPException(400, "unknown attack")
    result = _submit(db, "mallory", modified, simulated=attack != "impersonate")
    return {"attack": attack, "original": original, "submitted": modified, **result}
