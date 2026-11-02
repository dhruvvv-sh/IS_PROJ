"""Stateless HTTP relay for Vercel; browser keys stay in IndexedDB."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .database import AuditFailure, Config, Database
from .protocol import EnvelopeError, aad, decode_base64, validate_envelope
from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.security.attacks import KeySubstitutionError, verify_expected_public_key
from cipherchat.security.recovery import RecoveryState

STATIC = Path(__file__).with_name("static")
USERS = {"alice", "bob", "mallory"}


def _secret() -> bytes:
    value = os.getenv("CIPHERCHAT_SESSION_SECRET")
    if not value or len(value) < 32:
        raise RuntimeError("set CIPHERCHAT_SESSION_SECRET to at least 32 characters")
    return value.encode()


def _hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return f"pbkdf2_sha256$100000${salt.hex()}${derived.hex()}"


def _verify_password(username: str, candidate: str) -> bool:
    stored = os.getenv(f"CIPHERCHAT_{username.upper()}_PASSWORD")
    if not stored:
        raise RuntimeError(f"set CIPHERCHAT_{username.upper()}_PASSWORD")
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters_str, salt_hex, hash_hex = stored.split("$", 3)
            iters = int(iters_str)
            salt = bytes.fromhex(salt_hex)
            derived = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, iters)
            return hmac.compare_digest(derived.hex(), hash_hex)
        except Exception:
            return False
    return hmac.compare_digest(candidate, stored)


def _password(username: str) -> str:
    value = os.getenv(f"CIPHERCHAT_{username.upper()}_PASSWORD")
    if not value:
        raise RuntimeError(f"set CIPHERCHAT_{username.upper()}_PASSWORD")
    return value


_rate_limit_state: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW = 60


def _rate_limit(key: str, max_attempts: int | None = None, window: int = RATE_LIMIT_WINDOW) -> None:
    limit_env = os.getenv("CIPHERCHAT_RATE_LIMIT")
    if limit_env == "0" or "testclient" in key:
        return
    limit = max_attempts or int(limit_env or "60")
    now = time.time()
    attempts = _rate_limit_state.setdefault(key, [])
    valid = [t for t in attempts if t > now - window]
    _rate_limit_state[key] = valid
    if len(valid) >= limit:
        raise HTTPException(429, "too many requests; please slow down")
    valid.append(now)


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

_allowed_origins = [o.strip() for o in os.getenv("CIPHERCHAT_ALLOWED_ORIGINS", "").split(",") if o.strip()]
if _allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def central_api_or_frontend_proxy(request: Request, call_next):
    """Keep the Vercel page same-origin while its API runs on Alice's MacBook."""
    path = request.url.path
    if request.method in {"POST", "PUT", "PATCH"}:
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 200_000:
                return JSONResponse({"detail": "request exceeds 200,000 bytes"}, status_code=413)
        request._body = bytes(body)
    upstream = os.getenv("CIPHERCHAT_API_UPSTREAM_URL", "").rstrip("/")
    central_only = os.getenv("CIPHERCHAT_CENTRAL_ONLY") == "1"
    if central_only and path != "/health":
        if not path.startswith("/api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        expected = os.getenv("CIPHERCHAT_PROXY_SECRET", "")
        supplied = request.headers.get("x-cipherchat-proxy-secret", "")
        if len(expected) < 32 or not hmac.compare_digest(supplied, expected):
            return JSONResponse({"detail": "proxy authorization required"}, status_code=403)
    if upstream and path.startswith("/api/"):
        origin = request.headers.get("origin")
        host = request.headers.get("host")
        if origin and origin not in {f"http://{host}", f"https://{host}"}:
            return JSONResponse({"detail": "cross-origin request rejected"}, status_code=403)
        parsed = urlparse(upstream)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            return JSONResponse({"detail": "invalid HTTPS API upstream configuration"}, status_code=503)
        proxy_secret = os.getenv("CIPHERCHAT_PROXY_SECRET", "")
        if len(proxy_secret) < 32:
            return JSONResponse({"detail": "proxy secret is not configured"}, status_code=503)
        query = f"?{request.url.query}" if request.url.query else ""
        headers = {name: value for name, value in request.headers.items()
                   if name.lower() in {"accept", "content-type", "cookie", "user-agent"}}
        headers["x-cipherchat-proxy-secret"] = proxy_secret
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
                result = await client.request(request.method, upstream + path + query,
                                              content=await request.body(), headers=headers)
        except httpx.RequestError:
            return JSONResponse({"detail": "Alice's backend is unavailable"}, status_code=502)
        outgoing = {name: value for name, value in result.headers.items()
                    if name.lower() in {"content-type", "set-cookie", "cache-control"}}
        return Response(content=result.content, status_code=result.status_code, headers=outgoing)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


async def _json_object(request: Request) -> dict:
    try:
        value = await request.json()
    except (ValueError, UnicodeDecodeError) as error:
        raise HTTPException(400, "invalid JSON body") from error
    if not isinstance(value, dict):
        raise HTTPException(400, "request must be an object")
    return value


@lru_cache(maxsize=1)
def _database() -> Database:
    database = Database(Config.from_env())
    return database


def _db(request: Request) -> Database:
    return _database()


def _check(db: Database):
    try:
        db.verify()
    except Exception as error:
        raise HTTPException(409, f"chat blocked: audit integrity failure: {error}") from error


@app.get("/health")
def health(request: Request):
    """Health check endpoint for Docker and orchestrator probes."""
    if os.getenv("CIPHERCHAT_CENTRAL_ONLY") == "1" and (not request.client or request.client.host not in {"127.0.0.1", "::1"}):
        raise HTTPException(404, "not found")
    db_ok = True
    try:
        _db(request).presence()
    except Exception:
        db_ok = False
    return JSONResponse(
        {"status": "ok" if db_ok else "degraded", "database": "connected" if db_ok else "unreachable"},
        status_code=200 if db_ok else 503,
    )


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/login")
async def login(request: Request):
    _same_origin(request)
    client_ip = request.client.host if request.client else "unknown"
    _rate_limit(f"login:{client_ip}")
    data = await _json_object(request)
    if not isinstance(data, dict):
        raise HTTPException(400, "request must be an object")
    username = data.get("username", "")
    if not isinstance(username, str) or username not in USERS or not _verify_password(username, str(data.get("password", ""))):
        raise HTTPException(401, "invalid credentials")
    token = _token(username)
    if not _db(request).claim_session(username, _token_hash(token), replace_existing=data.get("replace_existing") is True):
        raise HTTPException(409, f"{username.capitalize()} is already online. Log out there, wait 30 seconds, or take over this role.")
    response = JSONResponse({"username": username})
    response.set_cookie("cipherchat_session", token, httponly=True, samesite="strict",
                        secure=os.getenv("CIPHERCHAT_COOKIE_SECURE", "1") == "1", max_age=8 * 3600)
    return response


@app.post("/api/logout")
def logout(request: Request):
    _same_origin(request)
    token = request.cookies.get("cipherchat_session")
    username = _user(token)
    if username:
        _db(request).release_session(username, _token_hash(token))
    response = JSONResponse({"ok": True})
    response.delete_cookie("cipherchat_session")
    return response


@app.post("/api/refresh")
def refresh_session(request: Request):
    _same_origin(request)
    username = _http_user(request)
    new_token = _token(username)
    if not _db(request).claim_session(username, _token_hash(new_token), replace_existing=True):
        raise HTTPException(409, "could not refresh session")
    response = JSONResponse({"username": username, "refreshed": True})
    response.set_cookie("cipherchat_session", new_token, httponly=True, samesite="strict",
                        secure=os.getenv("CIPHERCHAT_COOKIE_SECURE", "1") == "1", max_age=8 * 3600)
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
    data = await _json_object(request)
    if not isinstance(data, dict):
        raise HTTPException(400, "request must be an object")
    try:
        exchange = bytes.fromhex(data["exchange_public"])
        signing = bytes.fromhex(data["signing_public"])
        db.register_identity(username, exchange, signing)
    except (ValueError, KeyError) as error:
        if "mismatch" in str(error):
            db.event("KEY_SUBSTITUTION", username, None, {"reason": str(error)})
            db.recovery_transition(username, None, RecoveryState.SECURE,
                                   (RecoveryState.SUSPECTED_ATTACK, RecoveryState.QUARANTINED),
                                   {"incident_type": "KEY_SUBSTITUTION", "reason": str(error)})
        raise HTTPException(409, str(error)) from error
    return {"username": username, "keys": db.identity(username)}


@app.post("/api/identity/rotate")
async def rotate_identity(request: Request):
    _same_origin(request)
    username = _http_user(request)
    if username == "mallory":
        raise HTTPException(403, "Mallory has no chat identity")
    db = _db(request)
    _check(db)
    data = await _json_object(request)
    if not isinstance(data, dict) or data.get("confirm_new_browser") is not True:
        raise HTTPException(400, "explicit new-browser confirmation required")
    try:
        exchange = bytes.fromhex(data["exchange_public"])
        signing = bytes.fromhex(data["signing_public"])
        detail = db.rotate_identity(username, exchange, signing)
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(409, str(error)) from error
    return {"username": username, "keys": db.identity(username), "chat": db.chat_state(),
            "old_fingerprint": detail["old_fingerprint"], "new_fingerprint": detail["new_fingerprint"]}


@app.get("/api/history")
def history(request: Request, limit: int = 50, offset: int = 0):
    username = _http_user(request)
    if not 1 <= limit <= 100 or offset < 0:
        raise HTTPException(400, "limit must be 1–100 and offset must be nonnegative")
    return _db(request).history_page(username, limit, offset)


@app.get("/api/messages/{message_id}")
def message_status(message_id: str, request: Request):
    username = _http_user(request)
    row = _db(request).message(message_id)
    if not row or (username != "mallory" and username not in {row["envelope"]["sender_id"], row["envelope"]["receiver_id"]}):
        raise HTTPException(404, "message not found")
    return row


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
        stats = db.stats()
    except AuditFailure:
        audit_valid = False
        stats = {"audit": {"valid": False}}
    return {"chat": db.chat_state(), "presence": db.presence(), "audit_valid": audit_valid,
            "destructive_demo": os.getenv("CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO") == "1" and os.getenv("CIPHERCHAT_DISPOSABLE_LAB") == "1",
            "stats": stats, "events": db.events()}


@app.get("/api/mallory/audit")
def mallory_audit(request: Request):
    if _http_user(request) != "mallory":
        raise HTTPException(403, "Mallory role required")
    db = _db(request)
    _check(db)
    return {"records": db.audit_rows()}


def _classify(error: str) -> str:
    if "signature" in error or "ciphertext" in error or "schema" in error or "base64" in error:
        return "TAMPERING"
    if "timestamp" in error:
        return "TIMESTAMP_REJECTED"
    return "INVALID_MESSAGE"


def _quarantine(db: Database, actor: str, message_id: str | None, event_type: str, reason: str) -> None:
    db.recovery_transition(actor, message_id, RecoveryState.SECURE,
                           (RecoveryState.SUSPECTED_ATTACK, RecoveryState.QUARANTINED),
                           {"incident_type": event_type, "reason": reason})


def _submit(db: Database, actor: str, envelope: dict, simulated: bool = False,
            verification_time: datetime | None = None, idempotent: bool = False) -> dict:
    try:
        _check(db)
        state = db.chat_state()
        if state["blocked"]:
            return {"accepted": False, "reason": f"chat is {state['state'].lower()}; recovery is required",
                    "event_type": state["state"]}
        if not isinstance(envelope, dict):
            db.event("INVALID_MESSAGE", actor, None, {"reason": "envelope must be an object"})
            return {"accepted": False, "reason": "envelope must be an object", "event_type": "INVALID_MESSAGE"}
        if not simulated and actor != envelope.get("sender_id"):
            reason = "authenticated actor differs from claimed sender"
            db.event("IMPERSONATION", actor, envelope.get("message_id"), {"reason": reason})
            _quarantine(db, actor, envelope.get("message_id"), "IMPERSONATION", reason)
            return {"accepted": False, "reason": "authenticated sender mismatch", "event_type": "IMPERSONATION"}
        sender = envelope.get("sender_id")
        keys = db.identity(sender) if sender in {"alice", "bob"} else None
        if not keys:
            reason = "sender has no registered key"
            db.event("AUTHENTICATION_FAILURE", actor, envelope.get("message_id"), {"reason": reason})
            if simulated:
                _quarantine(db, actor, envelope.get("message_id"), "AUTHENTICATION_FAILURE", reason)
            return {"accepted": False, "reason": "sender key not registered", "event_type": "AUTHENTICATION_FAILURE"}
        try:
            validate_envelope(envelope, bytes.fromhex(keys["signing_public"]),
                              now=verification_time,
                              window_seconds=int(os.getenv("CIPHERCHAT_TIMESTAMP_WINDOW_SECONDS", "300")))
            if envelope["session_id"] != state["session_id"]:
                raise EnvelopeError("session changed; refresh chat")
        except (EnvelopeError, ValueError, KeyError, TypeError) as error:
            reason = str(error)
            event_type = _classify(reason)
            db.event(event_type, actor, envelope.get("message_id"), {"reason": reason, "claimed_sender": sender})
            if simulated or event_type in {"TAMPERING", "TIMESTAMP_REJECTED"}:
                _quarantine(db, actor, envelope.get("message_id"), event_type, reason)
            return {"accepted": False, "reason": reason, "event_type": event_type}
        accepted, reason = db.accept(envelope, idempotent=True) if idempotent else db.accept(envelope)
        if not accepted:
            if "chat blocked or session changed" in reason:
                return {"accepted": False, "reason": reason, "event_type": "SESSION_UNAVAILABLE"}
            db.event("REPLAY", actor, envelope["message_id"],
                     {"reason": reason, "verified_sender": sender,
                      "attempted_timestamp": envelope["timestamp"],
                      "sequence_number": envelope["sequence_number"]})
            _quarantine(db, actor, envelope["message_id"], "REPLAY", reason)
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
    data = await _json_object(request)
    if not isinstance(data, dict):
        raise HTTPException(400, "request must be an object")
    db = _db(request)
    envelope = data.get("envelope")
    retry_key = request.headers.get("x-cipherchat-request-id")
    idempotent = bool(retry_key and isinstance(envelope, dict) and retry_key == envelope.get("message_id")
                      and username == envelope.get("sender_id"))
    if idempotent:
        _check(db)
        existing = db.message(retry_key)
        if existing and existing["envelope"] == envelope:
            return {"accepted": True, "reason": "already accepted", "delivery_status": existing["delivery_status"]}
    return _submit(db, username, envelope, idempotent=idempotent)


@app.post("/api/delivered")
async def delivered(request: Request):
    _same_origin(request)
    username = _http_user(request)
    data = await _json_object(request)
    if not isinstance(data, dict) or not isinstance(data.get("message_id"), str):
        raise HTTPException(400, "message_id must be a string")
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
    if state["state"] == RecoveryState.BLOCKED.value and state["incident_type"] == "LEGACY_BLOCK":
        db.event("CHAT_REKEYED", username, None, {"generation": state["generation"] + 1,
                                                   "reason": "migrate a chat blocked by the previous recovery flow"})
        return {"chat": db.chat_state(), "verified": True}
    if state["state"] == RecoveryState.BLOCKED.value:
        raise HTTPException(409, "verification failed; this relationship is blocked")
    if state["state"] != RecoveryState.QUARANTINED.value:
        raise HTTPException(409, "chat is not quarantined")
    if state["incident_type"] == "KEY_SUBSTITUTION":
        db.recovery_transition(username, None, RecoveryState.QUARANTINED,
                               (RecoveryState.VERIFYING, RecoveryState.BLOCKED),
                               {"reason": "presented peer key differs from registered key"})
        return {"chat": db.chat_state(), "verified": False}
    if not db.identity("alice") or not db.identity("bob"):
        db.recovery_transition(username, None, RecoveryState.QUARANTINED,
                               (RecoveryState.VERIFYING, RecoveryState.BLOCKED),
                               {"reason": "both registered identities required"})
        return {"chat": db.chat_state(), "verified": False}
    if not db.recovery_transition(username, None, RecoveryState.QUARANTINED,
                                  (RecoveryState.VERIFYING, RecoveryState.REKEYING, RecoveryState.SECURE),
                                  {"reason": "audit and registered identities verified"}):
        raise HTTPException(409, "recovery state changed; refresh chat")
    return {"chat": db.chat_state(), "verified": True}


@app.post("/api/operator/new-run")
def operator_new_run(request: Request):
    _same_origin(request)
    _http_user(request)
    db = _db(request)
    _check(db)
    state = db.chat_state()
    detail = db.start_new_run(state["session_id"])
    return {"chat": db.chat_state(), "detail": detail}


@app.post("/api/mallory/attack")
async def mallory_attack(request: Request):
    _same_origin(request)
    if _http_user(request) != "mallory":
        raise HTTPException(403, "Mallory role required")
    db = _db(request)
    _check(db)
    data = await _json_object(request)
    if not isinstance(data, dict):
        raise HTTPException(400, "request must be an object")
    attack = data.get("attack")
    if attack == "delete_record":
        if os.getenv("CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO") != "1" or os.getenv("CIPHERCHAT_DISPOSABLE_LAB") != "1":
            raise HTTPException(403, "record deletion is disabled; enable destructive demo and disposable lab flags only on a separate disposable database")
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
        source_id = data.get("message_id")
        if source_id is not None and not isinstance(source_id, str):
            raise HTTPException(400, "message_id must be a string")
        selected = db.message(source_id) if source_id is not None else None
        if source_id is not None and selected is None:
            raise HTTPException(404, "captured message not found")
        captured = db.captured() if selected is None else [selected]
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
            _quarantine(db, "mallory", None, "KEY_SUBSTITUTION", str(error))
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
    verification_time = None
    if attack == "stale":
        sent_at = datetime.fromisoformat(original["timestamp"].replace("Z", "+00:00"))
        verification_time = sent_at + timedelta(seconds=int(os.getenv("CIPHERCHAT_TIMESTAMP_WINDOW_SECONDS", "300")) + 1)
    result = _submit(db, "mallory", modified, simulated=attack != "impersonate", verification_time=verification_time)
    return {"attack": attack, "original": original, "submitted": modified, **result}
