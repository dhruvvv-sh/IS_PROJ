"""Regression tests for the shared terminal lab's HTTP contracts."""
from fastapi.testclient import TestClient
from cipherchat.realtime import server
from tests.test_realtime_http_cases import lab, post
from tests.test_realtime import MemoryDatabase, envelope_for


def test_retry_is_idempotent_but_mallory_replay_is_detected(lab):
    client, cookies, db, alice, bob = lab
    envelope = envelope_for(alice, bob)
    headers = {"x-cipherchat-request-id": envelope["message_id"]}
    for _ in range(2):
        response = client.post("/api/send", cookies=cookies["alice"], headers=headers, json={"envelope": envelope})
        assert response.json()["accepted"] is True
    assert len(db.saved) == 1
    assert not db.security_events
    receipt = client.get("/api/messages/" + envelope["message_id"], cookies=cookies["alice"])
    assert receipt.json()["envelope"] == envelope
    attack = post(client, cookies, "mallory", "/api/mallory/attack", {"attack": "replay", "message_id": envelope["message_id"]})
    assert attack.json()["accepted"] is False
    assert attack.json()["event_type"] == "REPLAY"


def test_retry_cannot_bypass_sender_binding(lab):
    client, cookies, db, alice, bob = lab
    envelope = envelope_for(alice, bob)
    assert post(client, cookies, "alice", "/api/send", {"envelope": envelope}).json()["accepted"]
    response = client.post("/api/send", cookies=cookies["bob"], headers={"x-cipherchat-request-id": envelope["message_id"]}, json={"envelope": envelope})
    assert response.json()["accepted"] is False
    assert response.json()["event_type"] == "IMPERSONATION"
    assert len(db.saved) == 1


def test_pagination_beyond_one_hundred_and_validation(lab):
    client, cookies, db, alice, bob = lab
    for seq in range(1, 122):
        db.accept(envelope_for(alice, bob, sequence=seq))
    for role in ("alice", "bob", "mallory"):
        response = client.get("/api/history?limit=50&offset=100", cookies=cookies[role])
        assert response.json()["total"] == 121
        assert len(response.json()["messages"]) == 21
        assert response.json()["messages"][0]["envelope"]["sequence_number"] == 101
    for query in ("limit=0", "limit=101", "offset=-1"):
        assert client.get("/api/history?" + query, cookies=cookies["alice"]).status_code == 400


def test_bad_json_and_actual_request_limit(lab):
    client, cookies, *_ = lab
    for path in ("/api/send", "/api/mallory/attack", "/api/delivered"):
        response = client.post(path, cookies=cookies["mallory" if 'mallory' in path else "alice"], content='{bad', headers={"content-type": "application/json"})
        assert response.status_code == 400
    response = client.post("/api/send", cookies=cookies["alice"], content=b'x' * 200001)
    assert response.status_code == 413
    assert client.get("/api/history", cookies=cookies["alice"]).headers["cache-control"] == "no-store"


def test_destructive_demo_requires_disposable_database(lab, monkeypatch):
    client, cookies, *_ = lab
    monkeypatch.setenv("CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO", "1")
    monkeypatch.delenv("CIPHERCHAT_DISPOSABLE_LAB", raising=False)
    assert post(client, cookies, "mallory", "/api/mallory/attack", {"attack":"delete_record", "record_number":1}).status_code == 403
    assert client.get("/api/dashboard", cookies=cookies["mallory"]).json()["destructive_demo"] is False


def test_central_health_is_local_only(monkeypatch):
    monkeypatch.setenv("CIPHERCHAT_CENTRAL_ONLY", "1")
    monkeypatch.setattr(server, "_database", lambda: MemoryDatabase())
    with TestClient(server.app, client=("127.0.0.1", 12345)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/").status_code == 404
        assert client.get("/api/me").status_code == 403
    with TestClient(server.app, client=("203.0.113.10", 12345)) as client:
        assert client.get("/health").status_code == 404
