import threading
import time
import json
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
import pytest

from cipherchat.crypto.identity import Identity
from cipherchat.multiterminal.keys import create_files, load_identity, load_peer
from cipherchat.multiterminal.participant import ParticipantController
from cipherchat.multiterminal.relay import EvaController, RelayHandler, RelayState
from cipherchat.multiterminal.ui import LabUIHandler
from cipherchat.multiterminal.wire import control_bytes, join_bytes


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("network state did not arrive before timeout")


def test_three_role_delivery_attack_rekey_and_block():
    relay = RelayState()
    handler = type("TestRelayHandler", (RelayHandler,), {"state": relay})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    alice_identity, bob_identity = Identity.create("alice"), Identity.create("bob")
    alice = bob = None
    try:
        alice = ParticipantController("alice", alice_identity, bob_identity.public_material(), url)
        bob = ParticipantController("bob", bob_identity, alice_identity.public_material(), url)
        wait_for(lambda: alice.snapshot()["session"]["session_id"] == bob.snapshot()["session"]["session_id"]
                 and alice.snapshot()["session"]["session_id"] is not None)
        first_session = alice.snapshot()["session"]["session_id"]

        alice.send("hello from Alice", "alice")
        wait_for(lambda: bob.snapshot()["deliveries"] and bob.snapshot()["deliveries"][0]["plaintext"] == "hello from Alice")
        relay.attack("replay")
        wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "QUARANTINED")
        assert bob.snapshot()["evidence"]["records"][0]["attack_type"] == "REPLAY"

        alice.recover()
        wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "SECURE"
                 and alice.snapshot()["session"]["session_id"] != first_session)
        assert alice.session.sender.key == bob.session.receiver.key
        bob.send("hello from Bob", "bob")
        wait_for(lambda: any(item["plaintext"] == "hello from Bob" for item in alice.snapshot()["deliveries"]))

        relay.attack("key_substitution")
        wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "BLOCKED")
        blocked_session = alice.snapshot()["session"]["session_id"]
        relay.reset()
        wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "SECURE"
                 and alice.snapshot()["session"]["session_id"] != blocked_session)
        alice.send("new session after block", "alice")
        wait_for(lambda: any(item["plaintext"] == "new session after block" for item in bob.snapshot()["deliveries"]))
    finally:
        if alice:
            alice.close()
        if bob:
            bob.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_evidence_deletion_blocks_both_participants():
    relay = RelayState()
    handler = type("TestRelayHandler", (RelayHandler,), {"state": relay})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    alice_identity, bob_identity = Identity.create("alice"), Identity.create("bob")
    alice = bob = None
    try:
        alice = ParticipantController("alice", alice_identity, bob_identity.public_material(), url)
        bob = ParticipantController("bob", bob_identity, alice_identity.public_material(), url)
        wait_for(lambda: alice.session is not None and bob.session is not None)
        alice.send("message to attack", "alice")
        wait_for(lambda: bob.snapshot()["deliveries"])
        relay.attack("tamper_nonce")
        wait_for(lambda: bob.snapshot()["recovery"]["state"] == "QUARANTINED")
        relay.attack("delete_evidence")
        wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "BLOCKED")
        assert bob.snapshot()["evidence"]["chain_valid"] is True
    finally:
        if alice:
            alice.close()
        if bob:
            bob.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_role_local_ui_api_and_persistent_identity_files(tmp_path):
    alice_private, alice_public = create_files("alice", tmp_path / "alice")
    bob_private, bob_public = create_files("bob", tmp_path / "bob")
    alice_identity = load_identity(alice_private, "alice")
    bob_identity = load_identity(bob_private, "bob")
    assert alice_identity.public_material() == load_peer(alice_public, "alice")
    assert bob_identity.public_material() == load_peer(bob_public, "bob")

    relay = RelayState()
    relay_handler = type("TestRelayHandler", (RelayHandler,), {"state": relay})
    relay_server = ThreadingHTTPServer(("127.0.0.1", 0), relay_handler)
    relay_thread = threading.Thread(target=relay_server.serve_forever, daemon=True)
    relay_thread.start()
    relay_url = f"http://127.0.0.1:{relay_server.server_port}"
    alice = bob = None
    ui_servers = []
    ui_threads = []
    try:
        alice = ParticipantController("alice", alice_identity, load_peer(bob_public, "bob"), relay_url)
        bob = ParticipantController("bob", bob_identity, load_peer(alice_public, "alice"), relay_url)
        for role, controller in (("alice", alice), ("bob", bob), ("eva", EvaController(relay))):
            handler = type(f"{role.title()}UIHandler", (LabUIHandler,), {
                "controller": controller, "audit_logs": [],
                "live_log_path": tmp_path / f"{role}-audit.json", "last_persisted_revision": -1,
            })
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            ui_servers.append(server)
            ui_threads.append(thread)
        urls = [f"http://127.0.0.1:{server.server_port}" for server in ui_servers]
        wait_for(lambda: alice.session is not None and bob.session is not None)
        for role, url in zip(("alice", "bob", "eva"), urls):
            with urlopen(url + "/api/state") as response:
                assert json.load(response)["role"] == role
            with urlopen(url) as response:
                assert b'data-screen="attacker"' in response.read()

        def post(url, path, payload):
            request = Request(url + path, data=json.dumps(payload).encode(), method="POST",
                              headers={"Content-Type": "application/json"})
            with urlopen(request) as response:
                return json.load(response)

        post(urls[0], "/api/send", {"sender": "alice", "message": "browser to browser"})
        wait_for(lambda: bob.snapshot()["deliveries"] and bob.snapshot()["deliveries"][0]["plaintext"] == "browser to browser")
        post(urls[2], "/api/attack", {"attack": "replay"})
        wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "QUARANTINED")
        post(urls[1], "/api/recover", {})
        wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "SECURE")
        assert json.load(urlopen(urls[2] + "/api/state"))["attacks"][0]["rekeyed"] is True
    finally:
        for server, thread in zip(ui_servers, ui_threads):
            server.shutdown()
            server.server_close()
            thread.join()
        if alice:
            alice.close()
        if bob:
            bob.close()
        relay_server.shutdown()
        relay_server.server_close()
        relay_thread.join()


def test_every_tamper_control_rejects_a_real_envelope():
    relay = RelayState()
    handler = type("TestRelayHandler", (RelayHandler,), {"state": relay})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    alice_identity, bob_identity = Identity.create("alice"), Identity.create("bob")
    alice = bob = None
    fields = ("ciphertext", "nonce", "sequence_number", "message_id", "session_id", "sender_id")
    try:
        alice = ParticipantController("alice", alice_identity, bob_identity.public_material(), url)
        bob = ParticipantController("bob", bob_identity, alice_identity.public_material(), url)
        wait_for(lambda: alice.session is not None and bob.session is not None)
        for field in fields:
            alice.send(f"test {field}", "alice")
            wait_for(lambda: bob.snapshot()["deliveries"] and bob.snapshot()["deliveries"][-1]["plaintext"] == f"test {field}")
            relay.attack(f"tamper_{field}")
            wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "QUARANTINED")
            assert bob.snapshot()["attacks"][-1]["classification"] == "TAMPERING"
            bob.recover()
            wait_for(lambda: alice.snapshot()["recovery"]["state"] == bob.snapshot()["recovery"]["state"] == "SECURE")
    finally:
        if alice:
            alice.close()
        if bob:
            bob.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_relay_rejects_forged_incident_before_notifying_peer():
    relay = RelayState()
    alice_identity, bob_identity = Identity.create("alice"), Identity.create("bob")
    for identity in (alice_identity, bob_identity):
        public = identity.public_material()
        challenge = relay.challenge(identity.identity_id)["challenge"]
        signature = identity.signing_private_key.sign(join_bytes(identity.identity_id, public, challenge)).hex()
        result = relay.join(identity.identity_id, public, challenge, signature)
        if identity.identity_id == "bob":
            bob_token = result["token"]
    incident = {"reporter": "bob", "classification": "REPLAY", "recovery_state": "QUARANTINED",
                "session_id": relay.session_id, "message_id": None,
                "evidence_hash": "0" * 64, "attack_id": None, "detail": "forged"}
    forged = {"incident": incident,
              "signature": alice_identity.signing_private_key.sign(control_bytes(incident)).hex()}
    with pytest.raises(ValueError, match="signature"):
        relay.incident("bob", bob_token, forged)
    assert relay.status == {"alice": "SECURE", "bob": "SECURE"}
    assert not relay.evidence.records


def test_join_requires_identity_private_key():
    relay = RelayState()
    alice_identity = Identity.create("alice")
    impostor = Identity.create("mallory")
    public = alice_identity.public_material()
    challenge = relay.challenge("alice")["challenge"]
    forged = impostor.signing_private_key.sign(join_bytes("alice", public, challenge)).hex()
    with pytest.raises(ValueError, match="join signature"):
        relay.join("alice", public, challenge, forged)
    assert "alice" not in relay.peers
