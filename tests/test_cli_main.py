import pytest
from cipherchat.main import hash_payload, setup_sessions, handle_attack
from cipherchat.security.recovery import RecoveryMachine


def test_hash_payload():
    payload = {"key": "value", "number": 123}
    h = hash_payload(payload)
    assert len(h) == 64
    assert h == hash_payload(payload)


def test_setup_sessions():
    alice_s, bob_s, sid, alice, bob = setup_sessions()
    assert alice_s.sender is not None and bob_s.receiver is not None
    assert alice.identity_id == "alice"
    assert bob.identity_id == "bob"
    assert isinstance(sid, str) and len(sid) > 0


def test_handle_attack_normal(capsys):
    alice_s, bob_s, sid, _, _ = setup_sessions()
    handle_attack("Alice -> Bob", alice_s, bob_s, sid, "test message", "normal")
    captured = capsys.readouterr().out
    assert "Message authenticated and decrypted successfully" in captured


def test_handle_attack_replay(capsys):
    alice_s, bob_s, sid, _, _ = setup_sessions()
    handle_attack("Alice -> Bob", alice_s, bob_s, sid, "replay message", "replay")
    captured = capsys.readouterr().out
    assert "Replay detected" in captured
    assert "Classification: REPLAY" in captured


def test_handle_attack_tamper(capsys):
    alice_s, bob_s, sid, _, _ = setup_sessions()
    handle_attack("Alice -> Bob", alice_s, bob_s, sid, "tamper message", "tamper", "ciphertext")
    captured = capsys.readouterr().out
    assert "Tampering detected" in captured
    assert "Classification: TAMPERING" in captured


def test_handle_attack_key_substitution(capsys):
    alice_s, bob_s, sid, _, _ = setup_sessions()
    handle_attack("Alice -> Bob", alice_s, bob_s, sid, "substitution message", "key_substitution")
    captured = capsys.readouterr().out
    assert "Key substitution detected" in captured
    assert "Classification: KEY_SUBSTITUTION" in captured
