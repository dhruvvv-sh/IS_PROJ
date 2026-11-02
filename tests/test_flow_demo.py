import io
import sys
import pytest
from cipherchat.security.flow_demo import FlowDemonstration, _sha256, _fingerprint, _canonical_json


def test_flow_demo_helpers():
    data = b"test payload"
    digest = _sha256(data)
    assert len(digest) == 64

    fp = _fingerprint(data)
    assert ":" in fp

    canon = _canonical_json({"b": 2, "a": 1})
    assert canon == '{"a":1,"b":2}'


def test_flow_demo_session_establishment_and_message(capsys):
    demo = FlowDemonstration()
    demo.show_session_establishment()
    captured = capsys.readouterr().out
    assert "SESSION ESTABLISHMENT: ALICE <-> BOB" in captured
    assert "Recovery state          : SECURE" in captured

    demo.send_message("Secret lab message")
    captured = capsys.readouterr().out
    assert "Delivery result         : ACCEPTED" in captured
    assert "Secret lab message" in captured


def test_flow_demo_replay_attack(capsys):
    demo = FlowDemonstration()
    demo.send_message("Original message")
    demo.replay_last_message()
    captured = capsys.readouterr().out
    assert "REPLAY ATTACK" in captured
    assert "Recovery state          : QUARANTINED" in captured


def test_flow_demo_tamper_attack(capsys):
    demo = FlowDemonstration()
    demo.send_message("Original message")
    demo.tamper_last_message("ciphertext")
    captured = capsys.readouterr().out
    assert "TAMPERING ATTACK" in captured
    assert "Recovery state          : QUARANTINED" in captured


def test_flow_demo_key_substitution(capsys):
    demo = FlowDemonstration()
    demo.attempt_key_substitution()
    captured = capsys.readouterr().out
    assert "KEY-SUBSTITUTION" in captured
    assert "Recovery state          : QUARANTINED" in captured


def test_flow_demo_recovery_and_view(capsys, monkeypatch):
    demo = FlowDemonstration()
    demo.send_message("First message")
    demo.replay_last_message()

    monkeypatch.setattr("builtins.input", lambda prompt: "1")
    demo.recover()
    captured = capsys.readouterr().out
    assert "Final state             : SECURE" in captured
    assert "A fresh X25519/HKDF session is active" in captured

    demo.view_status()
    captured = capsys.readouterr().out
    assert "Session ID" in captured

    demo.view_evidence()
    captured = capsys.readouterr().out
    assert "Evidence record" in captured

    demo.view_observations()
    captured = capsys.readouterr().out
    assert "SUCCESSFUL MESSAGE OBSERVATIONS" in captured
