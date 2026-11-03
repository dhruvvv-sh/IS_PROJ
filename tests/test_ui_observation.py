import base64
import pytest

from cipherchat.ui.server import DemonstrationController


def test_normal_message_generates_actual_observation_events():
    controller = DemonstrationController()
    result = controller.send("Hello observation")
    names = [event["title"] for event in result["events"]]
    assert "MESSAGE CREATED" in names
    assert "CANONICAL AAD CONSTRUCTED" in names
    assert "AES-256-GCM ENCRYPTION" in names
    assert "AES-GCM AUTHENTICATION AND DECRYPTION" in names
    assert result["plaintext"] == "Hello observation"
    encryption = next(event for event in result["events"] if event["title"] == "AES-256-GCM ENCRYPTION")
    assert encryption["data"]["nonce"] == base64.b64decode(result["message"]["nonce"]).hex()


def test_attack_quarantines_live_chat_until_verification_and_rekey():
    controller = DemonstrationController()
    original_session_id = controller.session_id
    original_sender = controller.alice_sessions.sender
    original_key = original_sender.key
    result = controller.attack("replay")
    attack = result["attack"]
    assert attack["detected"] and attack["classification"] == "REPLAY"
    assert attack["evidence_generated"] and attack["checkpoint_valid"]
    assert attack["recovery_state"] == "QUARANTINED"
    assert not attack["rekeyed"] and attack["old_session_invalidated"]
    assert result["recovery"]["state"] == "QUARANTINED"
    with pytest.raises(ValueError, match="quarantined"):
        controller.send("cannot send")
    with pytest.raises(ValueError, match="quarantined"):
        controller.attack("tamper_nonce")
    assert result["attacks"] == [attack]
    assert result["attacks"][0]["timestamp"]
    names = [event["title"] for event in result["events"]]
    assert "ATTACKER INTERCEPTED" in names
    assert "INCIDENT EVIDENCE GENERATED" in names
    assert "RECOVERY STATE TRANSITIONS" in names

    recovered = controller.recover()
    assert recovered["recovery"]["state"] == "SECURE"
    assert recovered["recovery"]["history"] == [
        "SECURE", "SUSPECTED_ATTACK", "QUARANTINED", "VERIFYING", "REKEYING", "SECURE"
    ]
    assert recovered["session"]["session_id"] != original_session_id
    assert controller.alice_sessions.sender.key != original_key
    assert recovered["rekey"]["fresh_x25519"] is True
    assert original_sender._active is False
    assert recovered["attacks"][0]["rekeyed"] is True
    assert controller.send("works after rekey")["plaintext"] == "works after rekey"


def test_key_substitution_observation_shows_blocked_session():
    controller = DemonstrationController()
    result = controller.attack("key_substitution")
    assert result["attack"]["classification"] == "KEY_SUBSTITUTION"
    assert result["attack"]["recovery_state"] == "BLOCKED"
    assert not result["attack"]["rekeyed"]
    assert result["recovery"]["state"] == "BLOCKED"
    with pytest.raises(ValueError, match="blocked"):
        controller.send("cannot send")
    with pytest.raises(ValueError, match="quarantined"):
        controller.recover()
    assert controller.establish()["recovery"]["state"] == "SECURE"
    assert controller.send("new session works")["plaintext"] == "new session works"


def test_attack_history_is_exported_and_reset_with_the_session():
    controller = DemonstrationController()
    first = controller.attack("replay")["attack"]
    controller.recover()
    second = controller.attack("tamper_nonce")["attack"]

    exported = controller.export_logs()
    assert exported["attacks"] == [first, second]
    assert [item["attack_type"] for item in exported["attacks"]] == ["REPLAY", "TAMPERING"]

    reset = controller.establish()
    assert reset["attacks"] == []
    assert controller.export_logs()["attacks"] == []


def test_ui_snapshot_exposes_delivery_hashes_and_verified_evidence_chain():
    controller = DemonstrationController()
    delivered = controller.send("four-screen verification")
    delivery = delivered["deliveries"][0]
    assert delivery["plaintext"] == "four-screen verification"
    assert len(delivery["aad_sha256"]) == 64
    assert len(delivery["envelope_sha256"]) == 64
    assert delivery["signature_verified"] is True
    assert len(base64.b64decode(delivery["signature"])) == 64
    assert any(event["title"] == "ED25519 SIGNATURE VERIFIED" for event in delivered["events"])

    attacked = controller.attack("tamper_ciphertext")
    assert attacked["evidence"]["chain_valid"] is True
    assert attacked["evidence"]["checkpoint"]["record_count"] == 1
    assert attacked["evidence"]["records"][0]["attack_type"] == "TAMPERING"
    assert attacked["attack"]["evidence_hash"] == attacked["evidence"]["checkpoint"]["evidence_hash"]


def test_ui_evidence_deletion_demo_detects_missing_record_and_preserves_live_chain():
    controller = DemonstrationController()
    with pytest.raises(ValueError, match="Run a message attack first"):
        controller.attack("delete_evidence")

    first = controller.attack("replay")
    original = first["evidence"]["records"][0]
    result = controller.attack("delete_evidence")
    deletion = result["attack"]

    assert deletion["attack_type"] == "EVIDENCE_DELETION"
    assert deletion["detected"] is True
    assert deletion["altered_copy_valid"] is False
    assert deletion["original_record_count"] == 1
    assert deletion["altered_copy_count"] == 0
    assert deletion["removed_incident_id"] == original["incident_id"]
    assert deletion["recovery_state"] == "BLOCKED"
    assert deletion["old_session_invalidated"] is True
    assert result["recovery"]["state"] == "BLOCKED"
    assert result["evidence"]["records"][0] == original
    assert result["evidence"]["checkpoint"]["record_count"] == 2
    assert result["evidence"]["chain_valid"] is True
    assert controller.export_logs()["attacks"][-1] == deletion
    with pytest.raises(ValueError, match="blocked"):
        controller.send("cannot send after deletion")
    with pytest.raises(ValueError, match="quarantined"):
        controller.recover()
    assert controller.establish()["recovery"]["state"] == "SECURE"


def test_evidence_deletion_blocks_a_recovered_chat_too():
    controller = DemonstrationController()
    controller.attack("replay")
    controller.recover()
    result = controller.attack("delete_evidence")
    assert result["recovery"]["state"] == "BLOCKED"
    assert result["attack"]["recovery_history"][-4:] == [
        "SUSPECTED_ATTACK", "QUARANTINED", "VERIFYING", "BLOCKED"
    ]
    with pytest.raises(ValueError, match="blocked"):
        controller.send("still blocked")


def test_alice_and_bob_can_both_send_simple_messages():
    controller = DemonstrationController()
    controller.send("Hello Bob", "alice")
    result = controller.send("Hello Alice", "bob")

    assert [(item["sender"], item["recipient"], item["plaintext"]) for item in result["deliveries"]] == [
        ("alice", "bob", "Hello Bob"),
        ("bob", "alice", "Hello Alice"),
    ]
    assert result["deliveries"][0]["sequence_number"] == 1
    assert result["deliveries"][1]["sequence_number"] == 1
    assert any(event["title"] == "ALICE RECEIVED MESSAGE" for event in result["events"])
