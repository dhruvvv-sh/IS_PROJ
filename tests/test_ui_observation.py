import base64

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


def test_attack_observations_use_simulator_evidence_and_recovery():
    controller = DemonstrationController()
    result = controller.attack("replay")
    attack = result["attack"]
    assert attack["detected"] and attack["classification"] == "REPLAY"
    assert attack["evidence_generated"] and attack["checkpoint_valid"]
    assert attack["rekeyed"] and attack["old_session_invalidated"]
    assert result["attacks"] == [attack]
    assert result["attacks"][0]["timestamp"]
    names = [event["title"] for event in result["events"]]
    assert "ATTACKER INTERCEPTED" in names
    assert "INCIDENT EVIDENCE GENERATED" in names
    assert "RECOVERY STATE TRANSITIONS" in names


def test_key_substitution_observation_shows_blocked_session():
    result = DemonstrationController().attack("key_substitution")
    assert result["attack"]["classification"] == "KEY_SUBSTITUTION"
    assert result["attack"]["recovery_state"] == "BLOCKED"
    assert not result["attack"]["rekeyed"]


def test_attack_history_is_exported_and_reset_with_the_session():
    controller = DemonstrationController()
    first = controller.attack("replay")["attack"]
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
