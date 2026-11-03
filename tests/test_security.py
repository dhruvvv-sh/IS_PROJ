from dataclasses import replace
import pytest
from cipherchat.security.attacks import AttackType, KeySubstitutionError, verify_expected_public_key
from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.messages import DigitalSignatureError, SessionInactiveError, ValidationError
from cipherchat.protocol.session import SessionManager, rekey_pair
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.recovery import InvalidTransition, RecoveryMachine, RecoveryState

def test_evidence_chain_detects_change_and_reordering():
    log = EvidenceLog()
    one = log.record(session_id="s", attack_type=AttackType.REPLAY, description="replayed", timestamp="2026-01-01T00:00:00+00:00")
    two = log.record(session_id="s", attack_type=AttackType.TAMPERING, description="tag failed", timestamp="2026-01-01T00:00:01+00:00")
    checkpoint = log.checkpoint()
    assert verify_evidence_chain(log.records, checkpoint)
    assert not verify_evidence_chain([replace(one, description="changed"), two], checkpoint)
    assert not verify_evidence_chain([two, one], checkpoint)
    assert not verify_evidence_chain([one], checkpoint)  # trusted tip catches tail deletion

def test_bounded_recovery_valid_and_invalid_paths():
    machine = RecoveryMachine()
    with pytest.raises(InvalidTransition): machine.transition(RecoveryState.REKEYING)
    machine.report_violation(); machine.begin_verification(); machine.verification_succeeded(); machine.rekey_complete()
    assert machine.state is RecoveryState.SECURE
    machine.report_violation(); machine.begin_verification(); machine.verification_failed()
    assert machine.state is RecoveryState.BLOCKED
    with pytest.raises(InvalidTransition): machine.transition(RecoveryState.SECURE)

def test_key_substitution_is_detected_against_a_pinned_public_key():
    verify_expected_public_key(b"expected", b"expected")
    with pytest.raises(KeySubstitutionError):
        verify_expected_public_key(b"expected", b"unexpected")

def test_session_establishment_verifies_pin_and_rekey_invalidates_old_sessions():
    alice, bob, attacker = Identity.create("alice"), Identity.create("bob"), Identity.create("mallory")
    alice_manager = SessionManager(alice, "bob", public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
    bob_manager = SessionManager(bob, "alice", public_key_bytes(alice.public_key), alice.signing_public_key_bytes)
    with pytest.raises(KeySubstitutionError):
        alice_manager.establish(public_key_bytes(attacker.public_key), attacker.signing_public_key_bytes, session_id="one", context=b"one")
    with pytest.raises(KeySubstitutionError):
        alice_manager.establish(public_key_bytes(bob.public_key), attacker.signing_public_key_bytes, session_id="one", context=b"one")
    alice_manager.establish(public_key_bytes(bob.public_key), bob.signing_public_key_bytes, session_id="one", context=b"one")
    bob_manager.establish(public_key_bytes(alice.public_key), alice.signing_public_key_bytes, session_id="one", context=b"one")
    old_sender, old_receiver = alice_manager.sender, bob_manager.receiver
    old_key = old_sender.key
    old_alice_exchange = alice_manager.info.local_exchange_public_key
    old_bob_exchange = bob_manager.info.local_exchange_public_key
    assert old_sender is not None and old_receiver is not None
    old_message = old_sender.encrypt("before rekey")
    assert old_receiver.decrypt(old_message) == "before rekey"
    alice_offer = alice_manager.begin_rekey(session_id="two", context=b"two")
    bob_offer = bob_manager.begin_rekey(session_id="two", context=b"two")
    assert alice_offer.exchange_public_key != old_alice_exchange
    assert bob_offer.exchange_public_key != old_bob_exchange
    with pytest.raises(ValidationError):
        alice_manager.finish_rekey(replace(bob_offer, context=b"wrong"))
    with pytest.raises(DigitalSignatureError):
        alice_manager.finish_rekey(replace(bob_offer, exchange_public_key=public_key_bytes(attacker.public_key)))
    reused_key_offer = replace(bob_offer, exchange_public_key=old_bob_exchange, signature=b"")
    reused_key_offer = replace(reused_key_offer, signature=bob.signing_private_key.sign(reused_key_offer.signing_bytes()))
    with pytest.raises(ValidationError, match="reused"):
        alice_manager.finish_rekey(reused_key_offer)
    assert old_sender._active is True
    alice_manager.finish_rekey(bob_offer)
    bob_manager.finish_rekey(alice_offer)
    with pytest.raises(SessionInactiveError): old_sender.encrypt("must fail")
    with pytest.raises(SessionInactiveError): old_receiver.decrypt(old_message)
    assert alice_manager.sender is not None and bob_manager.receiver is not None
    assert alice_manager.sender.key == bob_manager.receiver.key
    assert alice_manager.sender.key != old_key
    assert alice_manager.info.local_exchange_public_key == alice_offer.exchange_public_key
    assert bob_manager.info.local_exchange_public_key == bob_offer.exchange_public_key
    with pytest.raises(ValidationError, match="new valid session ID"):
        alice_manager.begin_rekey(session_id="one", context=b"old")
    with pytest.raises(ValidationError):
        bob_manager.receiver.decrypt(old_message)
    new_message = alice_manager.sender.encrypt("after rekey")
    assert bob_manager.receiver.decrypt(new_message) == "after rekey"
    second_round_key = alice_manager.sender.key
    second_round_public = alice_manager.info.local_exchange_public_key
    rekey_pair(alice_manager, bob_manager, session_id="three", context=b"three")
    assert alice_manager.info.local_exchange_public_key != second_round_public
    assert alice_manager.sender.key != second_round_key
    assert alice_manager.sender.key == bob_manager.receiver.key
