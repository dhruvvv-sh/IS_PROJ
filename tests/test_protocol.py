from dataclasses import replace
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cipherchat.crypto.encryption import encrypt
from cipherchat.protocol.messages import DigitalSignatureError, EncryptedMessage, PROTOCOL_VERSION, ReceiverSession, ReplayError, SenderSession, SessionInactiveError


def sessions(key: bytes = b"a" * 32):
    signing_key = Ed25519PrivateKey.generate()
    return (
        SenderSession(key, "session", "alice", signing_key),
        ReceiverSession(key, "session", "alice", signing_key.public_key()),
    )

def test_message_roundtrip_replay_and_tampered_metadata():
    send, receive = sessions()
    message = send.encrypt("hello")
    assert receive.decrypt(message) == "hello"
    with pytest.raises(ReplayError): receive.decrypt(message)
    altered = replace(send.encrypt("later"), sequence_number=77)
    with pytest.raises(DigitalSignatureError): receive.decrypt(altered)

def test_json_is_deterministic_and_validated():
    message = sessions()[0].encrypt("hello")
    assert message.from_json(message.to_json()) == message

def test_duplicate_message_id_is_rejected_independently_of_sequence():
    key = b"a" * 32
    sender, receiver = sessions(key)
    first = sender.encrypt("first")
    assert receiver.decrypt(first) == "first"
    # This is a fully authenticated, forward-sequence message with a reused ID.
    draft = EncryptedMessage(PROTOCOL_VERSION, "session", "alice", first.message_id, 2, b"", b"", b"")
    payload = encrypt(key, b"duplicate id", draft.aad())
    unsigned = EncryptedMessage(PROTOCOL_VERSION, "session", "alice", first.message_id, 2, payload.nonce, payload.data, b"")
    duplicate = replace(unsigned, signature=sender.signing_key.sign(unsigned.signing_bytes()))
    with pytest.raises(ReplayError, match="identifier"):
        receiver.decrypt(duplicate)

def test_invalidated_sessions_fail_closed():
    sender, receiver = sessions()
    message = sender.encrypt("hello")
    sender.invalidate(); receiver.invalidate()
    with pytest.raises(SessionInactiveError): sender.encrypt("after rekey")
    with pytest.raises(SessionInactiveError): receiver.decrypt(message)


def test_signature_covers_ciphertext_and_all_protocol_metadata():
    sender, receiver = sessions()
    message = sender.encrypt("signed message")
    for tampered in (
        replace(message, ciphertext=bytes([message.ciphertext[0] ^ 1]) + message.ciphertext[1:]),
        replace(message, nonce=bytes([message.nonce[0] ^ 1]) + message.nonce[1:]),
        replace(message, sender_id="mallory"),
        replace(message, session_id="other"),
        replace(message, message_id="other"),
        replace(message, sequence_number=99),
        replace(message, signature=b"x" * 64),
    ):
        with pytest.raises(DigitalSignatureError):
            receiver.decrypt(tampered)


def test_shared_encryption_key_cannot_forge_another_signing_identity():
    sender, receiver = sessions()
    attacker_signing_key = Ed25519PrivateKey.generate()
    forged = SenderSession(sender.key, "session", "alice", attacker_signing_key).encrypt("forged")
    with pytest.raises(DigitalSignatureError):
        receiver.decrypt(forged)
