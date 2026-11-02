"""Run with: python -m cipherchat.main"""
import hashlib
import json
from dataclasses import replace
from uuid import uuid4

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.messages import ValidationError
from cipherchat.protocol.session import SessionManager
from cipherchat.security.attacks import classify_failure
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.recovery import RecoveryMachine


def hash_payload(message_dict: dict[str, object]) -> str:
    encoded = json.dumps(message_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def print_encrypted_message(label: str, message) -> None:
    payload = message.to_dict()
    print(f"\n{label}:")
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    print(f"SHA-256: {hash_payload(payload)}")


def setup_sessions() -> tuple[SessionManager, SessionManager, str, Identity, Identity]:
    alice, bob = Identity.create("alice"), Identity.create("bob")
    context, session_id = b"demo-session", str(uuid4())
    alice_sessions = SessionManager(alice, bob.identity_id, public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
    bob_sessions = SessionManager(bob, alice.identity_id, public_key_bytes(alice.public_key), alice.signing_public_key_bytes)
    alice_sessions.establish(public_key_bytes(bob.public_key), bob.signing_public_key_bytes, session_id=session_id, context=context)
    bob_sessions.establish(public_key_bytes(alice.public_key), alice.signing_public_key_bytes, session_id=session_id, context=context)
    return alice_sessions, bob_sessions, session_id, alice, bob


def print_recovery_summary(recovery: RecoveryMachine) -> None:
    print("\nRecovery history:")
    print("    " + "\n      ↓\n    ".join(item.value for item in recovery.history))


def handle_attack(label: str, alice_sessions: SessionManager, bob_sessions: SessionManager, session_id: str, plaintext: str, attack_choice: str, tamper_field: str | None = None) -> None:
    sender, receiver = alice_sessions.sender, bob_sessions.receiver
    assert sender is not None and receiver is not None
    evidence = EvidenceLog()
    recovery = RecoveryMachine()

    if attack_choice == "normal":
        message = sender.encrypt(plaintext)
        print_encrypted_message("Alice → Bob (encrypted payload)", message)
        print(f"Decrypted plaintext: {receiver.decrypt(message)}")
        print("\n[+] Message authenticated and decrypted successfully")
        return

    if attack_choice == "replay":
        message = sender.encrypt(plaintext)
        print_encrypted_message("Alice → Bob (encrypted payload)", message)
        print(f"First decrypt: {receiver.decrypt(message)}")
        try:
            receiver.decrypt(message)
        except Exception as error:
            attack = classify_failure(error)
            record = evidence.record(
                session_id=session_id,
                attack_type=attack,
                description=f"Replay test: {error}",
                message_id=message.message_id,
                sequence_number=message.sequence_number,
            )
            print(f"\n[!] Replay detected")
            print(f"Classification: {attack.value}")
            print(f"Evidence hash: {record.evidence_hash}")
            print(f"Previous evidence hash: {record.previous_evidence_hash}")
            recovery.report_violation(); recovery.begin_verification(); recovery.verification_succeeded()
            rekey_session_id, rekey_context = str(uuid4()), b"rekey-replay-" + uuid4().bytes
            alice_sessions.rekey(public_key_bytes(bob_sessions.identity.public_key), bob_sessions.identity.signing_public_key_bytes, session_id=rekey_session_id, context=rekey_context)
            bob_sessions.rekey(public_key_bytes(alice_sessions.identity.public_key), alice_sessions.identity.signing_public_key_bytes, session_id=rekey_session_id, context=rekey_context)
            recovery.rekey_complete()
            print_recovery_summary(recovery)
        return

    if attack_choice == "tamper":
        if tamper_field is None:
            tamper_field = "ciphertext"
        message = sender.encrypt(plaintext)
        print_encrypted_message("Alice → Bob (encrypted payload)", message)
        changes = {
            "ciphertext": bytes([message.ciphertext[0] ^ 1]) + message.ciphertext[1:],
            "nonce": bytes([message.nonce[0] ^ 1]) + message.nonce[1:],
            "sequence_number": message.sequence_number + 1,
            "message_id": "tampered-message-id",
            "session_id": "tampered-session-id",
            "sender_id": "mallory",
        }
        tampered = replace(message, **{tamper_field: changes[tamper_field]})
        print(f"\nTampering with field: {tamper_field}")
        print(json.dumps(tampered.to_dict(), sort_keys=True, separators=(",", ":")))
        try:
            receiver.decrypt(tampered)
        except Exception as error:
            attack = classify_failure(error)
            record = evidence.record(
                session_id=session_id,
                attack_type=attack,
                description=f"Tampering test on {tamper_field}: {error}",
                message_id=tampered.message_id,
                sequence_number=tampered.sequence_number,
            )
            print(f"\n[!] Tampering detected")
            print(f"Classification: {attack.value}")
            print(f"Evidence hash: {record.evidence_hash}")
            print(f"Previous evidence hash: {record.previous_evidence_hash}")
            recovery.report_violation(); recovery.begin_verification(); recovery.verification_succeeded()
            rekey_session_id, rekey_context = str(uuid4()), b"rekey-tamper-" + uuid4().bytes
            alice_sessions.rekey(public_key_bytes(bob_sessions.identity.public_key), bob_sessions.identity.signing_public_key_bytes, session_id=rekey_session_id, context=rekey_context)
            bob_sessions.rekey(public_key_bytes(alice_sessions.identity.public_key), alice_sessions.identity.signing_public_key_bytes, session_id=rekey_session_id, context=rekey_context)
            recovery.rekey_complete()
            print_recovery_summary(recovery)
        return

    if attack_choice == "key_substitution":
        print("Attempting to establish a session with Mallory's public key...")
        mallory = Identity.create("mallory")
        try:
            alice_sessions.establish(public_key_bytes(mallory.public_key), mallory.signing_public_key_bytes, session_id="substituted", context=b"substituted")
        except Exception as error:
            attack = classify_failure(error)
            record = evidence.record(
                session_id=session_id,
                attack_type=attack,
                description=f"Key substitution attack: {error}",
                message_id=None,
                sequence_number=None,
            )
            print(f"\n[!] Key substitution detected")
            print(f"Classification: {attack.value}")
            print(f"Evidence hash: {record.evidence_hash}")
            print(f"Previous evidence hash: {record.previous_evidence_hash}")
        return

    raise ValueError(f"Unsupported attack choice: {attack_choice}")


def main() -> None:
    print("=== CipherChat Interactive Security Demo ===\n")

    while True:
        print("Choose the attack scenario:")
        print("  1. Normal message")
        print("  2. Replay attack")
        print("  3. Tampering attack")
        print("  4. Key substitution attack")
        print("  5. Exit")
        choice = input("Select an option: ").strip()

        if choice == "5":
            print("Goodbye.")
            break

        attack_map = {"1": "normal", "2": "replay", "3": "tamper", "4": "key_substitution"}
        if choice not in attack_map:
            print("Invalid option. Please choose 1, 2, 3, 4, or 5.")
            continue

        plaintext = input("Enter the plaintext Alice should send to Bob: ").strip() or "Hello Bob"
        if attack_map[choice] == "tamper":
            tamper_field = input("Choose tamper field (ciphertext, nonce, sequence_number, message_id, session_id, sender_id): ").strip() or "ciphertext"
            tamper_field = tamper_field.lower()
            if tamper_field not in {"ciphertext", "nonce", "sequence_number", "message_id", "session_id", "sender_id"}:
                print("Invalid field. Defaulting to ciphertext.")
                tamper_field = "ciphertext"
        else:
            tamper_field = None

        alice_sessions, bob_sessions, session_id, alice, bob = setup_sessions()
        print(f"\n[+] Alice identity created: {alice.identity_id}")
        print(f"[+] Bob identity created: {bob.identity_id}")
        print("[+] ECDH session established")
        print("[+] Session key derived")

        handle_attack(
            label="Alice → Bob",
            alice_sessions=alice_sessions,
            bob_sessions=bob_sessions,
            session_id=session_id,
            plaintext=plaintext,
            attack_choice=attack_map[choice],
            tamper_field=tamper_field,
        )

        checkpoint = EvidenceLog().checkpoint() if False else None
        again = input("\nRun another scenario? (y/n): ").strip().lower()
        if again not in {"y", "yes"}:
            print("Goodbye.")
            break


if __name__ == "__main__":
    main()
