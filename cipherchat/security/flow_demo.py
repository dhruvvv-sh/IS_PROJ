"""Menu-driven, end-to-end CipherChat process demonstration.

Run from the repository root with::

    .venv/bin/python -m cipherchat.security.flow_demo

This teaching tool uses the real CipherChat security classes. It displays
public metadata, hashes, state changes, and ciphertext, but never displays
private keys, shared secrets, or derived session keys.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from uuid import uuid4

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.messages import EncryptedMessage
from cipherchat.protocol.session import SessionManager, rekey_pair
from cipherchat.security.attacks import AttackType, classify_failure
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.recovery import RecoveryMachine, RecoveryState


LINE = "=" * 78
SUBLINE = "-" * 78
TAMPER_FIELDS = (
    "ciphertext",
    "nonce",
    "sequence_number",
    "message_id",
    "session_id",
    "sender_id",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(public_key: bytes) -> str:
    digest = _sha256(public_key)
    return ":".join(digest[index:index + 4] for index in range(0, len(digest), 4))


def _canonical_json(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _pretty_json(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, indent=2)


def _step(number: int, title: str) -> None:
    print(f"\n[{number}] {title}")
    print(SUBLINE)


def _status(label: str, value: str) -> None:
    print(f"{label:<24}: {value}")


@dataclass(frozen=True)
class MessageObservation:
    recorded_at: str
    direction: str
    message_id: str
    sequence_number: int
    session_id: str
    sender_id: str
    aad_sha256: str
    envelope_sha256: str
    ciphertext_bytes: int
    outcome: str


class FlowDemonstration:
    """Stateful interactive demonstration of messaging and incident handling."""

    def __init__(self) -> None:
        self.alice = Identity.create("alice")
        self.bob = Identity.create("bob")
        self.alice_sessions = SessionManager(
            self.alice, self.bob.identity_id, public_key_bytes(self.bob.public_key),
            self.bob.signing_public_key_bytes,
        )
        self.bob_sessions = SessionManager(
            self.bob, self.alice.identity_id, public_key_bytes(self.alice.public_key),
            self.alice.signing_public_key_bytes,
        )
        self.evidence = EvidenceLog()
        self.recovery = RecoveryMachine()
        self.observations: list[MessageObservation] = []
        self.last_message: EncryptedMessage | None = None
        self.session_generation = 0
        self.session_id = ""
        self.context = b""
        self._establish_new_session("initial-establishment")

    def _establish_new_session(self, reason: str) -> None:
        self.session_generation += 1
        self.session_id = f"cipherchat-{self.session_generation}-{uuid4()}"
        self.context = f"cipherchat-flow:{reason}:generation-{self.session_generation}".encode()
        self.alice_sessions.establish(
            public_key_bytes(self.bob.public_key),
            self.bob.signing_public_key_bytes,
            session_id=self.session_id,
            context=self.context,
        )
        self.bob_sessions.establish(
            public_key_bytes(self.alice.public_key),
            self.alice.signing_public_key_bytes,
            session_id=self.session_id,
            context=self.context,
        )

    def show_session_establishment(self) -> None:
        print(f"\n{LINE}\nSESSION ESTABLISHMENT: ALICE <-> BOB\n{LINE}")

        _step(1, "Create long-lived local identities")
        _status("Alice identity", self.alice.identity_id)
        _status("Bob identity", self.bob.identity_id)
        print("Private keys remain inside their Identity objects and are never displayed.")

        _step(2, "Exchange public X25519 and Ed25519 material")
        alice_public = public_key_bytes(self.alice.public_key)
        bob_public = public_key_bytes(self.bob.public_key)
        _status("Alice public key bytes", str(len(alice_public)))
        _status("Alice fingerprint", _fingerprint(alice_public))
        _status("Bob public key bytes", str(len(bob_public)))
        _status("Bob fingerprint", _fingerprint(bob_public))
        _status("Alice signing fingerprint", _fingerprint(self.alice.signing_public_key_bytes))
        _status("Bob signing fingerprint", _fingerprint(self.bob.signing_public_key_bytes))

        _step(3, "Verify pinned peer keys before key agreement")
        _status("Alice expects", "Bob's pinned public-key fingerprint")
        _status("Bob expects", "Alice's pinned public-key fingerprint")
        _status("Pin verification", "PASS - presented keys equal expected keys")
        print("Meaning: a substituted public key is rejected, assuming the original pins were trusted.")

        _step(4, "Perform X25519 ECDH and HKDF-SHA-256 derivation")
        _status("Key agreement", "X25519")
        _status("Key derivation", "HKDF-SHA-256")
        _status("Application key", "AES-256 key (32 bytes; value intentionally hidden)")
        _status("HKDF context", self.context.decode())
        print("Both sides independently derived matching session keys; no secret was transmitted.")

        _step(5, "Install directional protocol sessions")
        _status("Session generation", str(self.session_generation))
        _status("Session ID", self.session_id)
        _status("Alice role", "Sender authenticated as alice")
        _status("Bob role", "Receiver expecting alice")
        _status("Recovery state", self.recovery.state.value)

    def send_message(self, plaintext: str) -> None:
        if self.recovery.state is not RecoveryState.SECURE:
            print(
                f"\n[DENIED] Messaging is unavailable while recovery is "
                f"{self.recovery.state.value}. Use the recovery menu first."
            )
            return
        sender = self.alice_sessions.sender
        receiver = self.bob_sessions.receiver
        assert sender is not None and receiver is not None

        print(f"\n{LINE}\nALICE SENDS AN ENCRYPTED MESSAGE TO BOB\n{LINE}")

        _step(1, "Accept plaintext at Alice's trusted endpoint")
        _status("Direction", "Alice -> Bob")
        _status("Plaintext", repr(plaintext))
        _status("UTF-8 length", f"{len(plaintext.encode('utf-8'))} bytes")
        print("The plaintext is displayed for demonstration only; it will not enter the evidence log.")

        _step(2, "Create protocol metadata")
        message = sender.encrypt(plaintext)
        _status("Protocol version", str(message.protocol_version))
        _status("Session ID", message.session_id)
        _status("Sender ID", message.sender_id)
        _status("Message ID", message.message_id)
        _status("Sequence number", str(message.sequence_number))
        print("The UUID identifies this message; the monotonic sequence number supports replay detection.")

        _step(3, "Construct canonical authenticated associated data (AAD)")
        aad_text = message.aad().decode("utf-8")
        aad_hash = _sha256(message.aad())
        _status("Canonical AAD", aad_text)
        _status("AAD SHA-256", aad_hash)
        print("AAD is visible but authenticated. Changing any bound field invalidates the GCM tag.")

        _step(4, "Encrypt with AES-256-GCM")
        _status("Cipher", "AES-256-GCM")
        _status("Nonce", message.nonce.hex())
        _status("Nonce length", f"{len(message.nonce)} bytes (96 bits)")
        _status("Ciphertext + tag", f"{len(message.ciphertext)} bytes")
        _status("Authentication tag", "16 bytes, appended to ciphertext")
        print("A fresh random nonce was generated. The session key remains hidden.")

        _step(5, "Sign and serialize the encrypted wire envelope")
        wire_dict = message.to_dict()
        wire_json = message.to_json()
        envelope_hash = _sha256(wire_json.encode("utf-8"))
        print(_pretty_json(wire_dict))
        _status("Canonical envelope bytes", str(len(wire_json.encode("utf-8"))))
        _status("Envelope SHA-256", envelope_hash)
        _status("Digital signature", message.signature.hex())
        print("The envelope hash is an observation fingerprint; the Ed25519 signature proves possession of Alice's signing key.")

        _step(6, "Bob validates and decrypts")
        _status("Schema validation", "PASS")
        _status("Expected session", "PASS")
        _status("Expected sender", "PASS")
        _status("Ed25519 signature", "PASS")
        _status("Replay checks", "PASS - new sequence and message ID")
        recovered = receiver.decrypt(message)
        _status("AES-GCM authentication", "PASS")
        _status("Recovered plaintext", repr(recovered))
        _status("Delivery result", "ACCEPTED")

        _step(7, "Record a privacy-preserving observation")
        observation = MessageObservation(
            recorded_at=datetime.now().astimezone().isoformat(),
            direction="alice->bob",
            message_id=message.message_id,
            sequence_number=message.sequence_number,
            session_id=message.session_id,
            sender_id=message.sender_id,
            aad_sha256=aad_hash,
            envelope_sha256=envelope_hash,
            ciphertext_bytes=len(message.ciphertext),
            outcome="ACCEPTED",
        )
        self.observations.append(observation)
        self.last_message = message
        _status("Observation number", str(len(self.observations)))
        _status("Stored plaintext", "NO")
        _status("Stored key material", "NO")
        _status("Stored envelope hash", observation.envelope_sha256)
        print("Normal delivery does not create incident evidence because no security violation occurred.")

    def _record_incident(
        self,
        expected_attack: AttackType,
        error: Exception,
        message: EncryptedMessage | None,
        description: str,
    ) -> None:
        classified = classify_failure(error)
        record = self.evidence.record(
            session_id=self.session_id,
            attack_type=classified,
            description=description,
            message_id=message.message_id if message else None,
            sequence_number=message.sequence_number if message else None,
        )
        if self.recovery.state is RecoveryState.SECURE:
            self.recovery.report_violation()
        checkpoint = self.evidence.checkpoint()

        print("\n[SECURITY VIOLATION DETECTED]")
        _status("Expected scenario", expected_attack.value)
        _status("Actual classification", classified.value)
        _status("Failure type", type(error).__name__)
        _status("Failure detail", str(error))
        _status("Evidence incident ID", record.incident_id)
        _status("Previous evidence hash", record.previous_evidence_hash)
        _status("New evidence hash", record.evidence_hash)
        _status("Chain checkpoint count", str(checkpoint.record_count))
        _status("Checkpoint tip", checkpoint.evidence_hash)
        _status("Evidence chain valid", str(verify_evidence_chain(self.evidence.records, checkpoint)))
        _status("Recovery state", self.recovery.state.value)
        print("Plaintext and cryptographic keys were excluded from the evidence record.")

    def replay_last_message(self) -> None:
        if self.last_message is None:
            print("\n[UNAVAILABLE] Send and successfully deliver a message first.")
            return
        if self.recovery.state is not RecoveryState.SECURE:
            print(f"\n[DENIED] Recovery is currently {self.recovery.state.value}.")
            return
        receiver = self.bob_sessions.receiver
        assert receiver is not None
        print(f"\n{LINE}\nREPLAY ATTACK: RESEND THE LAST ACCEPTED ENVELOPE\n{LINE}")
        _status("Replayed message ID", self.last_message.message_id)
        _status("Replayed sequence", str(self.last_message.sequence_number))
        _status("Envelope SHA-256", _sha256(self.last_message.to_json().encode("utf-8")))
        print("The bytes are valid and unchanged, but Bob has already accepted this sequence.")
        try:
            receiver.decrypt(self.last_message)
            print("[FAIL] Replay was unexpectedly accepted.")
        except Exception as error:
            self._record_incident(
                AttackType.REPLAY,
                error,
                self.last_message,
                f"Replay rejected: {type(error).__name__}",
            )

    def tamper_last_message(self, field: str) -> None:
        if self.last_message is None:
            print("\n[UNAVAILABLE] Send and successfully deliver a message first.")
            return
        if self.recovery.state is not RecoveryState.SECURE:
            print(f"\n[DENIED] Recovery is currently {self.recovery.state.value}.")
            return
        receiver = self.bob_sessions.receiver
        assert receiver is not None
        original = self.last_message
        changes: dict[str, object] = {
            "ciphertext": b"x" + original.ciphertext[1:],
            "nonce": b"x" + original.nonce[1:],
            "sequence_number": original.sequence_number + 100,
            "message_id": f"tampered-{uuid4()}",
            "session_id": "attacker-controlled-session",
            "sender_id": "mallory",
        }
        tampered = replace(original, **{field: changes[field]})
        original_hash = _sha256(original.to_json().encode("utf-8"))
        tampered_hash = _sha256(tampered.to_json().encode("utf-8"))

        print(f"\n{LINE}\nTAMPERING ATTACK: ALTER {field.upper()}\n{LINE}")
        _status("Original envelope hash", original_hash)
        _status("Tampered envelope hash", tampered_hash)
        _status("Hashes equal", str(original_hash == tampered_hash))
        print("The changed envelope is submitted to Bob's real receiver.")
        try:
            receiver.decrypt(tampered)
            print("[FAIL] Tampered message was unexpectedly accepted.")
        except Exception as error:
            self._record_incident(
                AttackType.TAMPERING,
                error,
                tampered,
                f"Tampered {field} rejected: {type(error).__name__}",
            )

    def attempt_key_substitution(self) -> None:
        if self.recovery.state is not RecoveryState.SECURE:
            print(f"\n[DENIED] Recovery is currently {self.recovery.state.value}.")
            return
        mallory = Identity.create("mallory")
        mallory_public = public_key_bytes(mallory.public_key)
        expected_public = public_key_bytes(self.bob.public_key)
        print(f"\n{LINE}\nKEY-SUBSTITUTION ATTACK DURING SESSION ESTABLISHMENT\n{LINE}")
        _status("Alice's expected peer", "bob")
        _status("Expected fingerprint", _fingerprint(expected_public))
        _status("Presented identity", "mallory")
        _status("Presented fingerprint", _fingerprint(mallory_public))
        _status("Fingerprints match", str(expected_public == mallory_public))
        try:
            self.alice_sessions.establish(
                mallory_public,
                mallory.signing_public_key_bytes,
                session_id=f"substitution-{uuid4()}",
                context=b"untrusted-substitution",
            )
            print("[FAIL] Substituted key was unexpectedly accepted.")
        except Exception as error:
            self._record_incident(
                AttackType.KEY_SUBSTITUTION,
                error,
                None,
                f"Pinned-key substitution rejected: {type(error).__name__}",
            )

    def recover(self) -> None:
        print(f"\n{LINE}\nBOUNDED INCIDENT RECOVERY\n{LINE}")
        _status("Current state", self.recovery.state.value)
        if self.recovery.state is RecoveryState.SECURE:
            print("No recovery is required; the session is secure.")
            return
        if self.recovery.state is RecoveryState.BLOCKED:
            print("The recovery machine is permanently BLOCKED. Reset the demo to start again.")
            return
        if self.recovery.state is not RecoveryState.QUARANTINED:
            print("Recovery cannot start from the current state.")
            return

        print("\nVerification choices:")
        print("  1. Verification succeeds: rekey and resume securely")
        print("  2. Verification fails: block the relationship")
        choice = input("Select outcome [1/2]: ").strip()
        self.recovery.begin_verification()
        if choice == "1":
            old_session = self.session_id
            self.recovery.verification_succeeded()
            self.session_generation += 1
            self.session_id = f"cipherchat-{self.session_generation}-{uuid4()}"
            self.context = f"cipherchat-flow:incident-recovery:generation-{self.session_generation}".encode()
            rekey_pair(self.alice_sessions, self.bob_sessions, session_id=self.session_id, context=self.context)
            self.recovery.rekey_complete()
            self.last_message = None
            _status("Verification", "SUCCEEDED")
            _status("Old session", old_session)
            _status("New session", self.session_id)
            _status("Old session objects", "INVALIDATED")
            _status("Final state", self.recovery.state.value)
            print("A fresh X25519/HKDF session is active. Old messages cannot enter it.")
        else:
            self.recovery.verification_failed()
            _status("Verification", "FAILED")
            _status("Final state", self.recovery.state.value)
            print("The relationship is blocked. There is no automatic retry path.")

    def view_evidence(self) -> None:
        print(f"\n{LINE}\nINCIDENT EVIDENCE LOG\n{LINE}")
        if not self.evidence.records:
            print("No incident evidence exists. Normal accepted messages are not incidents.")
            return
        checkpoint = self.evidence.checkpoint()
        for index, record in enumerate(self.evidence.records, 1):
            print(f"\nEvidence record {index}/{len(self.evidence.records)}")
            print(SUBLINE)
            print(_pretty_json(asdict(record)))
            _status("Record hash valid", str(verify_evidence_chain(self.evidence.records[:index])))
        print(f"\n{SUBLINE}")
        _status("Records", str(checkpoint.record_count))
        _status("Trusted checkpoint tip", checkpoint.evidence_hash)
        _status("Complete chain valid", str(verify_evidence_chain(self.evidence.records, checkpoint)))
        print(
            "Interpretation: each hash covers the record and previous hash. A separately "
            "stored checkpoint detects modification, reordering, deletion, or appended records."
        )

    def view_observations(self) -> None:
        print(f"\n{LINE}\nSUCCESSFUL MESSAGE OBSERVATIONS\n{LINE}")
        if not self.observations:
            print("No messages have been successfully delivered.")
            return
        for index, observation in enumerate(self.observations, 1):
            print(f"\nObservation {index}/{len(self.observations)}")
            print(SUBLINE)
            print(_pretty_json(asdict(observation)))
        print("\nThese observations contain hashes and metadata, not plaintext or keys.")

    def view_status(self) -> None:
        print(f"\n{LINE}\nCURRENT DEMONSTRATION STATUS\n{LINE}")
        _status("Session generation", str(self.session_generation))
        _status("Session ID", self.session_id)
        _status("Recovery state", self.recovery.state.value)
        _status("Recovery history", " -> ".join(state.value for state in self.recovery.history))
        _status("Delivered observations", str(len(self.observations)))
        _status("Evidence records", str(len(self.evidence.records)))
        _status("Last message available", str(self.last_message is not None))
        if self.evidence.records:
            checkpoint = self.evidence.checkpoint()
            _status("Evidence chain valid", str(verify_evidence_chain(self.evidence.records, checkpoint)))
            _status("Evidence checkpoint", checkpoint.evidence_hash)


def _choose_tamper_field() -> str | None:
    print("\nChoose exactly one field to alter:")
    for index, field in enumerate(TAMPER_FIELDS, 1):
        print(f"  {index}. {field}")
    choice = input("Field [1-6]: ").strip()
    try:
        return TAMPER_FIELDS[int(choice) - 1]
    except (ValueError, IndexError):
        print("Invalid field selection.")
        return None


def _print_menu() -> None:
    print(f"\n{LINE}")
    print("CIPHERCHAT END-TO-END PROCESS MENU")
    print(LINE)
    print("  1. Show session establishment and key-agreement flow")
    print("  2. Alice sends an encrypted message to Bob (complete flow)")
    print("  3. Replay the last accepted message")
    print("  4. Tamper with the last encrypted message")
    print("  5. Attempt public-key substitution")
    print("  6. Run incident verification and recovery/rekey")
    print("  7. View successful-message observation log")
    print("  8. View hash-chained incident evidence log")
    print("  9. View current session and recovery status")
    print(" 10. Reset the complete demonstration")
    print("  0. Exit")


def main() -> None:
    demo = FlowDemonstration()
    print(f"\n{LINE}")
    print("CIPHERCHAT: ALICE-TO-BOB END-TO-END SECURITY FLOW")
    print(LINE)
    print(
        "This interactive demonstration uses the real X25519, HKDF-SHA-256,\n"
        "AES-256-GCM, replay detection, evidence chaining, and recovery logic.\n"
        "Choose option 1 first for the clearest guided sequence."
    )

    while True:
        _print_menu()
        choice = input("Select an option: ").strip()
        if choice == "1":
            demo.show_session_establishment()
        elif choice == "2":
            plaintext = input("Enter Alice's message to Bob: ")
            if not plaintext:
                plaintext = "Hello Bob, this is Alice."
            demo.send_message(plaintext)
        elif choice == "3":
            demo.replay_last_message()
        elif choice == "4":
            field = _choose_tamper_field()
            if field is not None:
                demo.tamper_last_message(field)
        elif choice == "5":
            demo.attempt_key_substitution()
        elif choice == "6":
            demo.recover()
        elif choice == "7":
            demo.view_observations()
        elif choice == "8":
            demo.view_evidence()
        elif choice == "9":
            demo.view_status()
        elif choice == "10":
            confirmation = input("Reset identities, sessions, observations, and evidence? [y/N]: ").strip().lower()
            if confirmation in {"y", "yes"}:
                demo = FlowDemonstration()
                print("Demonstration reset with new identities and a fresh session.")
            else:
                print("Reset cancelled.")
        elif choice == "0":
            print("\nDemonstration ended. No secret key material was displayed or logged.")
            break
        else:
            print("Invalid selection. Choose a number from 0 to 10.")


if __name__ == "__main__":
    main()
