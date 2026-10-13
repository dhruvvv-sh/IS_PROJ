"""Controlled local attack scenarios built on CipherChat's real security APIs.

Run all scenarios with ``python -m cipherchat.security.simulator``.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Literal

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.messages import EncryptedMessage, SessionInactiveError, ValidationError
from cipherchat.protocol.session import SessionManager
from cipherchat.security.attacks import AttackType, classify_failure
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.recovery import RecoveryMachine, RecoveryState

TamperField = Literal["ciphertext", "nonce", "sequence_number", "message_id", "session_id", "sender_id"]
TAMPER_FIELDS: tuple[TamperField, ...] = ("ciphertext", "nonce", "sequence_number", "message_id", "session_id", "sender_id")


@dataclass(frozen=True)
class AttackResult:
    """Machine-readable output for a single controlled attack attempt."""
    attack_type: AttackType
    detected: bool
    classification: AttackType
    session_id: str
    message_id: str | None
    sequence_number: int | None
    evidence_generated: bool
    evidence_hash: str | None
    checkpoint_valid: bool
    recovery_state: RecoveryState
    recovery_history: tuple[RecoveryState, ...]
    recovered: bool
    rekeyed: bool
    old_session_invalidated: bool
    detail: str


@dataclass(frozen=True)
class SimulationMetrics:
    total_attacks: int
    attacks_detected: int
    attacks_missed: int
    replay_attacks: int
    tampering_attacks: int
    key_substitutions: int
    evidence_records_generated: int
    successful_recoveries: int
    blocked_sessions: int
    rekeys_performed: int
    detection_rate: float
    recovery_success_rate: float


@dataclass(frozen=True)
class SimulationReport:
    results: tuple[AttackResult, ...]
    metrics: SimulationMetrics

    def to_dict(self) -> dict[str, object]:
        return {
            "format": "cipherchat-simulation-report-v1",
            "metrics": asdict(self.metrics),
            "results": [
                {
                    "attack_type": r.attack_type.value,
                    "detected": r.detected,
                    "classification": r.classification.value,
                    "session_id": r.session_id,
                    "message_id": r.message_id,
                    "sequence_number": r.sequence_number,
                    "evidence_generated": r.evidence_generated,
                    "evidence_hash": r.evidence_hash,
                    "checkpoint_valid": r.checkpoint_valid,
                    "recovery_state": r.recovery_state.value,
                    "recovery_history": [s.value for s in r.recovery_history],
                    "recovered": r.recovered,
                    "rekeyed": r.rekeyed,
                    "old_session_invalidated": r.old_session_invalidated,
                    "detail": r.detail,
                }
                for r in self.results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def export_json(self, path: Path | str, indent: int = 2) -> Path:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(self.to_json(indent=indent), encoding="utf-8")
        return out_path


@dataclass
class _Scenario:
    alice: Identity
    bob: Identity
    alice_sessions: SessionManager
    bob_sessions: SessionManager
    evidence: EvidenceLog
    recovery: RecoveryMachine
    session_id: str


class AttackSimulator:
    """Runs reproducible local attacks; cryptographic values remain random."""

    def _scenario(self, label: str) -> _Scenario:
        alice, bob = Identity.create("alice"), Identity.create("bob")
        alice_sessions = SessionManager(alice, bob.identity_id, public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
        bob_sessions = SessionManager(bob, alice.identity_id, public_key_bytes(alice.public_key), alice.signing_public_key_bytes)
        session_id = f"simulation-{label}"
        context = f"cipherchat-simulation:{label}".encode()
        alice_sessions.establish(public_key_bytes(bob.public_key), bob.signing_public_key_bytes, session_id=session_id, context=context)
        bob_sessions.establish(public_key_bytes(alice.public_key), alice.signing_public_key_bytes, session_id=session_id, context=context)
        return _Scenario(alice, bob, alice_sessions, bob_sessions, EvidenceLog(), RecoveryMachine(), session_id)

    @staticmethod
    def _record(scenario: _Scenario, attack_type: AttackType, error: Exception, message: EncryptedMessage | None) -> tuple[str, bool]:
        record = scenario.evidence.record(
            session_id=scenario.session_id,
            attack_type=attack_type,
            description=f"Observed {attack_type.value}: {type(error).__name__}",
            message_id=message.message_id if message else None,
            sequence_number=message.sequence_number if message else None,
        )
        checkpoint = scenario.evidence.checkpoint()
        return record.evidence_hash, verify_evidence_chain(scenario.evidence.records, checkpoint)

    @staticmethod
    def _result(
        scenario: _Scenario,
        *, attack_type: AttackType,
        classification: AttackType,
        message: EncryptedMessage | None,
        evidence_hash: str | None,
        checkpoint_valid: bool,
        recovered: bool,
        rekeyed: bool,
        old_session_invalidated: bool,
        detail: str,
    ) -> AttackResult:
        return AttackResult(
            attack_type=attack_type, detected=classification is not AttackType.UNKNOWN,
            classification=classification, session_id=scenario.session_id,
            message_id=message.message_id if message else None,
            sequence_number=message.sequence_number if message else None,
            evidence_generated=evidence_hash is not None, evidence_hash=evidence_hash,
            checkpoint_valid=checkpoint_valid, recovery_state=scenario.recovery.state,
            recovery_history=tuple(scenario.recovery.history), recovered=recovered,
            rekeyed=rekeyed, old_session_invalidated=old_session_invalidated, detail=detail,
        )

    def _recover_with_rekey(self, scenario: _Scenario, label: str, old_message: EncryptedMessage) -> tuple[bool, bool]:
        """Drive the real FSM and replace both active local sessions."""
        old_sender, old_receiver = scenario.alice_sessions.sender, scenario.bob_sessions.receiver
        assert old_sender is not None and old_receiver is not None
        scenario.recovery.report_violation()
        scenario.recovery.begin_verification()
        scenario.recovery.verification_succeeded()
        new_session_id = f"{scenario.session_id}-rekey"
        context = f"cipherchat-simulation:rekey:{label}".encode()
        scenario.alice_sessions.rekey(public_key_bytes(scenario.bob.public_key), scenario.bob.signing_public_key_bytes, session_id=new_session_id, context=context)
        scenario.bob_sessions.rekey(public_key_bytes(scenario.alice.public_key), scenario.alice.signing_public_key_bytes, session_id=new_session_id, context=context)
        scenario.recovery.rekey_complete()
        try:
            old_sender.encrypt("must not send")
            old_receiver.decrypt(old_message)
            old_inactive = False
        except SessionInactiveError:
            old_inactive = True
        new_sender, new_receiver = scenario.alice_sessions.sender, scenario.bob_sessions.receiver
        assert new_sender is not None and new_receiver is not None
        new_message = new_sender.encrypt("post-rekey check")
        new_works = new_receiver.decrypt(new_message) == "post-rekey check"
        return new_works, old_inactive

    def simulate_replay(self) -> AttackResult:
        scenario = self._scenario("replay")
        sender, receiver = scenario.alice_sessions.sender, scenario.bob_sessions.receiver
        assert sender is not None and receiver is not None
        message = sender.encrypt("replay scenario")
        receiver.decrypt(message)  # normal delivery must use the real receiver
        try:
            receiver.decrypt(message)
        except Exception as error:
            classification = classify_failure(error)
            evidence_hash, checkpoint_valid = self._record(scenario, classification, error, message)
            recovered, old_inactive = self._recover_with_rekey(scenario, "replay", message)
            return self._result(scenario, attack_type=AttackType.REPLAY, classification=classification,
                message=message, evidence_hash=evidence_hash, checkpoint_valid=checkpoint_valid,
                recovered=recovered, rekeyed=True, old_session_invalidated=old_inactive, detail=type(error).__name__)
        return self._result(scenario, attack_type=AttackType.REPLAY, classification=AttackType.UNKNOWN,
            message=message, evidence_hash=None, checkpoint_valid=False, recovered=False, rekeyed=False,
            old_session_invalidated=False, detail="replay was unexpectedly accepted")

    def simulate_tampering(self, field: TamperField = "ciphertext") -> AttackResult:
        scenario = self._scenario(f"tampering-{field}")
        sender, receiver = scenario.alice_sessions.sender, scenario.bob_sessions.receiver
        assert sender is not None and receiver is not None
        message = sender.encrypt("tampering scenario")
        changes: dict[TamperField, object] = {
            "ciphertext": b"x" + message.ciphertext[1:], "nonce": b"x" + message.nonce[1:],
            "sequence_number": message.sequence_number + 1, "message_id": "tampered-message-id",
            "session_id": "tampered-session-id", "sender_id": "mallory",
        }
        tampered = replace(message, **{field: changes[field]})
        try:
            receiver.decrypt(tampered)
        except Exception as error:
            classification = classify_failure(error)
            evidence_hash, checkpoint_valid = self._record(scenario, classification, error, tampered)
            recovered, old_inactive = self._recover_with_rekey(scenario, f"tampering-{field}", message)
            return self._result(scenario, attack_type=AttackType.TAMPERING, classification=classification,
                message=tampered, evidence_hash=evidence_hash, checkpoint_valid=checkpoint_valid,
                recovered=recovered, rekeyed=True, old_session_invalidated=old_inactive, detail=type(error).__name__)
        return self._result(scenario, attack_type=AttackType.TAMPERING, classification=AttackType.UNKNOWN,
            message=tampered, evidence_hash=None, checkpoint_valid=False, recovered=False, rekeyed=False,
            old_session_invalidated=False, detail=f"tampered {field} was unexpectedly accepted")

    def simulate_key_substitution(self) -> AttackResult:
        scenario = self._scenario("key-substitution")
        mallory = Identity.create("mallory")
        try:
            scenario.alice_sessions.establish(public_key_bytes(mallory.public_key), mallory.signing_public_key_bytes, session_id="substituted", context=b"substituted")
        except Exception as error:
            classification = classify_failure(error)
            evidence_hash, checkpoint_valid = self._record(scenario, classification, error, None)
            scenario.recovery.report_violation()
            scenario.recovery.begin_verification()
            scenario.recovery.verification_failed()
            return self._result(scenario, attack_type=AttackType.KEY_SUBSTITUTION, classification=classification,
                message=None, evidence_hash=evidence_hash, checkpoint_valid=checkpoint_valid,
                recovered=False, rekeyed=False, old_session_invalidated=False, detail=type(error).__name__)
        return self._result(scenario, attack_type=AttackType.KEY_SUBSTITUTION, classification=AttackType.UNKNOWN,
            message=None, evidence_hash=None, checkpoint_valid=False, recovered=False, rekeyed=False,
            old_session_invalidated=False, detail="substituted public key was unexpectedly accepted")

    def run_all(self) -> SimulationReport:
        results = [self.simulate_replay()]
        results.extend(self.simulate_tampering(field) for field in TAMPER_FIELDS)
        results.append(self.simulate_key_substitution())
        return SimulationReport(tuple(results), metrics_for(results))


def metrics_for(results: list[AttackResult] | tuple[AttackResult, ...]) -> SimulationMetrics:
    items = tuple(results)
    total = len(items)
    detected = sum(result.detected for result in items)
    recoverable = [result for result in items if result.recovered or result.recovery_state is RecoveryState.BLOCKED]
    recoveries = sum(result.recovered for result in items)
    return SimulationMetrics(
        total_attacks=total, attacks_detected=detected, attacks_missed=total - detected,
        replay_attacks=sum(result.attack_type is AttackType.REPLAY for result in items),
        tampering_attacks=sum(result.attack_type is AttackType.TAMPERING for result in items),
        key_substitutions=sum(result.attack_type is AttackType.KEY_SUBSTITUTION for result in items),
        evidence_records_generated=sum(result.evidence_generated for result in items),
        successful_recoveries=recoveries,
        blocked_sessions=sum(result.recovery_state is RecoveryState.BLOCKED for result in items),
        rekeys_performed=sum(result.rekeyed for result in items),
        detection_rate=(detected / total) if total else 0.0,
        recovery_success_rate=(recoveries / len(recoverable)) if recoverable else 0.0,
    )


def main() -> None:
    report = AttackSimulator().run_all()
    print("=" * 50 + "\nCipherChat Attack Simulation\n" + "=" * 50)
    for index, result in enumerate(report.results, 1):
        title = result.attack_type.value if result.attack_type is not AttackType.TAMPERING else f"TAMPERING ({result.detail})"
        print(f"\n[{index}] {title}")
        print(f"    Detection:      {'PASS' if result.detected else 'FAIL'}")
        print(f"    Classification: {result.classification.value}")
        print(f"    Evidence:       {'PASS' if result.evidence_generated and result.checkpoint_valid else 'FAIL'}")
        print(f"    Recovery:       {result.recovery_state.value}")
        if result.rekeyed:
            print(f"    Rekey:          {'PASS' if result.old_session_invalidated else 'FAIL'}")
    metrics = report.metrics
    print("\n" + "=" * 50 + "\nSimulation Complete")
    print(f"Attacks: {metrics.total_attacks}; detected: {metrics.attacks_detected}; missed: {metrics.attacks_missed}")
    print(f"Detection rate: {metrics.detection_rate:.0%}; recovery success rate: {metrics.recovery_success_rate:.0%}")
    out_dir = Path("security_test_results")
    if out_dir.exists():
        json_path = out_dir / "attack_simulation.json"
        report.export_json(json_path)
        print(f"JSON LOG:       {json_path}")


if __name__ == "__main__":
    main()
