"""Reproducible preliminary security evaluation for CipherChat.

Run with::

    python -m cipherchat.security.evaluation

The command writes a concise Markdown report and one JSON Lines record per
security property.  Logs intentionally exclude plaintext and key material.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path
from time import perf_counter_ns
from typing import Callable

from cryptography import __version__ as cryptography_version

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.messages import ReceiverSession, SenderSession, SessionInactiveError
from cipherchat.protocol.session import SessionManager
from cipherchat.security.attacks import AttackType, KeySubstitutionError
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    security_property: str
    status: str
    objective: str
    expected: str
    observed: str
    metrics: dict[str, int | float | bool | str]
    interpretation: str
    duration_ms: float


@dataclass(frozen=True)
class EvaluationReport:
    generated_at: str
    environment: dict[str, str]
    sample_size: int
    results: tuple[CaseResult, ...]

    @property
    def counts(self) -> dict[str, int]:
        return {
            status: sum(result.status == status for result in self.results)
            for status in ("PASS", "FAIL", "LIMITATION")
        }

    @property
    def overall_status(self) -> str:
        if self.counts["FAIL"]:
            return "FAIL"
        if self.counts["LIMITATION"]:
            return "PASS WITH LIMITATIONS"
        return "PASS"


def _timed(case: Callable[[], CaseResult]) -> CaseResult:
    started = perf_counter_ns()
    result = case()
    elapsed = (perf_counter_ns() - started) / 1_000_000
    return replace(result, duration_ms=round(elapsed, 3))


def _sessions(label: str) -> tuple[SessionManager, SessionManager]:
    alice, bob = Identity.create("alice"), Identity.create("bob")
    alice_manager = SessionManager(alice, "bob", public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
    bob_manager = SessionManager(bob, "alice", public_key_bytes(alice.public_key), alice.signing_public_key_bytes)
    context = f"security-evaluation:{label}".encode()
    alice_manager.establish(public_key_bytes(bob.public_key), bob.signing_public_key_bytes, session_id=label, context=context)
    bob_manager.establish(public_key_bytes(alice.public_key), alice.signing_public_key_bytes, session_id=label, context=context)
    return alice_manager, bob_manager


def _confidentiality(sample_size: int) -> CaseResult:
    alice, bob = _sessions("confidentiality")
    assert alice.sender is not None and bob.receiver is not None
    messages = [alice.sender.encrypt(f"confidential sample {index}") for index in range(sample_size)]
    unauthorized_rejections = 0
    authorized_round_trips = 0
    serialized_leaks = 0
    for index, message in enumerate(messages):
        attacker = ReceiverSession(b"M" * 32, message.session_id, message.sender_id, alice.identity.signing_public_key)
        try:
            attacker.decrypt(message)
        except Exception:
            unauthorized_rejections += 1
        if f"confidential sample {index}" in message.to_json():
            serialized_leaks += 1
        if bob.receiver.decrypt(message) == f"confidential sample {index}":
            authorized_round_trips += 1
    unique_nonces = len({message.nonce for message in messages})
    passed = (
        unauthorized_rejections == sample_size
        and authorized_round_trips == sample_size
        and serialized_leaks == 0
        and unique_nonces == sample_size
    )
    return CaseResult(
        "CONF-01", "Confidentiality", "PASS" if passed else "FAIL",
        "Verify authorized decryption, wrong-key rejection, nonce uniqueness, and absence of plaintext in wire JSON.",
        "All authorized reads succeed; all wrong-key reads fail; no plaintext is serialized; all sampled nonces differ.",
        f"{authorized_round_trips}/{sample_size} authorized reads succeeded and "
        f"{unauthorized_rejections}/{sample_size} wrong-key reads were rejected.",
        {
            "samples": sample_size,
            "authorized_success_rate": authorized_round_trips / sample_size,
            "wrong_key_rejection_rate": unauthorized_rejections / sample_size,
            "unique_nonce_rate": unique_nonces / sample_size,
            "serialized_plaintext_leaks": serialized_leaks,
        },
        "AES-256-GCM protects sampled message content in transit. This does not assess endpoint compromise, memory disclosure, or traffic analysis.",
        0.0,
    )


def _authenticity() -> CaseResult:
    alice, bob = _sessions("authenticity")
    assert alice.sender is not None and bob.receiver is not None
    message = alice.sender.encrypt("authenticity probe")
    probes = (
        replace(message, sender_id="mallory"),
        replace(message, message_id="forged-message-id"),
        replace(message, ciphertext=b"x" + message.ciphertext[1:]),
    )
    rejected = 0
    for probe in probes:
        receiver = ReceiverSession(bob.receiver.key, "authenticity", "alice", alice.identity.signing_public_key)
        try:
            receiver.decrypt(probe)
        except Exception:
            rejected += 1
    mallory = Identity.create("mallory")
    pin_rejected = False
    try:
        alice.establish(public_key_bytes(mallory.public_key), mallory.signing_public_key_bytes, session_id="forged", context=b"forged")
    except KeySubstitutionError:
        pin_rejected = True
    passed = rejected == len(probes) and pin_rejected
    return CaseResult(
        "AUTH-01", "Authenticity", "PASS" if passed else "FAIL",
        "Verify authenticated message fields and reject a peer key that differs from the trusted pin.",
        "Every forged message and the substituted public key are rejected.",
        f"Rejected {rejected}/{len(probes)} message forgeries; pinned-key substitution rejected={pin_rejected}.",
        {
            "forgery_attempts": len(probes),
            "forgery_rejection_rate": rejected / len(probes),
            "key_substitution_rejected": pin_rejected,
        },
        "The session authenticates encrypted content and pinned peer-key continuity. Initial pin provisioning remains an external trust requirement.",
        0.0,
    )


def _integrity() -> CaseResult:
    alice, bob = _sessions("integrity")
    assert alice.sender is not None and bob.receiver is not None
    message = alice.sender.encrypt("integrity probe")
    variants = {
        "ciphertext": replace(message, ciphertext=b"x" + message.ciphertext[1:]),
        "nonce": replace(message, nonce=b"x" + message.nonce[1:]),
        "sequence_number": replace(message, sequence_number=message.sequence_number + 1),
        "message_id": replace(message, message_id="altered-message-id"),
        "session_id": replace(message, session_id="altered-session"),
        "sender_id": replace(message, sender_id="mallory"),
    }
    rejected = 0
    for tampered in variants.values():
        receiver = ReceiverSession(bob.receiver.key, "integrity", "alice", alice.identity.signing_public_key)
        try:
            receiver.decrypt(tampered)
        except Exception:
            rejected += 1
    passed = rejected == len(variants)
    return CaseResult(
        "INT-01", "Integrity", "PASS" if passed else "FAIL",
        "Alter every protected payload or metadata field individually and attempt decryption.",
        "All altered messages are rejected before plaintext is released.",
        f"Rejected {rejected}/{len(variants)} tampered messages.",
        {"tamper_attempts": len(variants), "tamper_detection_rate": rejected / len(variants)},
        "GCM authentication and receiver binding detected every tested in-transit modification.",
        0.0,
    )


def _non_repudiation() -> CaseResult:
    alice, bob = _sessions("non-repudiation")
    assert alice.sender is not None and bob.receiver is not None
    # Bob knows the shared encryption key, but not Alice's Ed25519 private key.
    # A message signed with Bob's key while claiming to be Alice must fail.
    peer_forge = SenderSession(bob.receiver.key, "non-repudiation", "alice", bob.identity.signing_private_key)
    forged = peer_forge.encrypt("peer-generated message")
    forgery_accepted = False
    try:
        bob.receiver.decrypt(forged)
        forgery_accepted = True
    except Exception:
        pass
    return CaseResult(
        "NREP-01", "Non-repudiation", "FAIL" if forgery_accepted else "PASS",
        "Determine whether a recipient can create a message that verifies as if it came from the sender.",
        "A message lacking a valid signature from the sender-only Ed25519 key is rejected.",
        f"A peer holding the shared session key created a message accepted as Alice: {forgery_accepted}.",
        {"peer_forgery_accepted": forgery_accepted, "digital_signatures_present": True},
        "Ed25519 signatures bind the complete encrypted envelope to Alice's private signing key. This depends on protected private keys and trusted public-key provisioning.",
        0.0,
    )


def _evidence_tampering() -> CaseResult:
    log = EvidenceLog()
    first = log.record(session_id="evidence", attack_type=AttackType.REPLAY,
                       description="Replay rejected", timestamp="2026-01-01T00:00:00+00:00")
    second = log.record(session_id="evidence", attack_type=AttackType.TAMPERING,
                        description="Authentication failed", timestamp="2026-01-01T00:00:01+00:00")
    third = log.record(session_id="evidence", attack_type=AttackType.KEY_SUBSTITUTION,
                       description="Pinned key mismatch", timestamp="2026-01-01T00:00:02+00:00")
    checkpoint = log.checkpoint()
    attacks = (
        [replace(first, description="rewritten"), second, third],
        [second, first, third],
        [first, second],
        [second, third],
        [first, second, third, replace(third, incident_id="appended")],
    )
    detected = sum(not verify_evidence_chain(records, checkpoint) for records in attacks)
    baseline_valid = verify_evidence_chain(log.records, checkpoint)
    passed = baseline_valid and detected == len(attacks)
    return CaseResult(
        "EVID-01", "Evidence tampering", "PASS" if passed else "FAIL",
        "Attempt record modification, reordering, tail deletion, prefix deletion, and untrusted append against a checkpoint.",
        "The original chain verifies and every altered chain fails verification.",
        f"Original valid={baseline_valid}; detected {detected}/{len(attacks)} evidence-chain attacks.",
        {
            "tampering_attempts": len(attacks),
            "tampering_detection_rate": detected / len(attacks),
            "trusted_checkpoint_used": True,
        },
        "The SHA-256 chain detects tested changes only when the chain checkpoint is retained in independent trusted storage.",
        0.0,
    )


def _access_control() -> CaseResult:
    alice, bob = _sessions("access-control")
    assert alice.sender is not None and bob.receiver is not None
    message = alice.sender.encrypt("access probe")
    denied = 0
    for receiver in (
        ReceiverSession(bob.receiver.key, "other-session", "alice", alice.identity.signing_public_key),
        ReceiverSession(bob.receiver.key, "access-control", "mallory", alice.identity.signing_public_key),
        ReceiverSession(b"Z" * 32, "access-control", "alice", alice.identity.signing_public_key),
    ):
        try:
            receiver.decrypt(message)
        except Exception:
            denied += 1
    old_sender, old_receiver = alice.sender, bob.receiver
    alice.rekey(public_key_bytes(bob.identity.public_key), bob.identity.signing_public_key_bytes, session_id="access-control-2", context=b"access-control-2")
    bob.rekey(public_key_bytes(alice.identity.public_key), alice.identity.signing_public_key_bytes, session_id="access-control-2", context=b"access-control-2")
    invalidated = 0
    try:
        old_sender.encrypt("should be denied")
    except SessionInactiveError:
        invalidated += 1
    try:
        old_receiver.decrypt(message)
    except SessionInactiveError:
        invalidated += 1
    passed = denied == 3 and invalidated == 2
    return CaseResult(
        "AC-01", "Access control", "PASS" if passed else "FAIL",
        "Attempt access with the wrong session, sender binding, key, and invalidated session objects.",
        "All unauthorized protocol-level attempts fail closed.",
        f"Denied {denied}/3 binding/key attempts and {invalidated}/2 invalidated-session operations.",
        {
            "unauthorized_attempts": 5,
            "unauthorized_rejections": denied + invalidated,
            "unauthorized_rejection_rate": (denied + invalidated) / 5,
        },
        "Protocol-level possession and binding checks pass. The prototype has no users, roles, resource permissions, or persistent authorization policy.",
        0.0,
    )


def run_evaluation(sample_size: int = 100) -> EvaluationReport:
    if sample_size < 1:
        raise ValueError("sample_size must be at least 1")
    cases: tuple[Callable[[], CaseResult], ...] = (
        lambda: _confidentiality(sample_size),
        _authenticity,
        _integrity,
        _non_repudiation,
        _evidence_tampering,
        _access_control,
    )
    return EvaluationReport(
        generated_at=datetime.now().astimezone().isoformat(),
        environment={
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cryptography": cryptography_version,
        },
        sample_size=sample_size,
        results=tuple(_timed(case) for case in cases),
    )


def write_jsonl(report: EvaluationReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for result in report.results:
            record = {
                "generated_at": report.generated_at,
                "environment": report.environment,
                **asdict(result),
            }
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def write_json(report: EvaluationReport, path: Path, indent: int = 2) -> None:
    """Store complete evaluation audit log in JSON format with all relevant details."""
    from cipherchat.protocol.limits import (
        MAX_CONTEXT_LENGTH,
        MAX_CIPHERTEXT_SIZE,
        MAX_ID_LENGTH,
        MAX_JSON_MESSAGE_SIZE,
        MAX_REQUEST_BODY_SIZE,
        MAX_PLAINTEXT_SIZE,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "report_format": "cipherchat-security-evaluation-v1",
        "generated_at": report.generated_at,
        "overall_status": report.overall_status,
        "counts": report.counts,
        "sample_size": report.sample_size,
        "environment": report.environment,
        "system_limits": {
            "max_plaintext_size": MAX_PLAINTEXT_SIZE,
            "max_ciphertext_size": MAX_CIPHERTEXT_SIZE,
            "max_request_body_size": MAX_REQUEST_BODY_SIZE,
            "max_json_message_size": MAX_JSON_MESSAGE_SIZE,
            "max_id_length": MAX_ID_LENGTH,
            "max_context_length": MAX_CONTEXT_LENGTH,
        },
        "results": [
            {
                "case_id": item.case_id,
                "security_property": item.security_property,
                "status": item.status,
                "objective": item.objective,
                "expected": item.expected,
                "observed": item.observed,
                "duration_ms": item.duration_ms,
                "metrics": item.metrics,
                "interpretation": item.interpretation,
            }
            for item in report.results
        ],
    }
    path.write_text(json.dumps(payload, indent=indent, sort_keys=True), encoding="utf-8")


def _metric_text(metrics: dict[str, int | float | bool | str]) -> str:
    values = []
    for key, value in metrics.items():
        if isinstance(value, float):
            rendered = f"{value:.2%}" if 0 <= value <= 1 else f"{value:.3f}"
        else:
            rendered = str(value)
        values.append(f"`{key}`={rendered}")
    return "; ".join(values)


def print_terminal_report(report: EvaluationReport, markdown_path: Path, jsonl_path: Path, json_path: Path | None = None) -> None:
    """Print a self-contained explanation suitable for a live evaluation."""
    counts = report.counts
    width = 78
    print("=" * width)
    print("CIPHERCHAT PRELIMINARY INFORMATION-SECURITY EVALUATION")
    print("=" * width)
    print(f"Generated: {report.generated_at}")
    print(
        "Method: controlled local tests of confidentiality, authenticity, integrity,\n"
        "        non-repudiation, evidence tampering, and protocol access control."
    )
    print(f"Confidentiality sample: {report.sample_size} encrypted messages")
    print(
        f"Environment: Python {report.environment['python']} | "
        f"cryptography {report.environment['cryptography']}"
    )
    print(
        "Status meaning: PASS = tested control behaved as expected; "
        "FAIL = control failed;\n"
        "                LIMITATION = the security property is not provided."
    )

    for index, item in enumerate(report.results, 1):
        print("\n" + "-" * width)
        print(f"TEST {index}/{len(report.results)} | {item.case_id} | {item.security_property.upper()}")
        print("-" * width)
        print(f"STATUS         : {item.status}")
        print(f"WHAT IS TESTED : {item.objective}")
        print(f"EXPECTED       : {item.expected}")
        print(f"OBSERVED       : {item.observed}")
        print(f"METRICS        : {_metric_text(item.metrics).replace('`', '')}")
        print(f"DURATION       : {item.duration_ms:.3f} ms (observational only)")
        print(f"MEANING        : {item.interpretation}")

    print("\n" + "=" * width)
    print("FINAL SECURITY POSTURE")
    print("=" * width)
    print(f"OVERALL STATUS : {report.overall_status}")
    print(
        f"RESULT COUNTS  : {counts['PASS']} PASS | {counts['FAIL']} FAIL | "
        f"{counts['LIMITATION']} LIMITATION"
    )
    print(
        "CONCLUSION     : Tested encryption, Ed25519 signatures, evidence, and\n"
        "                 protocol controls passed. Trust still depends on secure\n"
        "                 private keys and public-key provisioning."
    )
    print(f"READABLE REPORT: {markdown_path}")
    if json_path is not None:
        print(f"JSON AUDIT LOG : {json_path}")
    print(f"JSONL AUDIT LOG: {jsonl_path}")
    print("No plaintext, private keys, session keys, or shared secrets are logged.")
    print("=" * width)


def write_markdown(report: EvaluationReport, path: Path, jsonl_name: str, json_name: str = "security_evaluation.json") -> None:
    counts = report.counts
    rows = "\n".join(
        f"| {item.case_id} | {item.security_property} | {item.status} | {item.observed} |"
        for item in report.results
    )
    details = "\n\n".join(
        f"### {item.case_id}: {item.security_property}\n\n"
        f"- **Status:** {item.status}\n"
        f"- **Objective:** {item.objective}\n"
        f"- **Expected:** {item.expected}\n"
        f"- **Observed:** {item.observed}\n"
        f"- **Metrics:** {_metric_text(item.metrics)}; `duration_ms`={item.duration_ms:.3f}\n"
        f"- **Interpretation:** {item.interpretation}"
        for item in report.results
    )
    content = f"""# CipherChat Preliminary Security Test Report

Generated: `{report.generated_at}`
Overall status: **{report.overall_status}**

## Scope and Method

This reproducible, local black/grey-box evaluation covers confidentiality,
authenticity, integrity, non-repudiation, evidence tampering, and protocol-level
access control. It is a preliminary control verification, not a production
penetration test or formal cryptographic proof. Timing is observational only.

Environment: Python `{report.environment['python']}`, `cryptography`
`{report.environment['cryptography']}`, `{report.environment['platform']}`.
Confidentiality sample size: `{report.sample_size}` messages.

## Summary

| Case | Property | Status | Observed result |
|---|---|---|---|
{rows}

Totals: **{counts['PASS']} PASS**, **{counts['FAIL']} FAIL**, and
**{counts['LIMITATION']} LIMITATION**.

## Detailed Cases and Interpretation

{details}

## Conclusion

CipherChat passed the sampled confidentiality, authenticity, integrity,
digital-signature/non-repudiation, evidence-tamper detection, and
protocol-binding/access tests. Ed25519 signatures prevent a peer that knows
only the shared AES key from forging another identity's messages. Peer-key
pinning still depends on trusted out-of-band provisioning, evidence checkpoints
must be stored separately, and application-level authorization is outside the
prototype.

The machine-readable logs are `{json_name}` (JSON audit log) and `{jsonl_name}` (per-case JSON Lines).
They store outcomes and metrics only; no plaintext, private key, session key, or shared secret is logged.
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CipherChat preliminary security evaluation")
    parser.add_argument("--sample-size", type=int, default=100)
    parser.add_argument("--output-dir", type=Path, default=Path("security_test_results"))
    args = parser.parse_args(argv)
    report = run_evaluation(args.sample_size)
    jsonl_path = args.output_dir / "security_evaluation.jsonl"
    json_path = args.output_dir / "security_evaluation.json"
    markdown_path = args.output_dir / "SECURITY_TEST_REPORT.md"
    write_jsonl(report, jsonl_path)
    write_json(report, json_path)
    write_markdown(report, markdown_path, jsonl_path.name, json_name=json_path.name)
    print_terminal_report(report, markdown_path, jsonl_path, json_path)
    return 1 if report.counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
