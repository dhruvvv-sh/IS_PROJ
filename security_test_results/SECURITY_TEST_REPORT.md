# CipherChat Preliminary Security Test Report

Generated: `2026-10-13T07:49:19.728632+05:30`
Overall status: **PASS**

## Scope and Method

This reproducible, local black/grey-box evaluation covers confidentiality,
authenticity, integrity, non-repudiation, evidence tampering, and protocol-level
access control. It is a preliminary control verification, not a production
penetration test or formal cryptographic proof. Timing is observational only.

Environment: Python `3.13.12`, `cryptography`
`46.0.5`, `macOS-26.5.1-arm64-arm-64bit-Mach-O`.
Confidentiality sample size: `100` messages.

## Summary

| Case | Property | Status | Observed result |
|---|---|---|---|
| CONF-01 | Confidentiality | PASS | 100/100 authorized reads succeeded and 100/100 wrong-key reads were rejected. |
| AUTH-01 | Authenticity | PASS | Rejected 3/3 message forgeries; pinned-key substitution rejected=True. |
| INT-01 | Integrity | PASS | Rejected 6/6 tampered messages. |
| NREP-01 | Non-repudiation | PASS | A peer holding the shared session key created a message accepted as Alice: False. |
| EVID-01 | Evidence tampering | PASS | Original valid=True; detected 5/5 evidence-chain attacks. |
| AC-01 | Access control | PASS | Denied 3/3 binding/key attempts and 2/2 invalidated-session operations. |

Totals: **6 PASS**, **0 FAIL**, and
**0 LIMITATION**.

## Detailed Cases and Interpretation

### CONF-01: Confidentiality

- **Status:** PASS
- **Objective:** Verify authorized decryption, wrong-key rejection, nonce uniqueness, and absence of plaintext in wire JSON.
- **Expected:** All authorized reads succeed; all wrong-key reads fail; no plaintext is serialized; all sampled nonces differ.
- **Observed:** 100/100 authorized reads succeeded and 100/100 wrong-key reads were rejected.
- **Metrics:** `samples`=100; `authorized_success_rate`=100.00%; `wrong_key_rejection_rate`=100.00%; `unique_nonce_rate`=100.00%; `serialized_plaintext_leaks`=0; `duration_ms`=23.582
- **Interpretation:** AES-256-GCM protects sampled message content in transit. This does not assess endpoint compromise, memory disclosure, or traffic analysis.

### AUTH-01: Authenticity

- **Status:** PASS
- **Objective:** Verify authenticated message fields and reject a peer key that differs from the trusted pin.
- **Expected:** Every forged message and the substituted public key are rejected.
- **Observed:** Rejected 3/3 message forgeries; pinned-key substitution rejected=True.
- **Metrics:** `forgery_attempts`=3; `forgery_rejection_rate`=100.00%; `key_substitution_rejected`=True; `duration_ms`=0.578
- **Interpretation:** The session authenticates encrypted content and pinned peer-key continuity. Initial pin provisioning remains an external trust requirement.

### INT-01: Integrity

- **Status:** PASS
- **Objective:** Alter every protected payload or metadata field individually and attempt decryption.
- **Expected:** All altered messages are rejected before plaintext is released.
- **Observed:** Rejected 6/6 tampered messages.
- **Metrics:** `tamper_attempts`=6; `tamper_detection_rate`=100.00%; `duration_ms`=0.740
- **Interpretation:** GCM authentication and receiver binding detected every tested in-transit modification.

### NREP-01: Non-repudiation

- **Status:** PASS
- **Objective:** Determine whether a recipient can create a message that verifies as if it came from the sender.
- **Expected:** A message lacking a valid signature from the sender-only Ed25519 key is rejected.
- **Observed:** A peer holding the shared session key created a message accepted as Alice: False.
- **Metrics:** `peer_forgery_accepted`=False; `digital_signatures_present`=True; `duration_ms`=0.324
- **Interpretation:** Ed25519 signatures bind the complete encrypted envelope to Alice's private signing key. This depends on protected private keys and trusted public-key provisioning.

### EVID-01: Evidence tampering

- **Status:** PASS
- **Objective:** Attempt record modification, reordering, tail deletion, prefix deletion, and untrusted append against a checkpoint.
- **Expected:** The original chain verifies and every altered chain fails verification.
- **Observed:** Original valid=True; detected 5/5 evidence-chain attacks.
- **Metrics:** `tampering_attempts`=5; `tampering_detection_rate`=100.00%; `trusted_checkpoint_used`=True; `duration_ms`=0.111
- **Interpretation:** The SHA-256 chain detects tested changes only when the chain checkpoint is retained in independent trusted storage.

### AC-01: Access control

- **Status:** PASS
- **Objective:** Attempt access with the wrong session, sender binding, key, and invalidated session objects.
- **Expected:** All unauthorized protocol-level attempts fail closed.
- **Observed:** Denied 3/3 binding/key attempts and 2/2 invalidated-session operations.
- **Metrics:** `unauthorized_attempts`=5; `unauthorized_rejections`=5; `unauthorized_rejection_rate`=100.00%; `duration_ms`=0.568
- **Interpretation:** Protocol-level possession and binding checks pass. The prototype has no users, roles, resource permissions, or persistent authorization policy.

## Conclusion

CipherChat passed the sampled confidentiality, authenticity, integrity,
digital-signature/non-repudiation, evidence-tamper detection, and
protocol-binding/access tests. Ed25519 signatures prevent a peer that knows
only the shared AES key from forging another identity's messages. Peer-key
pinning still depends on trusted out-of-band provisioning, evidence checkpoints
must be stored separately, and application-level authorization is outside the
prototype.

The machine-readable logs are `security_evaluation.json` (JSON audit log) and `security_evaluation.jsonl` (per-case JSON Lines).
They store outcomes and metrics only; no plaintext, private key, session key, or shared secret is logged.
