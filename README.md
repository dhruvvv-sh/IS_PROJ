# CipherChat

An educational prototype for attack-aware encrypted messaging: protocol violations
become privacy-preserving, hash-chained incident evidence and drive an explicit,
bounded recovery state machine.

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest
python -m cipherchat.main
# Reproducible security-property evaluation and structured logs
python -m cipherchat.security.evaluation
# Local teaching UI (open http://127.0.0.1:8000)
python -m cipherchat.ui.server
```

The evaluation writes `security_test_results/SECURITY_TEST_REPORT.md` and a
machine-readable `security_test_results/security_evaluation.jsonl` containing
one interpreted result per tested security property. No plaintext or key
material is included in that log.

See [UI_OBSERVATION_GUIDE.md](UI_OBSERVATION_GUIDE.md) for the local
cryptographic observation interface and its demonstration-mode boundaries.
For the three-computer deployment with Alice's MacBook hosting MySQL and the
HTTP API, see [CENTRAL_PC_SETUP.md](CENTRAL_PC_SETUP.md).

## Three-role HTTP laboratory

Alice and Bob log in, encrypt and sign in their browsers, and send envelopes through
FastAPI HTTP endpoints to persistent MySQL. The browser refreshes chat and security
events every three seconds. Mallory logs in separately to replay, tamper with, and
inspect captured ciphertext. Rejected tampering, replay, or impersonation blocks
the chat. Alice or Bob can start a new session with a changed key-derivation context.
This derives a new AES key from the existing X25519 identity keys; it does not rotate
those identity keys or provide forward secrecy. The full signed envelopes and
security events are visible to Alice and Bob. The deployment and role-by-role
testing steps are in [CENTRAL_PC_SETUP.md](CENTRAL_PC_SETUP.md).
See [ALGORITHMS_AND_DATA_FLOW.md](ALGORITHMS_AND_DATA_FLOW.md) for the
implemented algorithms, process order, and input/output byte sizes.
See [VIVA_QUESTIONS_AND_ANSWERS.md](VIVA_QUESTIONS_AND_ANSWERS.md) for concise
answers to likely questions about the key exchange, KDF, messages, attacks,
evidence, and current implementation limits.

## Design

The cryptographic path is **X25519 ECDH → HKDF-SHA-256 → AES-256-GCM →
Ed25519 signature**. Each identity owns separate key-agreement and signing key
pairs. Each message has an unpredictable UUID, a strict monotonically
increasing sequence number, a fresh random 96-bit GCM nonce, canonical JSON AAD
over the protocol version, session ID, sender ID, message ID, and sequence
number, and an Ed25519 signature over the complete canonical encrypted envelope.
Receivers reject a sequence at or below the highest accepted sequence; this is
a deliberately simple in-order policy. A production transport may use a
bounded sliding window for out-of-order delivery.

Both the peer's X25519 and Ed25519 public keys are pinned before session use.
This prototype assumes those pins were provisioned through a trusted external
channel; it does not provide a certificate authority or key-transparency
system. A verification failure establishes only a cryptographic failure, not
proof of a particular attacker.

Evidence excludes plaintext, private keys, session keys, and raw shared
secrets. SHA-256 chaining detects modifications and reordering relative to the
stored chain. It does not prove authorship or protect against an attacker who
can rewrite both the records and the trusted chain reference.

Recovery only permits:

`SECURE → SUSPECTED_ATTACK → QUARANTINED → VERIFYING → REKEYING → SECURE`

Verification can instead lead to `BLOCKED`. There is no automatic retry loop.
The current `rekey()` can derive a new session key when given a changed context,
but it reuses the identity X25519 key pair; it does not provide a fresh ephemeral
exchange or enforce context uniqueness.
