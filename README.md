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

For Alice, Bob, and Eva on separate laptops, follow
[MULTITERMINAL_GUIDE.md](MULTITERMINAL_GUIDE.md).

For the reproducible CipherChat/Matrix Olm performance comparison, see
[benchmarks/results/REPORT.md](benchmarks/results/REPORT.md) and
[benchmarks/run.py](benchmarks/run.py).

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

Verification can instead lead to `BLOCKED`. There is no automatic retry loop;
rekeying generates new X25519 key pairs on both sides. Each side signs its new
public key, session ID, and context with its pinned Ed25519 identity before the
new ECDH secret is used. Old session objects are invalidated on replacement.
