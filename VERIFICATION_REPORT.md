# CipherChat Verification Report

## Terminal lab verification - 2026-11-03

Implemented the pastel terminal interface, first-contact combined-key fingerprint
approval, serialized polling and guarded actions, exact-envelope send retries,
separate delivery receipt retries, session-aware readable history, bounded shared
history pages, and explicit operator fresh runs. The API retains role-specific
permissions over a single shared database. Destructive demonstrations require two
explicit flags and a separate disposable database.

Validation on Windows with Python 3.14.6, real Chromium Web Crypto, and a dedicated
MySQL 8.0 container:

- Full suite with browser and MySQL tests enabled: **124 passed, zero skipped**.
- 265 warnings from deprecated Starlette/httpx test interfaces; no failing checks.
- JavaScript syntax validation and Git whitespace checks passed.
- Follow-up tests passed after final visual adjustments: keyboard CRT toggle,
  reduced motion, 200% zoom, 320/390/768/1280/1440px reflow, and upgrading a populated
  old MySQL schema while retaining its evidence chain.
- Three isolated browser contexts exercised Unicode messaging, receipt retry,
  response loss after commit, replay/tamper/impersonation/stale/eavesdrop/key
  substitution, recovery, retained history after reload, role takeover, key
  movement, and connection recovery without losing the draft.
- Live MySQL exercised persistent replay prevention, concurrent identical-send
  retries, paging beyond 100 messages, recovery, and fresh runs retaining evidence.
- The preview runtime account successfully read the audit and claimed/released a
  role lease; attempting DDL was denied. Production grants remain an operator setup
  responsibility as documented in CENTRAL_PC_SETUP.md.
- Primary text contrast is approximately 7.3-7.6:1 on the three pastel surfaces,
  and at least 4.58:1 after the specified 20% scanline compositing. Coral is used
  for accents rather than small-text surfaces.

Screenshots are in `output/terminal-ui/`. A localhost preview runs on port 8765
against the isolated test database, with destructive mode off. Demo credentials
are `alice` / `alice-password`, `bob` / `bob-password`, and
`mallory` / `mallory-password`. These are local preview credentials only.

Scope: browser tests use an isolated in-memory HTTP backend, and the persistence
suite separately uses real MySQL. The final preview smoke check uses the actual
MySQL backend. A remote multi-device deployment, other browser engines, a complete
screen-reader audit, and production-scale performance have not been verified.
The app remains a single three-role educational lab with no forward secrecy.
Run the migration before updating an existing deployment.

## Earlier verification record

The following report describes an earlier local-protocol verification run; its
platform and test counts are historical.

## 1. Executive Summary

**Overall status: PASS WITH WARNINGS.** All four requested fixes are implemented
and verified: duplicate IDs are tracked independently, active sessions rekey
and invalidate old objects, evidence checkpoints detect truncation, and pinned
peer-key verification is called before session ECDH. CipherChat still does not
provide a full authenticated key-exchange protocol or complete MITM prevention.

## 2. Environment

| Item | Value |
|---|---|
| Python | 3.14.6 |
| OS | macOS 27.0 (arm64), build 26A428 |
| `cryptography` | 50.0.2 |
| `pytest` | 9.1.1 |
| Test command | `.venv/bin/python -m pytest -q` |
| Demo command | `.venv/bin/python -m cipherchat.main` |

## 3. Verification Results

| Component | Status | Result |
|---|---|---|
| X25519 ECDH | PASS | Matching session managers exchanged encrypted messages. |
| HKDF-SHA-256 | PASS | Domain-separated 32-byte AES key derived. |
| AES-256-GCM | PASS | Round trip works; altered inputs and wrong keys fail. |
| Nonce handling | PASS | Fresh random 12-byte nonce per encryption. |
| AAD | PASS | Deterministic canonical metadata AAD is authenticated. |
| Message protocol | PASS | JSON, UUIDs, sessions, and AAD work. |
| Replay detection | PASS | Sequence and independently tracked duplicate-ID replays reject. |
| Tampering detection | PASS | Ciphertext, nonce, and metadata changes reject. |
| Key substitution | PASS WITH LIMITATION | Pinned mismatch blocks establishment; pin trust is external. |
| Incident evidence | PASS WITH WARNING | Intended fields are stored; description is caller supplied. |
| Evidence hash chain | PASS | Modification, reorder, and deletion fail against checkpoint. |
| Recovery FSM | PASS | Both paths work; invalid transitions reject. |
| Rekeying | PASS | Fresh session replaces and invalidates old session objects. |
| Existing tests | PASS | 12 passed, 0 failed, 0 skipped. |
| Terminal demo | PASS | Exercises real implementation, including rekey. |

## 4. Cryptographic Verification

### X25519

`SessionManager.establish` compares the presented serialized X25519 key to the
expected pinned key before loading it and deriving ECDH secret material. Paired
Alice/Bob managers established matching sessions in tests.

### HKDF

`derive_session_key` uses HKDF-SHA-256, a 32-byte output, and the
`cipherchat-v1|` domain prefix. Tests confirm equal inputs/context produce the
same key and a different context produces another key.

### AES-GCM

`AESGCM` uses a checked 32-byte key. Tests verify successful decryption and
rejection of wrong keys, ciphertext, nonce, and AAD changes.

### Nonce handling

Every encryption uses `os.urandom(12)`. Two executed encryptions had distinct
nonces. Uniqueness is probabilistic, not statefully recorded.

### AAD

Canonical sorted compact JSON authenticates protocol version, session ID,
sender ID, message ID, and sequence. Changed sequence or ID fails GCM; changed
session/sender fails explicit receiver binding before decryption.

No implementation code logs private keys or raw shared secrets.

## 5. Attack Verification

### Replay

**Test:** Accept a message, replay it, submit an old sequence, then create a
fully AES-GCM-valid message with the original ID and sequence 2.

**Expected:** All rejected.

**Actual:** Sequence replays raise `ReplayError`; the forward-sequence duplicate
also raises `ReplayError("message identifier was already accepted")`. IDs are
only remembered after authentication succeeds.

**Status:** PASS.

### Tampering

**Test:** Alter ciphertext, nonce, sequence number, message ID, session ID, and
sender ID after encryption.

**Actual:** Ciphertext/nonce/sequence/ID changes fail GCM authentication;
session/sender values fail receiver binding. Every variant was rejected.

**Status:** PASS.

### Key substitution

**Test:** Present Mallory's key to an Alice `SessionManager` pinned to Bob's
key; then establish using the valid Bob key.

**Actual:** The substituted key raises `KeySubstitutionError` before ECDH; the
valid pinned exchange succeeds.

**Status:** PASS WITH LIMITATION. Pin comparison detects only disagreement with
an already trusted key and does not authenticate first-contact provisioning.

## 6. Evidence Verification

`EvidenceLog.checkpoint()` exports immutable `EvidenceCheckpoint(record_count,
evidence_hash)`. This checkpoint must be stored independently from the evidence
records. `verify_evidence_chain(records, checkpoint)` validates the SHA-256
links, exact record count, and chain tip.

| Test with trusted checkpoint | Result |
|---|---|
| Original chain | Valid |
| Modify a record | Invalid |
| Delete first record | Invalid |
| Delete final record | Invalid |
| Reorder records | Invalid |

Evidence fields exclude plaintext, private keys, raw shared secrets, and
session keys. The free-form `description` remains caller supplied and therefore
must not receive sensitive input.

## 7. Recovery Verification

Successful path tested:

`SECURE → SUSPECTED_ATTACK → QUARANTINED → VERIFYING → REKEYING → SECURE`

Failure path tested:

`SECURE → SUSPECTED_ATTACK → QUARANTINED → VERIFYING → BLOCKED`

`SECURE → REKEYING` and `BLOCKED → SECURE` raised `InvalidTransition`.

### Rekeying

Two managers established session `one`, exchanged a message, then rekeyed to
session `two` with a new HKDF context. References to the old sender and receiver
raised `SessionInactiveError`; the replacement receiver rejects the old message
because its session ID no longer matches. A new message from the replacement
sender decrypted at the replacement receiver. Old active session objects and
old messages cannot be used after rekeying.

## 8. Test Results

```text
Command: .venv/bin/python -m pytest -q
Tests executed: 12
Passed: 12
Failed: 0
Skipped: 0
```

The terminal demo completed successfully, displaying replay/tampering detection,
checkpointed evidence validation, recovery transitions, and fresh-session
installation with old-session invalidation.

## 9. Problems and Limitations

### Actual Problems

No correctness failures were discovered in the post-fix tests.

### Security Limitations

- Peer-key pinning depends on trustworthy provisioning; it is not complete MITM
  prevention or an authenticated key-exchange protocol.
- Seen message IDs are an unbounded in-memory set. Production needs persistence
  and a bounded retention/window policy.
- Checkpoints detect deletion or rewriting only when retained independently from
  the evidence store.
- Rekeying replaces sessions and changes the HKDF context/session ID, but does
  not implement network negotiation or Signal-style ratcheting.
- Evidence descriptions are not automatically redacted.

## 10. Security Conclusion

The current CipherChat prototype works as intended for this phase. It now
rejects duplicate message IDs, verifies pinned peer keys during session setup,
performs operational session replacement, and detects evidence-tail deletion
when given an independently retained checkpoint. It is reasonable to progress
while keeping the stated authentication, checkpoint-storage, replay-cache, and
network-rekey limitations explicit.
