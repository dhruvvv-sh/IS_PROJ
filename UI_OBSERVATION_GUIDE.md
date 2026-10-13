# CipherChat UI Observation Guide

## Run locally

```bash
python -m cipherchat.ui.server
```

Open `http://127.0.0.1:8000`. This is a local-only **DEMONSTRATION MODE** for
teaching, not a production chat service.

The server atomically refreshes `security_test_results/attack_simulation.json`
after each API request. The file contains the current session, delivered
messages, a dedicated history of complete attack results, attack evidence,
observation events, and HTTP audit entries. Starting the server creates a fresh
log, while the Reset action clears the session data and persists the new state.

## Architecture

```text
Browser UI (renders backend JSON only)
  → DemonstrationController
  → SessionManager / SenderSession / ReceiverSession
  → X25519 → HKDF-SHA-256 → AES-256-GCM → Ed25519

Attacker control → existing AttackSimulator
  → EvidenceLog + checkpoint → RecoveryMachine → rekey / BLOCKED
```

The browser never computes cryptography, hashes, nonces, or attack results.
The Python controller creates chronological `ObservationEvent` records from
actual backend calls; JavaScript only renders them.

## Event and visualization model

An event contains a UTC timestamp, category, step, title, actual data, and a
short explanation. A normal message produces creation, AAD, encryption, raw
protocol message, signature creation and verification, receipt, validation,
decryption, and acceptance events. The
technical pane shows the exact event JSON; **Why?** toggles its explanation.

The pipeline and timeline are clickable. Previous, Next step, and Play provide
a paced presentation mode.

## Observable and private values

| Value | Policy |
|---|---|
| Public X25519 and Ed25519 keys | Full actual value |
| Session ID, UUID, sequence, AAD, nonce, ciphertext, GCM tag, signature | Full actual value |
| Derived AES session key | Full actual value, labelled local demonstration only |
| Long-term identity private keys | Never displayed |
| Raw ECDH shared secret | Not displayed |

The encryption API returns ciphertext and its final 16-byte GCM tag together.
The UI displays those actual bytes both split and combined.

## Attacks, evidence, and recovery

Every attacker button calls the existing Python `AttackSimulator`; no UI attack
logic is duplicated. The trace shows actual classification, evidence hash,
checkpoint status, recovery history, and rekey/block result. Replay and
tampering scenarios use the real recovery FSM and session rekeying. Key
substitution uses the pinned-key check and reaches `BLOCKED`.

The key-substitution view detects mismatch with an already trusted pin. It does
not claim complete MITM prevention or safe first-contact key provisioning.

## Demonstration workflow

1. Inspect session/public-key/HKDF steps.
2. Send a normal Alice-to-Bob message and step through its trace.
3. Inspect AAD, nonce, ciphertext/tag, signature, and raw protocol JSON.
4. Trigger replay or tampering; inspect evidence and recovery.
5. Trigger key substitution; inspect mismatch and `BLOCKED`.
6. Use step controls for a classroom-paced walkthrough.

## Limitations

- Local single-process demonstration; JSON persistence is a local audit snapshot,
  not a database or network transport.
- Session-key visibility is only permitted in explicit demonstration mode.
- Attack simulations are controlled local scenarios, not penetration tests.
- Evidence checkpoints must be retained independently to resist log rewriting.
