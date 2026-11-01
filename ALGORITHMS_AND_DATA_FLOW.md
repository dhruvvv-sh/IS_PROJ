# CipherChat algorithms and data flow

This file describes the algorithms **implemented in the current repository**. Byte counts refer to raw bytes unless a column explicitly says UTF-8, Base64, hex, or JSON. `N` means the UTF-8 plaintext length in bytes. The project currently runs local demonstrations; a multi-computer transport and SQLite storage are not implemented in this checkout.

## 1. Identity creation and session setup

Flow: **create two identity key pairs per participant → check the peer's pinned public keys → X25519 agreement → HKDF-SHA-256 session key**. Alice and Bob must use the same session context to derive the same encryption key.

| Step / implemented algorithm | Input size | Output size | Purpose and implementation |
|---|---|---|---|
| X25519 key generation | Randomness supplied internally by `cryptography`; no caller-provided bytes | 32-byte private key and 32-byte raw public key | Separate agreement key pair for each identity. `crypto/identity.py`, `crypto/key_exchange.py` |
| Ed25519 key generation | Randomness supplied internally by `cryptography`; no caller-provided bytes | 32-byte private seed and 32-byte raw public key | Separate signing key pair for each identity. `crypto/identity.py` |
| Public-key pin comparison | Expected and presented X25519 keys: 32 bytes each; expected and presented Ed25519 keys: 32 bytes each | Boolean match / exception; no cryptographic output | Rejects key substitution when the presented key differs from a previously trusted pin. `protocol/session.py`, `security/attacks.py` |
| X25519 ECDH | Local 32-byte private key + peer 32-byte public key | 32-byte shared secret | Both legitimate peers derive the same secret. The shared secret is not sent. `crypto/key_exchange.py` |
| HKDF-SHA-256 | 32-byte shared secret; context of **1–1,024 bytes**; optional salt (variable length, normally `None`) | **32-byte session key** | HKDF info is the 13-byte `cipherchat-v1` domain, a 1-byte `|`, then the context: **15–1,038 bytes** total. `crypto/kdf.py` |

### HKDF details: underlying function, steps, and rounds

The code calls `HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"cipherchat-v1|" + context).derive(shared_secret)`. The underlying pseudorandom function is **HMAC-SHA-256**: HMAC constructed from the SHA-256 hash function. This is HKDF as specified by [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), rather than a password KDF such as PBKDF2.

| HKDF stage | Exact input in this project | Output |
|---|---|---|
| **Extract** | `IKM` = 32-byte X25519 shared secret; `salt` = optional caller-supplied bytes. The current session calls omit it, so `None` becomes **32 zero bytes** in `cryptography`. | `PRK = HMAC-SHA-256(salt, IKM)`: **32 bytes** |
| **Expand** | HMAC key = 32-byte `PRK`; HMAC message for the first block = `info || 0x01`, where `info` is **15–1,038 bytes**. The one-byte counter makes this **16–1,039 input bytes**. | `T(1) = HMAC-SHA-256(PRK, info || 0x01)`: **32 bytes**; all 32 bytes become the AES-256 session key |

**Number of rounds:** HKDF has **no configurable iteration or work-factor count** in this implementation. Because the requested output is 32 bytes and SHA-256 produces 32 bytes per HMAC result, expand requires **one output block**. The overall derivation performs one extract HMAC and one expand HMAC. SHA-256 itself has 64 compression rounds *per internal message block*; that is a different meaning of “rounds” and is not an HKDF setting. The output size, underlying hash, domain, and context are fixed by `crypto/kdf.py`; the optional salt can be passed by a caller, but the current session setup does not pass one. The `None` salt behavior is documented by [`cryptography`](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/).

The public key is serialized as 32 raw bytes, or **64 ASCII hex characters** in `Identity.public_material()`. The project assumes a trusted external method supplied the original pins; it does not authenticate a first-time public-key exchange by itself. Session IDs are nonempty strings limited to 256 characters. A rekey can generate a new session ID, accepts a caller-supplied context, and invalidates old session objects. It currently **reuses the existing X25519 identity key pair** and does not enforce context uniqueness.

## 2. Sending a message

Flow: **UTF-8 text → message ID and sequence number → canonical JSON associated data → AES-256-GCM → canonical signed envelope → Ed25519 signature → JSON wire message**.

| Step / implemented algorithm | Input size | Output size | Purpose and implementation |
|---|---|---|---|
| UTF-8 encoding | Python text of variable character length | `N = 0–65,536` bytes | Enforces the maximum plaintext size before encryption. `protocol/messages.py` |
| UUIDv4 message ID generation | Randomness supplied by the runtime | 16-byte UUID value, rendered as **36 ASCII characters** | Unique message identifier for duplicate detection. UUID is an identifier, not an encryption or signature algorithm. `protocol/messages.py` |
| Sequence number | Current integer counter | Positive integer; its JSON decimal byte length varies | Starts at 1 and increases per sender session. `protocol/messages.py` |
| Canonical JSON AAD construction | Protocol version, session ID, sender ID, message ID, sequence number | Variable-length UTF-8 bytes | Metadata authenticated by AES-GCM. Keys are sorted and JSON uses compact separators. `EncryptedMessage.aad()` |
| Fresh random nonce | System randomness, no caller-provided bytes | **12 bytes** (96 bits) | A new nonce is generated for every AES-GCM encryption. `crypto/encryption.py` |
| AES-256-GCM encryption | **32-byte** session key + **12-byte** nonce + `N` plaintext bytes + variable-length AAD | `N + 16` bytes: `N` ciphertext bytes followed by a **16-byte** authentication tag | Encrypts text and authenticates AAD. Output range is **16–65,552 bytes**. `crypto/encryption.py` |
| Canonical signing-input construction | Protocol version, IDs, sequence, Base64 nonce, Base64 ciphertext/tag | **32-byte** domain prefix + variable-length compact UTF-8 JSON | Prefix is `cipherchat:encrypted-message:v2` followed by `0x00`. `EncryptedMessage.signing_bytes()` |
| Ed25519 signing | 32-byte private signing seed (held as a key object) + variable-length signing input | **64-byte signature** | Covers the encrypted payload and all wire metadata except the signature itself. `protocol/messages.py` |
| Base64 and JSON serialization | 12-byte nonce, `N + 16` ciphertext/tag, 64-byte signature, metadata | Nonce **16 ASCII bytes**; ciphertext **`4 × ceil((N + 16)/3)` ASCII bytes**; signature **88 ASCII bytes**; complete JSON envelope varies and is capped at **262,144 UTF-8 bytes** when parsed | `EncryptedMessage.to_json()` / `from_json()`. The JSON size also includes field names, quotes, punctuation, and metadata. |

The 16-byte GCM tag is part of the `ciphertext` field; there is no separate tag field. The 64-byte Ed25519 signature is separate. The envelope exposes IDs, sequence number, nonce, ciphertext, and signature, but not plaintext or private keys.

## 3. Receiving and verifying a message

Flow: **parse JSON → decode Base64 → validate sizes → verify Ed25519 signature → check session and sender → check replay state → AES-256-GCM decrypt → UTF-8 decode**.

| Step / implemented algorithm | Input size | Output size | Failure behavior |
|---|---|---|---|
| JSON and Base64 decoding | At most **262,144 UTF-8 bytes** of JSON | 12-byte nonce, `N + 16`-byte ciphertext/tag, 64-byte signature, plus metadata | Rejects malformed fields or invalid sizes. `EncryptedMessage.from_json()` |
| Ed25519 verification | 32-byte pinned sender public key + variable-length signing input + 64-byte signature | Accept/reject; no message bytes produced | Any signed-field alteration causes `DigitalSignatureError`. `ReceiverSession.decrypt()` |
| Session/sender binding | Session and sender IDs, each at most 256 characters | Accept/reject | Rejects a message for another session or sender. |
| Replay checks | Positive sequence number + 36-character UUID; in-memory highest sequence and seen-ID set | Accept/reject | Rejects a sequence at or below the highest accepted sequence, or a previously accepted message ID. `ReplayError` |
| AES-256-GCM decryption | 32-byte key + 12-byte nonce + `N + 16`-byte ciphertext/tag + variable-length AAD | `N` plaintext bytes on success | A bad tag or wrong key/AAD raises `AuthenticationError`; no plaintext is released. |
| UTF-8 decoding | `N` plaintext bytes | Python text, variable number of characters | Runs only after successful authentication. |

The current replay counter and seen-ID set live **in memory**. Restarting a local demo does not persist that state. The receiver follows a strict increasing-sequence policy, so it can reject a legitimate older message delivered out of order.

## 4. Attacker actions and classification

| Action | What is changed or resent | Implemented check | Outcome |
|---|---|---|---|
| Replay | Identical signed envelope, with the same message ID and sequence | Highest accepted sequence and seen-ID set | `REPLAY` rejection after the original was accepted |
| Ciphertext, nonce, or metadata tampering | One or more bytes/fields in the signed envelope | Ed25519 verification, then GCM authentication | `TAMPERING` classification for signature or tag failure |
| Key substitution | Presented 32-byte X25519 or Ed25519 public key differs from its pinned 32-byte value | Exact byte comparison before session establishment | `KEY_SUBSTITUTION` detection |

The key comparison has no digest: it compares the complete public-key byte strings. A failure proves the presented value differs from the trusted pin; it does not identify who changed it. See `security/attacks.py`, `security/simulator.py`, and `protocol/session.py`.

## 5. Observation hashes in the local teaching demos

The terminal flow demo and local UI also calculate **SHA-256 fingerprints** to make data changes visible. These hashes are observations; they do not replace Ed25519 verification or the evidence chain.

| Input to SHA-256 | Input size | Output size | Where used |
|---|---|---|---|
| Raw X25519 or Ed25519 public key | **32 bytes** | **32-byte digest**, displayed as 64 hex digits (the terminal demo adds colons between groups) | Public-key fingerprint in `security/flow_demo.py` |
| Canonical AAD | Variable-length UTF-8 bytes | **32-byte digest / 64 hex digits** | AAD observation in `security/flow_demo.py` and `ui/server.py` |
| Canonical signing input | 32-byte prefix + variable-length JSON bytes | **32-byte digest / 64 hex digits** | Signing-input observation in `ui/server.py` |
| Complete serialized encrypted envelope | Variable-length UTF-8 JSON bytes | **32-byte digest / 64 hex digits** | Envelope observation in `main.py`, `security/flow_demo.py`, and `ui/server.py` |

The local teaching UI deliberately exposes demonstration values, including plaintext and a session key, in its observation data and exported demo logs. Do not treat those UI logs as privacy-preserving incident evidence.

## 6. Hash-chaining incident evidence

Flow: **classify a rejected action → create an incident record → include the previous hash → canonical JSON → SHA-256 → append record → export checkpoint → verify chain**.

| Step / implemented algorithm | Input size | Output size | Purpose and implementation |
|---|---|---|---|
| Incident ID (UUIDv4) | Runtime randomness | 16-byte UUID value, rendered as **36 ASCII characters** | Identifies the incident. `security/evidence.py` |
| Previous-hash field | Previous record's SHA-256 digest | **64 ASCII hex characters** in the JSON record; genesis is 64 ASCII `0` characters | Links each record to its predecessor. |
| Canonical JSON encoding | Incident ID, timestamp, session ID, attack type, optional message ID/sequence, description, previous hash | Variable-length UTF-8 bytes | Uses sorted keys and compact separators; excludes the new `evidence_hash`. |
| SHA-256 hashing | Variable-length canonical JSON bytes | **32-byte digest**, stored as **64 ASCII hex characters** | Produces `evidence_hash`. `security/evidence.py` |
| Chain checkpoint | Record count integer + latest hash | Variable-length integer plus **64 ASCII hex characters** | Used to detect changes, reordering, or deletion when retained independently. |
| Verification | All stored records + optional trusted checkpoint | Boolean pass/fail | Recomputes every SHA-256 hash and predecessor link; checkpoint additionally checks the record count and final hash. |

Evidence is currently kept in an **in-memory list** and can be exported to JSON. The code does **not** currently store the chain in SQLite or keep an independent checkpoint automatically. A checkpoint stored beside attacker-controlled records cannot detect a coordinated rewrite of both. Plaintext, private keys, session keys, and shared secrets are excluded from incident records, but `description` is caller supplied and must be kept free of sensitive text.

## 7. Recovery state machine

The recovery flow is `SECURE → SUSPECTED_ATTACK → QUARANTINED → VERIFYING → REKEYING → SECURE`, with `BLOCKED` as a possible verification outcome. This is **state-machine logic, not another cryptographic algorithm**. When a successful recovery rekeys, it repeats the X25519 calculation with the **same existing identity keys**, runs HKDF with a caller-supplied session context, and invalidates the old sender and receiver objects. The caller must change the context to derive a different key. No fresh ephemeral exchange or ratchet is implemented. See `security/recovery.py` and `protocol/session.py`.

## Worked size example

With the ASCII plaintext `hello` (`N = 5` bytes), the AES-GCM ciphertext plus tag is **21 bytes**; its Base64 value is **28 ASCII bytes**. The nonce remains **12 raw / 16 Base64 bytes**, and the Ed25519 signature remains **64 raw / 88 Base64 bytes**. In one run with session ID `demo-session`, sender ID `alice`, and a UUID message ID, the AAD was **142 bytes**, the signing input was **245 bytes**, and the complete JSON envelope was **316 bytes**. Those last three counts change with IDs and sequence number.
