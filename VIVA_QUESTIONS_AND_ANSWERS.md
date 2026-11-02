# CipherChat viva questions and answers

These answers describe the **current code**, not a planned network or SQLite version. For byte-by-byte flow, see [ALGORITHMS_AND_DATA_FLOW.md](ALGORITHMS_AND_DATA_FLOW.md).

## A. Initial keys and key exchange

### 1. Which algorithm generates the keys for the initial exchange?

`X25519PrivateKey.generate()` from the `cryptography` library creates an **X25519 agreement key pair** for each participant. The raw private and public representations are 32 bytes each. `Identity.create()` also calls `Ed25519PrivateKey.generate()` to create a **separate Ed25519 signing key pair**, also represented by a 32-byte private seed and 32-byte public key. The application does not implement its own random-number generator. See `cipherchat/crypto/identity.py` and `cipherchat/crypto/key_exchange.py`.

### 2. Why are there two key pairs per participant?

X25519 keys establish a shared secret. Ed25519 keys sign and verify messages. Using separate pairs keeps agreement and signing roles distinct. The project does **not** use RSA for either operation.

### 3. Which keys can be shared?

The 32-byte X25519 public key and 32-byte Ed25519 public key can be shared. The private keys must remain with their owner. `Identity.public_material()` represents each public key as 64 hexadecimal characters for display or transfer.

### 4. How do Alice and Bob get the same shared secret without sending it?

Alice computes X25519 using her private key and Bob's public key. Bob computes X25519 using his private key and Alice's public key. Both calculations produce the same 32-byte shared secret. Neither transmits that secret. `derive_shared_secret()` performs the calculation.

### 5. Is the X25519 shared secret used directly as the AES key?

No. It is input key material for HKDF-SHA-256. HKDF produces the 32-byte AES-256 session key. This keeps key derivation tied to the protocol domain and session context.

### 6. How are exchanged public keys authenticated?

`SessionManager` compares each presented X25519 and Ed25519 public key against a previously trusted pinned value. A mismatch is rejected **before** agreement. The current project assumes the pins were obtained through a trusted external channel; it does not supply certificates or a trusted first-contact exchange.

### 7. Can the attacker replace a public key and still establish the session?

Not if the receiver already holds the genuine pinned key. The 32-byte presented key differs from the 32-byte pin and is rejected. If the attacker controls the *initial* pin provisioning, the current project has no independent way to discover that.

## B. KDF and session keys

### 8. What does KDF stand for, and which one is used?

**Key derivation function.** The project uses **HKDF-SHA-256**, whose underlying pseudorandom function is **HMAC-SHA-256**. `derive_session_key()` calls `HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=...).derive(shared_secret)`.

### 9. What are HKDF's inputs and output here?

Input key material is the **32-byte X25519 shared secret**. The context is **1–1,024 bytes**. HKDF `info` is the 13-byte `cipherchat-v1` label, one `|` byte, then that context. An optional salt can be supplied, but current session calls use `None`. Output is a **32-byte AES-256 key**.

### 10. What are the extract and expand steps?

**Extract:** `PRK = HMAC-SHA-256(salt, shared_secret)`, producing 32 bytes. With `salt=None`, `cryptography` uses 32 zero bytes. **Expand:** `T(1) = HMAC-SHA-256(PRK, info || 0x01)`, producing 32 bytes; this one block is the requested session key.

### 11. How many rounds does the KDF take?

HKDF has **no configurable iteration count** here. The code requests exactly one 32-byte output block, so it performs one extract HMAC and one expand HMAC. SHA-256's own 64 compression rounds per internal block are a different concept; do not claim “64 HKDF iterations.”

### 12. What does the context do?

It makes the derived key depend on a session-specific input. The `cipherchat-v1|` prefix separates this protocol's derivation from other uses of the same shared secret. Both participants must supply exactly the same context. A different context produces a different key.

### 13. What happens during `rekey()` today?

The existing session objects are invalidated. `rekey()` generates a new session ID when none is supplied and derives a key from the **caller-supplied context**. The caller must change that context to obtain a different key from the reused shared secret; the method does not enforce uniqueness. **The current `SessionManager.rekey()` reuses the same X25519 identity private key and peer public key.** It does not generate a fresh ephemeral X25519 key pair. Therefore do not claim fresh ECDH material, a ratchet, or forward secrecy from this method.

## C. Sending and receiving messages

### 14. Which encryption algorithm is used?

**AES-256-GCM**. The key is 32 bytes, the fresh random nonce is 12 bytes, and the authentication tag is 16 bytes. For `N` plaintext bytes, the returned ciphertext-plus-tag is `N + 16` bytes.

### 15. Why is the nonce required? Is it secret?

GCM needs a unique nonce for each encryption under a key. The code generates a fresh 12-byte nonce with `os.urandom()` for each message. The nonce travels with the message and is **not secret**. Reusing a nonce with the same key would be dangerous.

### 16. What is AAD?

**Additional authenticated data.** The project builds canonical JSON from protocol version, session ID, sender ID, message ID, and sequence number. AES-GCM authenticates these fields without encrypting them. Their byte length varies with the values.

### 17. What is signed?

Ed25519 signs a 32-byte domain prefix plus canonical JSON of all encrypted wire fields: protocol version, IDs, sequence, Base64 nonce, and Base64 ciphertext/tag. The signature itself is excluded from its input. The signature is 64 raw bytes, or 88 Base64 characters in JSON.

### 18. Why use both GCM authentication and Ed25519 signatures?

GCM detects ciphertext or AAD modification by someone lacking the session key. Alice and Bob both know that shared AES key. Ed25519 additionally verifies that the envelope was signed with the claimed sender's **private signing key**; Bob cannot create Alice's signature using only their shared AES key.

### 19. In what order does Bob validate a message?

Parse and validate the envelope → verify Ed25519 signature → check session/sender binding → check replay sequence and message ID → decrypt and authenticate with AES-GCM → decode UTF-8. Plaintext is returned only after the cryptographic checks pass.

### 20. How large can a message be?

The plaintext limit is **65,536 UTF-8 bytes**. The ciphertext plus 16-byte GCM tag can be **65,552 bytes**. The parser limits serialized message JSON to **262,144 UTF-8 bytes**. A character can take more than one byte in UTF-8, so the character count is not the byte limit.

### 21. Why does the message contain both a UUID and sequence number?

The UUID identifies a particular message; its standard text form is 36 characters. The sequence number records ordering and grows from 1. The receiver rejects an already seen ID or a sequence at or below its highest accepted value. The current receiver keeps this state only in memory.

## D. Attacks and evidence

### 22. How is a replay detected?

After Bob accepts a message, sending its identical signed envelope again passes signature verification but fails the sequence or message-ID replay check. The result is `ReplayError`. A restart loses the current in-memory replay state, so persistent protection has not yet been implemented.

### 23. What happens if an attacker changes ciphertext, nonce, or metadata?

Those fields are signed. Their modification ordinarily fails Ed25519 verification before decryption. If a validly signed envelope has a bad GCM tag, AES-GCM rejects it. The code classifies these cryptographic failures as tampering; they do not by themselves identify the attacker.

### 24. How is key substitution different from message tampering?

Key substitution occurs **during session establishment** and is checked against pinned public keys. Message tampering occurs **after a session exists** and is caught by signature/GCM checks. They should be shown as separate attack demonstrations.

### 25. How is incident evidence hashed?

Each incident record includes the previous record's hash. The code serializes the record without its new `evidence_hash` using sorted-key compact JSON and applies **SHA-256**. The digest is 32 bytes, stored as 64 hexadecimal characters. The first record uses 64 ASCII zero characters as its predecessor field.

### 26. What can the evidence chain detect?

Verification recomputes each hash and checks each predecessor link. It detects record modification and reordering. With a **trusted checkpoint containing the expected record count and tip hash**, it also detects deletion or truncation. A chain alone does not detect a complete tail deletion if no independent checkpoint survives.

### 27. Is the evidence chain currently in SQLite?

No. The local `EvidenceLog` stores records in memory and exports JSON. The realtime three-role chat uses central MySQL for encrypted envelopes, replay counters, delivery receipts, and audit evidence. Independent checkpoints are an explicit operator responsibility.

### 28. Does a hash chain prove who authored a record?

No. It checks internal consistency against a trusted checkpoint. Someone able to rewrite both the records and the only checkpoint can produce another consistent chain. The incident record does not have its own independent digital signature.

### 29. Are plaintext and keys logged?

The incident-evidence records are designed to exclude plaintext, private keys, session keys, and raw shared secrets. However, the **local teaching UI intentionally exposes plaintext and a demo session key** in observation data and exported UI logs. Do not present those UI logs as privacy-preserving production evidence.

### 30. What happens after a detected attack?

The recovery state machine moves through `SUSPECTED_ATTACK`, `QUARANTINED`, and `VERIFYING`, then either `REKEYING` and `SECURE` or `BLOCKED`. Both the controlled simulator and realtime chat use these transitions. Realtime replay, tampering, impersonation, and stale-delivery demonstrations quarantine the chat. Key-substitution verification blocks it. Audit deletion in a disposable lab makes integrity checks fail and blocks sending. An operator can start a fresh context with retained evidence after verifying an intact audit; a damaged database needs restoration.

## E. Scope and performance

### 31. Is this a complete Signal-style protocol?

No. It has X25519/HKDF setup, AES-GCM encryption, Ed25519 signatures, browser fingerprint approval, attack simulations, and MySQL-backed replay state and evidence for the realtime lab. It does not implement a Double Ratchet, fresh ephemeral key exchange, automatic key authenticity, or forward secrecy. Separate browser profiles are required to isolate role keys.

### 32. What has actually been benchmarked?

The saved local report compares CipherChat message-operation timings and wire size against AES-GCM and Fernet library baselines at several payload sizes. It is **not** a direct Signal or WhatsApp benchmark, and the benchmark script is absent from this checkout. See `security_test_results/PERFORMANCE_BENCHMARK.md` for the recorded method and measurements.

### 33. What is the shortest accurate summary of the cryptographic flow?

**X25519 keys establish a 32-byte shared secret → HKDF-SHA-256 derives a 32-byte AES key → AES-256-GCM encrypts each message using a fresh 12-byte nonce → Ed25519 signs the encrypted envelope → Bob verifies the signature, rejects replay, and authenticates/decrypts. SHA-256 links incident records.**


### How does the terminal UI verify identities?

It displays SHA-256 of a domain-separated string containing both the X25519 and
Ed25519 public keys. Alice and Bob compare the 64-digit fingerprint through an
independent channel before approving first contact or a changed identity. This
binds the encryption and signing keys together; it is not automatic authentication.

### Why can all three roles use the same database?

The API owns the database credentials and enforces role permissions. Alice and Bob
send signed ciphertext as themselves; Mallory reads lab captures and runs bounded
attack scenarios. Shared storage does not give Mallory plaintext, participant
private keys, direct SQL privileges, or permission to recover a quarantined chat.
