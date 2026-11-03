# How to present the performance benchmark

These notes use the saved run from 2026-11-03T05:33:16.840995+00:00. Put [encryption_decryption_comparison.svg](encryption_decryption_comparison.svg) on the main result slide and [benchmark_method.svg](benchmark_method.svg) on the method slide. On macOS, the harness also exports PNG copies for slide editors. Use only numbers from this run.

## Slide 1 — Question and comparator

**Say:** “We measured how much processing and message expansion CipherChat adds, then compared its warm one-to-one message path with Matrix Olm's Rust `vodozemac` implementation through Python bindings. A plaintext byte copy is an insecure lower-bound control.”

Both systems ran on the same Apple M3 using Python 3.14.6. CipherChat's protocol and JSON work are Python; `cryptography` supplies native primitives. Olm's message work is in Rust. The original C/C++ Olm implementation was not tested.

## Slide 2 — Method: show the flow diagram

```text
32 B / 1 KiB / 16 KiB plaintext
    → establish a warm sender/receiver session
    → 50 untimed warm-up messages
    → time encrypt + serialize
    → time parse + decrypt
    → verify recovered plaintext equals input
    → repeat 300 messages × 5 rounds for each size and system
    → summarize individual timings; measure throughput in a separate batch
```

**Say:** “Each operation ran in one process. The timer was `perf_counter_ns`, converted to microseconds. The order of systems rotated between rounds. The test excluded sockets, port 8000, the browser, relay polling, and disk writes.”

## Slide 3 — Define every column

| Term | What to say |
| --- | --- |
| Payload bytes | Size of the original plaintext before encryption: 32, 1,024, or 16,384 bytes. |
| Samples | 1,500 individual timings per system and size: 300 messages × 5 rounds. |
| Encrypt median (µs) | Typical time for encrypting **and serializing** a message. Lower is faster. |
| Decrypt median (µs) | Typical time for parsing **and decrypting** the message. Lower is faster. |
| Round-trip median (µs) | Typical encrypt-plus-decrypt processing time in this one process. It is not network round-trip time. |
| Round-trip p95 (µs) | 95% of measured message operations finished within this time; it is not the maximum. |
| Throughput (msg/s) | Median number of complete message operations per second across five separate timed batches. |
| Wire bytes | Bytes of the representation returned by the harness. CipherChat counts full JSON envelope; Olm counts only binary protocol body. |
| Overhead bytes | Wire bytes minus plaintext bytes. The differing serialization layers limit direct comparison. |
| Setup / rekey | Fresh session creation and CipherChat signed key replacement, measured separately from warm messages. |

**Note:** medians of the send and receive columns need not add exactly to the median of the combined operation; each median is calculated independently.

## Slide 4 — Explain the comparison chart

Both panels use the **same 0–350 µs horizontal scale**. Green is CipherChat; blue is Olm. Shorter bars mean less processing time.

- **32 B:** CipherChat encrypt/serialize is 93.2 µs versus Olm 13.7 µs. The message is tiny, so fixed per-message work matters most.
- **1 KiB:** CipherChat's full operation is 294.0 µs versus Olm 42.2 µs, about 7.0× the time in this run.
- **16 KiB:** CipherChat encrypt/serialize is **210.1 µs**, faster than Olm's **305.5 µs** (31% lower measured time). Its parse/decrypt time is **300.0 µs**, slower than Olm's **105.1 µs**. The full operation remains slower for CipherChat: **510.8 versus 410.9 µs**.

**Say:** “Our 16 KiB result is better on the **send side only**. The receive side reverses the result, so Olm still wins the complete operation. We cannot conclude CipherChat is faster overall.”

## Slide 5 — Why the numbers may differ

- CipherChat constructs metadata, signs each message, Base64-encodes binary fields, and serializes a full JSON envelope. Its receiver parses JSON, decodes Base64, validates fields, verifies the signature, and decrypts. These are plausible contributors to its higher small-message cost.
- CipherChat's 16 KiB send result is faster in this one run, but the benchmark does not isolate AES, signatures, ratcheting, encoding, or language runtime. Do not claim a single proven cause.
- CipherChat's 16 KiB full JSON envelope is 22,157 B; Olm's binary body is 16,450 B. Base64 contributes strongly to CipherChat's payload expansion, but a full Matrix network event would also add encoding and metadata.
- The plaintext copy has no encryption, authentication, signatures, or replay protection. It shows a rough lower bound, not an acceptable secure alternative.

## Slide 6 — Limits and conclusion

**Say:** “These are core-code measurements on one host, not port 8000 user-experience times. The systems have different security designs and different counted wire layers. A fairer follow-up would add a full Matrix event comparison, an end-to-end UI/transport test, and component profiling. Our result identifies where to investigate: especially CipherChat's receive path and JSON handling.”

**One-sentence conclusion:** “CipherChat's 16 KiB encryption path was faster in our sample, while Matrix Olm was faster at decryption and in the complete operation; our comparison is evidence for targeted profiling, not a claim of overall superiority.”
