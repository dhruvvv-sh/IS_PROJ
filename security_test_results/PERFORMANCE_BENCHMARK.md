# CipherChat performance benchmark

Generated: 2026-10-31T05:18:41.020408+00:00

Environment: Python 3.14.6; cryptography 50.0.2; macOS-27.0-arm64-arm-64bit-Mach-O.

Method: Single-process local timing with perf_counter_ns; 20 warmup runs per scheme/size; sequential operations; no network or disk I/O.

| Payload bytes | Scheme | Encrypt median ms | Decrypt median ms | Encrypt p95 ms | Decrypt p95 ms | Wire bytes |
|---:|---|---:|---:|---:|---:|---:|
| 64 | AES-256-GCM | 0.0012 | 0.0004 | 0.0013 | 0.0004 | 92 |
| 64 | Fernet | 0.0050 | 0.0046 | 0.0051 | 0.0047 | 184 |
| 64 | CipherChat | 0.0362 | 0.0801 | 0.0521 | 0.1110 | 395 |
| 1024 | AES-256-GCM | 0.0013 | 0.0005 | 0.0015 | 0.0006 | 1052 |
| 1024 | Fernet | 0.0160 | 0.0160 | 0.0176 | 0.0171 | 1464 |
| 1024 | CipherChat | 0.0403 | 0.0834 | 0.0425 | 0.0868 | 1675 |
| 8192 | AES-256-GCM | 0.0020 | 0.0013 | 0.0021 | 0.0014 | 8220 |
| 8192 | Fernet | 0.0245 | 0.0333 | 0.0271 | 0.0361 | 11020 |
| 8192 | CipherChat | 0.0758 | 0.1133 | 0.1042 | 0.1341 | 11231 |

Wire bytes for AES-GCM include nonce and tag; Fernet includes its token encoding; CipherChat includes the complete JSON envelope and signature.

Interpretation: AES-GCM is encryption only; Fernet is symmetric authenticated encryption; CipherChat adds X25519-derived key setup, Ed25519 signatures, IDs, and replay metadata. Setup is excluded from per-message timing. These are library baselines, not Signal/WhatsApp end-to-end benchmarks.
Results depend on this machine and load. Run the command again on the professor's target hardware for a fresh comparison.
