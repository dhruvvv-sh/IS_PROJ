"""Local core benchmark: CipherChat, Matrix Olm, and an insecure copy control."""

from __future__ import annotations

import argparse
import csv
import importlib.metadata
import json
import platform
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import cryptography
import vodozemac

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cipherchat.crypto.identity import Identity  # noqa: E402
from cipherchat.crypto.key_exchange import public_key_bytes  # noqa: E402
from cipherchat.protocol.messages import EncryptedMessage  # noqa: E402
from cipherchat.protocol.session import SessionManager, rekey_pair  # noqa: E402

SIZES = (32, 1024, 16384)
SYSTEMS = ("CipherChat", "Matrix Olm", "Plaintext copy")


def cipher_pair():
    alice, bob = Identity.create("alice"), Identity.create("bob")
    a = SessionManager(alice, "bob", public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
    b = SessionManager(bob, "alice", public_key_bytes(alice.public_key), alice.signing_public_key_bytes)
    a.establish(b.public_key_bytes, bob.signing_public_key_bytes, session_id="benchmark-0", context=b"benchmark")
    b.establish(a.public_key_bytes, alice.signing_public_key_bytes, session_id="benchmark-0", context=b"benchmark")
    return a, b


def olm_pair():
    alice, bob = vodozemac.Account(), vodozemac.Account()
    bob.generate_one_time_keys(1)
    sender = alice.create_outbound_session(bob.curve25519_key, next(iter(bob.one_time_keys.values())))
    receiver, first = bob.create_inbound_session(alice.curve25519_key, sender.encrypt(b"first").to_pre_key())
    if first != b"first" or sender.decrypt(receiver.encrypt(b"ack")) != b"ack":
        raise AssertionError("Olm setup failed")
    return sender, receiver


def message(system: str, pair, payload: bytes):
    if system == "CipherChat":
        start = time.perf_counter_ns()
        wire = pair[0].sender.encrypt(payload.decode("ascii")).to_json().encode("utf-8")
        middle = time.perf_counter_ns()
        received = pair[1].receiver.decrypt(EncryptedMessage.from_json(wire.decode("utf-8"))).encode("utf-8")
    elif system == "Matrix Olm":
        start = time.perf_counter_ns()
        kind, wire = pair[0].encrypt(payload).to_parts()
        middle = time.perf_counter_ns()
        received = pair[1].decrypt(vodozemac.AnyOlmMessage.from_parts(kind, wire))
    else:
        start = time.perf_counter_ns()
        wire = bytes(bytearray(payload))
        middle = time.perf_counter_ns()
        received = bytes(bytearray(wire))
    end = time.perf_counter_ns()
    if received != payload:
        raise AssertionError(f"{system} returned incorrect plaintext")
    return ((middle - start) / 1000, (end - middle) / 1000, (end - start) / 1000, len(wire))


def p95(values):
    ordered = sorted(values)
    index = (len(ordered) - 1) * .95
    low = int(index)
    return ordered[low] + (ordered[min(low + 1, len(ordered) - 1)] - ordered[low]) * (index - low)


def environment():
    try:
        cpu = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        cpu = platform.processor() or platform.machine()
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"
    return {"utc_time": datetime.now(timezone.utc).isoformat(), "cpu": cpu, "os": platform.platform(),
            "python": platform.python_version(), "cryptography": cryptography.__version__,
            "vodozemac": importlib.metadata.version("vodozemac"), "git_commit": commit}


def collect(iterations: int, rounds: int, warmup: int, setups: int):
    data = {"environment": environment(), "parameters": {"iterations_per_round": iterations,
            "rounds": rounds, "warmup_per_round": warmup, "setup_samples": setups, "sizes": SIZES},
            "samples": [], "batch_throughput": [], "setup_samples": [], "rekey_samples": []}
    for size in SIZES:
        payload = b"x" * size
        for cycle in range(rounds):
            # Rotate order so the same system is not always measured first.
            for system in SYSTEMS[cycle % 3:] + SYSTEMS[:cycle % 3]:
                pair = cipher_pair() if system == "CipherChat" else olm_pair() if system == "Matrix Olm" else None
                for _ in range(warmup):
                    message(system, pair, payload)
                for _ in range(iterations):
                    enc, dec, total, wire_size = message(system, pair, payload)
                    data["samples"].append({"system": system, "size": size, "round": cycle + 1,
                                            "encrypt_us": round(enc, 3), "decrypt_us": round(dec, 3),
                                            "total_us": round(total, 3), "wire_bytes": wire_size})
                # The rate pass excludes per-message result recording.
                start = time.perf_counter_ns()
                for _ in range(iterations):
                    message(system, pair, payload)
                elapsed = time.perf_counter_ns() - start
                data["batch_throughput"].append({"system": system, "size": size, "round": cycle + 1,
                                                  "messages_per_second": iterations * 1e9 / elapsed})
                print(f"{size:5} B | round {cycle + 1}/{rounds} | {system}", flush=True)
    for system in SYSTEMS[:2]:
        for _ in range(setups):
            start = time.perf_counter_ns()
            pair = cipher_pair() if system == "CipherChat" else olm_pair()
            data["setup_samples"].append({"system": system, "us": (time.perf_counter_ns() - start) / 1000})
            if system == "CipherChat":
                start = time.perf_counter_ns()
                rekey_pair(*pair, session_id="benchmark-1", context=b"rekey-benchmark")
                data["rekey_samples"].append((time.perf_counter_ns() - start) / 1000)
                if pair[1].receiver.decrypt(pair[0].sender.encrypt("probe")) != "probe":
                    raise AssertionError("rekey failed")
    return data


def summarize(data):
    rows = []
    for size in SIZES:
        for system in SYSTEMS:
            items = [x for x in data["samples"] if x["system"] == system and x["size"] == size]
            rates = [x["messages_per_second"] for x in data["batch_throughput"]
                     if x["system"] == system and x["size"] == size]
            median = lambda field: round(statistics.median(x[field] for x in items), 3)
            wire = round(median("wire_bytes"))
            rows.append({"system": system, "payload_bytes": size, "samples": len(items),
                         "encrypt_median_us": median("encrypt_us"), "decrypt_median_us": median("decrypt_us"),
                         "roundtrip_median_us": median("total_us"),
                         "roundtrip_p95_us": round(p95([x["total_us"] for x in items]), 3),
                         "throughput_median_msg_s": round(statistics.median(rates), 1),
                         "wire_bytes_median": wire, "overhead_bytes": wire - size})
    return rows


def chart(rows, field, title, units, path):
    colors = {"CipherChat": "#238b45", "Matrix Olm": "#2171b5", "Plaintext copy": "#888"}
    maximum = max(row[field] for row in rows) * 1.12
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="440" viewBox="0 0 1000 440">',
             '<rect width="100%" height="100%" fill="white"/>',
             f'<text x="20" y="32" font-family="sans-serif" font-size="20">{title}</text>']
    for index, row in enumerate(rows):
        y = 65 + index * 30 + index // 3 * 14
        width = 690 * row[field] / maximum
        parts += [f'<text x="20" y="{y + 16}" font-family="sans-serif" font-size="13">{row["payload_bytes"]:,} B · {row["system"]}</text>',
                  f'<rect x="225" y="{y}" width="{width:.1f}" height="21" fill="{colors[row["system"]]}"/>',
                  f'<text x="{233 + width:.1f}" y="{y + 16}" font-family="sans-serif" font-size="13">{row[field]:,.1f} {units}</text>']
    path.write_text("\n".join(parts + ["</svg>"]) + "\n", encoding="utf-8")


def comparison_chart(rows, path):
    """Presentation chart with matching axes for send and receive operations."""
    lookup = {(row["system"], row["payload_bytes"]): row for row in rows}
    colors = {"CipherChat": "#187b4b", "Matrix Olm": "#2766b0"}
    x_scale = 400 / 350  # Same 0–350 µs scale in both panels.
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1360" height="850" viewBox="0 0 1360 850" role="img" aria-labelledby="title desc">',
        '<title id="title">CipherChat versus Matrix Olm: encryption and decryption by payload size</title>',
        '<desc id="desc">Two side-by-side horizontal bar charts on the same microsecond scale. CipherChat is faster for 16 KiB encryption, but Matrix Olm is faster for decryption at every size and for the full operation.</desc>',
        '<rect width="1360" height="850" fill="#ffffff"/>',
        '<text x="42" y="55" font-family="Arial,sans-serif" font-size="30" font-weight="700" fill="#15243a">CipherChat vs Matrix Olm</text>',
        '<text x="42" y="88" font-family="Arial,sans-serif" font-size="17" fill="#53657d">Median warm-session time · lower is faster · same scale in both panels</text>',
        '<rect x="42" y="111" width="20" height="17" rx="3" fill="#187b4b"/>',
        '<text x="71" y="125" font-family="Arial,sans-serif" font-size="16" fill="#15243a">CipherChat</text>',
        '<rect x="190" y="111" width="20" height="17" rx="3" fill="#2766b0"/>',
        '<text x="219" y="125" font-family="Arial,sans-serif" font-size="16" fill="#15243a">Matrix Olm (Rust binding)</text>',
    ]
    for panel_x, field, heading, explanation in (
        (42, "encrypt_median_us", "ENCRYPT + SERIALIZE", "Plaintext → protocol message"),
        (700, "decrypt_median_us", "PARSE + DECRYPT", "Protocol message → plaintext"),
    ):
        axis_x = panel_x + 175
        parts += [
            f'<rect x="{panel_x}" y="158" width="618" height="560" rx="14" fill="#f7f9fc" stroke="#dce3ec"/>',
            f'<text x="{panel_x + 22}" y="193" font-family="Arial,sans-serif" font-size="19" font-weight="700" fill="#15243a">{heading}</text>',
            f'<text x="{panel_x + 22}" y="218" font-family="Arial,sans-serif" font-size="14" fill="#53657d">{explanation}</text>',
        ]
        for tick in (0, 100, 200, 300):
            x = axis_x + tick * x_scale
            parts += [f'<line x1="{x:.1f}" y1="245" x2="{x:.1f}" y2="681" stroke="#dce3ec"/>',
                      f'<text x="{x:.1f}" y="701" text-anchor="middle" font-family="Arial,sans-serif" font-size="13" fill="#53657d">{tick}</text>']
        parts.append(f'<text x="{axis_x + 410}" y="701" font-family="Arial,sans-serif" font-size="13" fill="#53657d">µs</text>')
        for index, size in enumerate(SIZES):
            y = 264 + index * 145
            label = "32 B" if size == 32 else "1 KiB" if size == 1024 else "16 KiB"
            parts.append(f'<text x="{panel_x + 22}" y="{y + 34}" font-family="Arial,sans-serif" font-size="19" font-weight="700" fill="#15243a">{label}</text>')
            for offset, system in ((0, "CipherChat"), (42, "Matrix Olm")):
                value = lookup[(system, size)][field]
                width = value * x_scale
                bar_y = y + offset
                parts += [f'<rect x="{axis_x}" y="{bar_y}" width="{width:.1f}" height="28" rx="4" fill="{colors[system]}"/>',
                          f'<text x="{axis_x + width + 8:.1f}" y="{bar_y + 20}" font-family="Arial,sans-serif" font-size="15" font-weight="700" fill="#15243a">{value:.1f}</text>']
    cipher_big = lookup[("CipherChat", 16384)]
    olm_big = lookup[("Matrix Olm", 16384)]
    parts += [
        '<rect x="42" y="737" width="1276" height="76" rx="12" fill="#edf7f1"/>',
        f'<text x="62" y="768" font-family="Arial,sans-serif" font-size="18" font-weight="700" fill="#145d38">16 KiB finding: CipherChat encrypts faster ({cipher_big["encrypt_median_us"]:.1f} vs {olm_big["encrypt_median_us"]:.1f} µs).</text>',
        f'<text x="62" y="795" font-family="Arial,sans-serif" font-size="17" fill="#24445a">Olm still completes encrypt + decrypt faster ({olm_big["roundtrip_median_us"]:.1f} vs {cipher_big["roundtrip_median_us"]:.1f} µs).</text>',
        '</svg>',
    ]
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def method_chart(path):
    """A slide-sized diagram of exactly what the harness times."""
    boxes = [
        (42, "Choose payload", "32 B · 1 KiB · 16 KiB"),
        (294, "Warm the session", "50 messages / round"),
        (546, "Time send side", "encrypt + serialize"),
        (798, "Time receive side", "parse + decrypt"),
        (1050, "Check & summarize", "match bytes · median · p95"),
    ]
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1320" height="300" viewBox="0 0 1320 300" role="img" aria-labelledby="title desc">',
             '<title id="title">CipherChat benchmark measurement flow</title>',
             '<desc id="desc">Payload sizes enter a warm session, then encrypt and serialize, parse and decrypt, verify plaintext and summarize timings. Network and UI are excluded.</desc>',
             '<rect width="1320" height="300" fill="white"/>',
             '<text x="42" y="43" font-family="Arial,sans-serif" font-size="27" font-weight="700" fill="#15243a">What the benchmark measures</text>']
    for index, (x, title, subtitle) in enumerate(boxes):
        parts += [f'<rect x="{x}" y="89" width="220" height="112" rx="12" fill="#f0f5fb" stroke="#9eb7d2"/>',
                  f'<text x="{x + 14}" y="125" font-family="Arial,sans-serif" font-size="17" font-weight="700" fill="#15243a">{title.replace("&", "&amp;")}</text>',
                  f'<text x="{x + 14}" y="158" font-family="Arial,sans-serif" font-size="14" fill="#385a76">{subtitle.replace("&", "&amp;")}</text>']
        if index < len(boxes) - 1:
            parts += [f'<line x1="{x + 222}" y1="145" x2="{x + 245}" y2="145" stroke="#2766b0" stroke-width="3"/>',
                      f'<polygon points="{x + 245},139 {x + 252},145 {x + 245},151" fill="#2766b0"/>']
    parts += ['<text x="42" y="252" font-family="Arial,sans-serif" font-size="17" fill="#53657d">5 rounds × 300 timed messages per system and size; throughput uses a separate batch.</text>',
              '<text x="42" y="280" font-family="Arial,sans-serif" font-size="17" fill="#9a3e32">No network, browser, relay, or disk I/O in the timed message path.</text>', '</svg>']
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def export_png_if_available(svg_path):
    """Also make a slide-friendly PNG on macOS; SVG remains portable."""
    if shutil.which("sips"):
        subprocess.run(["sips", "-s", "format", "png", str(svg_path), "--out",
                        str(svg_path.with_suffix(".png"))], check=True, stdout=subprocess.DEVNULL)


def presentation_guide(data, rows):
    lookup = {(row["system"], row["payload_bytes"]): row for row in rows}
    c32, o32 = lookup[("CipherChat", 32)], lookup[("Matrix Olm", 32)]
    c1, o1 = lookup[("CipherChat", 1024)], lookup[("Matrix Olm", 1024)]
    c16, o16 = lookup[("CipherChat", 16384)], lookup[("Matrix Olm", 16384)]
    return f"""# How to present the performance benchmark

These notes use the saved run from {data['environment']['utc_time']}. Put [encryption_decryption_comparison.svg](encryption_decryption_comparison.svg) on the main result slide and [benchmark_method.svg](benchmark_method.svg) on the method slide. On macOS, the harness also exports PNG copies for slide editors. Use only numbers from this run.

## Slide 1 — Question and comparator

**Say:** “We measured how much processing and message expansion CipherChat adds, then compared its warm one-to-one message path with Matrix Olm's Rust `vodozemac` implementation through Python bindings. A plaintext byte copy is an insecure lower-bound control.”

Both systems ran on the same {data['environment']['cpu']} using Python {data['environment']['python']}. CipherChat's protocol and JSON work are Python; `cryptography` supplies native primitives. Olm's message work is in Rust. The original C/C++ Olm implementation was not tested.

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

- **32 B:** CipherChat encrypt/serialize is {c32['encrypt_median_us']:.1f} µs versus Olm {o32['encrypt_median_us']:.1f} µs. The message is tiny, so fixed per-message work matters most.
- **1 KiB:** CipherChat's full operation is {c1['roundtrip_median_us']:.1f} µs versus Olm {o1['roundtrip_median_us']:.1f} µs, about {c1['roundtrip_median_us']/o1['roundtrip_median_us']:.1f}× the time in this run.
- **16 KiB:** CipherChat encrypt/serialize is **{c16['encrypt_median_us']:.1f} µs**, faster than Olm's **{o16['encrypt_median_us']:.1f} µs** ({(1-c16['encrypt_median_us']/o16['encrypt_median_us'])*100:.0f}% lower measured time). Its parse/decrypt time is **{c16['decrypt_median_us']:.1f} µs**, slower than Olm's **{o16['decrypt_median_us']:.1f} µs**. The full operation remains slower for CipherChat: **{c16['roundtrip_median_us']:.1f} versus {o16['roundtrip_median_us']:.1f} µs**.

**Say:** “Our 16 KiB result is better on the **send side only**. The receive side reverses the result, so Olm still wins the complete operation. We cannot conclude CipherChat is faster overall.”

## Slide 5 — Why the numbers may differ

- CipherChat constructs metadata, signs each message, Base64-encodes binary fields, and serializes a full JSON envelope. Its receiver parses JSON, decodes Base64, validates fields, verifies the signature, and decrypts. These are plausible contributors to its higher small-message cost.
- CipherChat's 16 KiB send result is faster in this one run, but the benchmark does not isolate AES, signatures, ratcheting, encoding, or language runtime. Do not claim a single proven cause.
- CipherChat's 16 KiB full JSON envelope is {c16['wire_bytes_median']:,} B; Olm's binary body is {o16['wire_bytes_median']:,} B. Base64 contributes strongly to CipherChat's payload expansion, but a full Matrix network event would also add encoding and metadata.
- The plaintext copy has no encryption, authentication, signatures, or replay protection. It shows a rough lower bound, not an acceptable secure alternative.

## Slide 6 — Limits and conclusion

**Say:** “These are core-code measurements on one host, not port 8000 user-experience times. The systems have different security designs and different counted wire layers. A fairer follow-up would add a full Matrix event comparison, an end-to-end UI/transport test, and component profiling. Our result identifies where to investigate: especially CipherChat's receive path and JSON handling.”

**One-sentence conclusion:** “CipherChat's 16 KiB encryption path was faster in our sample, while Matrix Olm was faster at decryption and in the complete operation; our comparison is evidence for targeted profiling, not a claim of overall superiority.”
"""


def report(data, rows):
    env, params = data["environment"], data["parameters"]
    lines = ["# CipherChat performance benchmark", "", f'Run: {env["utc_time"]} · commit `{env["git_commit"]}`', "",
             "## Method", "", "Local, single-process benchmark of a warm one-to-one messaging session. "
             f'Payloads: 32 B, 1 KiB, 16 KiB. {params["rounds"]} rounds × {params["iterations_per_round"]} timed messages '
             f'per system and size, after {params["warmup_per_round"]} warm-up messages each round. '
             "The order rotates by round. Each message is checked for correct decryption. "
             "Median and p95 use individual `perf_counter_ns` timings; throughput uses a separate whole-batch pass. "
             "No network, relay, disk, browser, or UI time is included.", "",
             "The Matrix comparator is the Rust `vodozemac` Olm implementation called through Python bindings; "
             "the original C/C++ Olm library was not measured. Both paths run in the same Python interpreter. "
             "CipherChat's protocol and JSON work run in Python, using native cryptographic primitives through `cryptography`. "
             "The plaintext copy is an insecure lower-bound control, not a messaging alternative.", "",
             "## Environment", "", f'- CPU: {env["cpu"]}', f'- OS: {env["os"]}',
             f'- Python: {env["python"]}', f'- cryptography: {env["cryptography"]}',
             f'- vodozemac: {env["vodozemac"]}', "", "## Warm-session results", "",
             "| Payload | System | Encrypt median (µs) | Decrypt median (µs) | Round trip median / p95 (µs) | Throughput (msg/s) | Wire bytes / overhead |",
             "| ---: | --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in rows:
        lines.append(f'| {row["payload_bytes"]:,} B | {row["system"]} | {row["encrypt_median_us"]:,.1f} | '
                     f'{row["decrypt_median_us"]:,.1f} | {row["roundtrip_median_us"]:,.1f} / '
                     f'{row["roundtrip_p95_us"]:,.1f} | {row["throughput_median_msg_s"]:,.1f} | '
                     f'{row["wire_bytes_median"]:,} / +{row["overhead_bytes"]:,} |')
    one_kib = {row["system"]: row for row in rows if row["payload_bytes"] == 1024}
    cipher, olm = one_kib["CipherChat"], one_kib["Matrix Olm"]
    setup = {system: [x["us"] for x in data["setup_samples"] if x["system"] == system] for system in SYSTEMS[:2]}
    lines += ["", "## Findings", "",
              f'- At 1 KiB, CipherChat measured {cipher["roundtrip_median_us"]:,.1f} µs versus '
              f'{olm["roundtrip_median_us"]:,.1f} µs for Olm '
              f'({cipher["roundtrip_median_us"] / olm["roundtrip_median_us"]:.1f}× the time on this host).',
              f'- CipherChat produced {cipher["wire_bytes_median"]:,} JSON-envelope bytes; Olm produced '
              f'{olm["wire_bytes_median"]:,} binary-message bytes. These are different serialization layers.',
              "- Protocol, serialization, signature, and language costs are combined; this test does not attribute the gap to one component.",
              "", "## Session operations", "", "| Operation | Median (µs) | p95 (µs) |", "| --- | ---: | ---: |"]
    for system in SYSTEMS[:2]:
        values = setup[system]
        lines.append(f'| {system} new conversation setup | {statistics.median(values):,.1f} | {p95(values):,.1f} |')
    values = data["rekey_samples"]
    lines += [f'| CipherChat signed two-party rekey | {statistics.median(values):,.1f} | {p95(values):,.1f} |',
              "", "Setup includes different steps for each protocol and is not directly equivalent. Rekey excludes network delivery; a verified post-rekey message is excluded from timing.",
              "", "## Charts", "", "![Encryption and decryption comparison](encryption_decryption_comparison.svg)",
              "", "A PNG copy is also exported on macOS for slide editors.",
              "", "![Benchmark measurement flow](benchmark_method.svg)",
              "", "![Round-trip latency](roundtrip_latency.svg)", "", "![Wire overhead](wire_overhead.svg)",
              "", "For slide-by-slide definitions, speaker notes, and interpretation, see [PRESENTATION_GUIDE.md](PRESENTATION_GUIDE.md).",
              "", "## Limitations", "", "- This is one host and one Python process; measure real LAN and UI latency separately.",
              "- Olm uses a ratchet; CipherChat uses a fixed session key until explicit rekey and signs each message. These are different feature sets.",
              "- Olm wire bytes are the binary protocol body and exclude Matrix event JSON and transport metadata. CipherChat bytes are its full JSON envelope. No complete product-size ranking follows from this comparison.",
              "- The language difference is only one possible factor. Component profiling is needed to explain timing costs.",
              "- Raw timing samples contain no plaintext or key material: `results.json`; summary: `summary.csv`.",
              "", "## Reproduce", "", "```bash", "python3 -m venv benchmarks/.venv",
              "benchmarks/.venv/bin/python -m pip install -r benchmarks/requirements.txt",
              "benchmarks/.venv/bin/python benchmarks/run.py", "```", "",
              "Sources: [vodozemac Python bindings](https://github.com/matrix-nio/vodozemac-python), "
              "[Matrix vodozemac](https://github.com/matrix-org/vodozemac).", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--setups", type=int, default=100)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "results")
    args = parser.parse_args()
    if min(args.iterations, args.rounds, args.warmup, args.setups) < 1:
        parser.error("all counts must be positive")
    data = collect(args.iterations, args.rounds, args.warmup, args.setups)
    rows = summarize(data)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "results.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    with (args.output / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    chart(rows, "roundtrip_median_us", "Warm-session round trip median", "µs", args.output / "roundtrip_latency.svg")
    chart(rows, "overhead_bytes", "Wire overhead (different serialization layers)", "bytes", args.output / "wire_overhead.svg")
    comparison_chart(rows, args.output / "encryption_decryption_comparison.svg")
    method_chart(args.output / "benchmark_method.svg")
    export_png_if_available(args.output / "encryption_decryption_comparison.svg")
    export_png_if_available(args.output / "benchmark_method.svg")
    (args.output / "REPORT.md").write_text(report(data, rows), encoding="utf-8")
    (args.output / "PRESENTATION_GUIDE.md").write_text(presentation_guide(data, rows), encoding="utf-8")
    print(f"Report: {args.output / 'REPORT.md'}")


if __name__ == "__main__":
    main()
