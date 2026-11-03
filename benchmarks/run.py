"""Local core benchmark: CipherChat, Matrix Olm, and an insecure copy control."""

from __future__ import annotations

import argparse
import csv
import importlib.metadata
import json
import platform
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
              "", "## Charts", "", "![Round-trip latency](roundtrip_latency.svg)", "", "![Wire overhead](wire_overhead.svg)",
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
    (args.output / "REPORT.md").write_text(report(data, rows), encoding="utf-8")
    print(f"Report: {args.output / 'REPORT.md'}")


if __name__ == "__main__":
    main()
