"""Persistent participant identities and public pin files for the LAN lab."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from cipherchat.crypto.identity import Identity


def create_files(role: str, directory: Path) -> tuple[Path, Path]:
    if role not in {"alice", "bob"}:
        raise ValueError("role must be alice or bob")
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / f"{role}-private.json"
    public_path = directory / f"{role}-public.json"
    if private_path.exists() or public_path.exists():
        raise FileExistsError(f"identity files already exist in {directory}; keep using those files")
    identity = Identity.create(role)
    private_path.touch(mode=0o600, exist_ok=False)
    private_path.write_text(json.dumps({
        "identity_id": role,
        "x25519_private_key": identity.private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        ).hex(),
        "ed25519_private_key": identity.signing_private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        ).hex(),
    }, indent=2), encoding="utf-8")
    public_path.write_text(json.dumps(identity.public_material(), indent=2), encoding="utf-8")
    return private_path, public_path


def load_identity(path: Path, expected_role: str) -> Identity:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("identity_id") != expected_role:
        raise ValueError(f"identity file must belong to {expected_role}")
    return Identity(expected_role,
                    X25519PrivateKey.from_private_bytes(bytes.fromhex(data["x25519_private_key"])),
                    Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["ed25519_private_key"])))


def load_peer(path: Path, expected_role: str) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("identity_id") != expected_role:
        raise ValueError(f"peer public file must belong to {expected_role}")
    if not all(isinstance(data.get(name), str) and len(data[name]) == 64
               for name in ("public_key", "signing_public_key")):
        raise ValueError("peer public file must contain 32-byte X25519 and Ed25519 keys")
    bytes.fromhex(data["public_key"])
    bytes.fromhex(data["signing_public_key"])
    return data


def print_fingerprints(data: dict[str, str]) -> None:
    print(f"{data['identity_id']} X25519: {hashlib.sha256(bytes.fromhex(data['public_key'])).hexdigest()}")
    print(f"{data['identity_id']} Ed25519: {hashlib.sha256(bytes.fromhex(data['signing_public_key'])).hexdigest()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a participant identity and shareable public pin file")
    parser.add_argument("--role", choices=("alice", "bob"), required=True)
    parser.add_argument("--directory", type=Path, default=Path(".cipherchat-lab"))
    parser.add_argument("--show-public", type=Path, help="Print fingerprints from an existing public pin file")
    args = parser.parse_args()
    if args.show_public:
        print_fingerprints(load_peer(args.show_public, args.role))
        return
    private_path, public_path = create_files(args.role, args.directory)
    print(f"Private identity (keep on this laptop): {private_path}")
    print(f"Public pin file (give to the other participant): {public_path}")
    print_fingerprints(load_peer(public_path, args.role))


if __name__ == "__main__":
    main()
