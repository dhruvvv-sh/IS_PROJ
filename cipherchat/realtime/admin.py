"""Database migration and independent audit-checkpoint commands."""
import argparse
from pathlib import Path

from .database import Config, Database


def main(argv=None):
    parser = argparse.ArgumentParser(description="CipherChat realtime database administration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    sub.add_parser("verify")
    checkpoint = sub.add_parser("checkpoint")
    checkpoint.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    database = Database(Config.from_env())
    database.migrate()
    if args.command == "checkpoint":
        print(database.checkpoint(args.output))
    else:
        print(database.verify())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
