"""Database migration and independent audit-checkpoint commands."""
import argparse
import os
from dataclasses import replace
from pathlib import Path

from .database import Config, Database


def main(argv=None):
    parser = argparse.ArgumentParser(description="CipherChat realtime database administration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    sub.add_parser("verify")
    fresh = sub.add_parser("new-run", help="start a fresh lab context without deleting evidence")
    fresh.add_argument("--expected-session", required=True)
    checkpoint = sub.add_parser("checkpoint")
    checkpoint.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    config = Config.from_env()
    if args.command == "migrate" and os.getenv("CIPHERCHAT_MIGRATION_MYSQL_USER"):
        config = replace(config, user=os.environ["CIPHERCHAT_MIGRATION_MYSQL_USER"],
                         password=os.environ["CIPHERCHAT_MIGRATION_MYSQL_PASSWORD"])
    database = Database(config)
    if args.command == "migrate":
        database.migrate()
    if args.command == "new-run":
        print(database.start_new_run(args.expected_session))
    elif args.command == "checkpoint":
        print(database.checkpoint(args.output))
    else:
        print(database.verify())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
