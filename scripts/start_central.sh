#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
set -a
. ./.env.central
set +a
PYTHON_BIN="${CIPHERCHAT_PYTHON:-.venv/bin/python}"
"$PYTHON_BIN" -m cipherchat.realtime.admin migrate
exec "$PYTHON_BIN" -m uvicorn app:app --host "${CIPHERCHAT_BIND_HOST:-0.0.0.0}" --port "${CIPHERCHAT_BIND_PORT:-8765}"
