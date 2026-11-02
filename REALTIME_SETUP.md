# CipherChat deployment

The application now uses HTTP requests and periodic refreshes. It has no WebSocket endpoint. See [VERCEL_SETUP.md](VERCEL_SETUP.md) for database setup, environment variables, deployment, and recovery behavior.

For local development, set the variables in `.env.example`, run `python -m cipherchat.realtime.admin migrate`, then start `uvicorn app:app --host 127.0.0.1 --port 8765`. Open the local URL in separate browser profiles for Alice, Bob, and Mallory.
