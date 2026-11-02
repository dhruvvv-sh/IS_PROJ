# CipherChat on Vercel

For the three-computer simulation where Alice's MacBook owns MySQL and the API,
use [CENTRAL_PC_SETUP.md](CENTRAL_PC_SETUP.md). The instructions below describe
the alternative direct Vercel-to-managed-MySQL setup.

The app exports `app` from the root `app.py`, which Vercel detects as a FastAPI
entry point. Its transport is HTTP only. The browser requests new messages and
security events every three seconds. A shared, persistent MySQL database is
required because Vercel function instances do not share memory or local files.
The database also holds one active login per role. Presence expires after 30
seconds without requests, so a role can log in elsewhere after a closed browser
times out. Logging out frees the role immediately. A browser tab lock prevents
duplicate tabs in the same browser profile where Web Locks is supported.

## Prepare the database

Provision a MySQL 8 database reachable from Vercel, create a database and user.
The app creates its tables on its first database request. You can also run the
migration manually from a machine that can reach the database:

```bash
python -m cipherchat.realtime.admin migrate
```

Set the environment variables below for the migration and in Vercel Project
Settings → Environment Variables. Use distinct, strong passwords and a random
session secret of at least 32 characters. Do not commit them.

| Variable | Purpose |
| --- | --- |
| `CIPHERCHAT_MYSQL_HOST` | MySQL host |
| `CIPHERCHAT_MYSQL_PORT` | MySQL port, usually `3306` |
| `CIPHERCHAT_MYSQL_DATABASE` | Database name |
| `CIPHERCHAT_MYSQL_USER` | Database user |
| `CIPHERCHAT_MYSQL_PASSWORD` | Database password |
| `CIPHERCHAT_SESSION_SECRET` | Signs login cookies |
| `CIPHERCHAT_ALICE_PASSWORD` | Alice login |
| `CIPHERCHAT_BOB_PASSWORD` | Bob login |
| `CIPHERCHAT_MALLORY_PASSWORD` | Mallory login |
| `CIPHERCHAT_COOKIE_SECURE` | Set to `1` on Vercel |

Import this repository into Vercel as a Python/FastAPI project and deploy it.
The included `.python-version` selects Python 3.12. Set the project root to the
repository root. Open the deployment URL in three separate browser profiles and
log in. Each profile must retain its IndexedDB keys; losing them makes old
messages undecryptable. Public keys are pinned on first contact in the browser.

## Recovery and limits

Replay, tampering, or impersonation records an event and blocks the current chat.
Alice or Bob can click **Start new chat / rekey**. A new session ID changes the
HKDF context, so subsequent messages use a different AES key. The X25519 identity
keys remain the same. Old ciphertext and evidence remain in the database.

Audit record deletion is a separate destructive lab demonstration, disabled by
default. It corrupts the audit chain and cannot be recovered by rekeying; restore
the database from a trusted backup. Do not enable
`CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO` on a shared deployment.

The app verifies the audit chain during sends and dashboard reads. Its database
head and records share the same trust boundary. For an independent checkpoint,
use `python -m cipherchat.realtime.admin checkpoint --output ...` and keep the
result outside the database. The current checkpoint setting reads a local file,
so it is intended for a persistent host rather than Vercel functions.

This is a teaching app. First-contact public-key trust depends on authenticated
registration, and a compromised server at first contact can mislead the browser.
