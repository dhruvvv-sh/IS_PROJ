# Three-computer CipherChat demo

## Architecture

Alice's MacBook runs `mysql_cc`, the FastAPI backend, and `cloudflared`.
Vercel serves the existing HTML, CSS, and JavaScript. Its FastAPI function
forwards same-origin `/api/*` HTTP requests to Alice's backend through an HTTPS
tunnel when `CIPHERCHAT_API_UPSTREAM_URL` is set. Bob and Mallory only connect
to the Vercel URL. Their browsers never receive MySQL credentials or the proxy
secret. The frontend continues to poll every three seconds. There are no sockets.

Vercel's configurable upstream URL is the API base URL. Keeping the browser's
requests same-origin avoids cross-origin cookies and CORS configuration. The
central backend accepts `/api/*` only with the proxy secret from Vercel, and
returns 404 for other paths except its loopback-only `/health` readiness check. The MySQL port is bound to `127.0.0.1` in the
existing Docker container; the tunnel targets only port 8765.

## Alice's MacBook

The previous local `cipherchat` schema has a broken audit chain from an earlier
record-deletion demonstration. The new `cipherchat_central` schema is clean;
the old schema was left untouched. The local `.env.central` file is ignored by
Git and contains the local MySQL credentials, login passwords, and proxy secret.
For a fresh checkout, copy `.env.central.example` to `.env.central` and fill its secrets.

In separate terminals, run:

```bash
docker start mysql_cc
./scripts/start_central.sh
cloudflared tunnel --url http://127.0.0.1:8765
```

The backend listens on `0.0.0.0:8765` by default. Set `CIPHERCHAT_BIND_HOST`
or `CIPHERCHAT_BIND_PORT` in `.env.central` to change that. The startup script
runs the idempotent database migration before starting FastAPI. Keep the backend
and tunnel terminals open. A Cloudflare Quick Tunnel prints a temporary HTTPS
URL; it changes when restarted. For repeated demos, use a named tunnel with a
stable hostname. See [Cloudflare's Quick Tunnel guide](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

## Vercel

Import `/Users/satishshankar/Desktop/cipherchat-vercel-proxy.env` into the
existing Vercel project's Production environment. It contains:

- `CIPHERCHAT_API_UPSTREAM_URL`: the current HTTPS tunnel URL.
- `CIPHERCHAT_PROXY_SECRET`: the same secret as Alice's `.env.central`.

The import file is local and contains a secret; do not commit or share it. If
the Quick Tunnel URL changes, update only `CIPHERCHAT_API_UPSTREAM_URL` and
redeploy. Remove the old `CIPHERCHAT_MYSQL_*` variables from Vercel after the
proxy is working; only Alice's backend should hold database credentials.
Changing Vercel environment variables requires a new deployment, per
[Vercel's environment-variable guide](https://vercel.com/docs/environment-variables/managing-environment-variables).

## Roles and checks

Open `https://cipherchat-delta.vercel.app/` on three separate browser profiles
or devices. Alice logs in on her MacBook, Bob on another computer, and Mallory
on a third. Alice and Bob each generate their own private keys in their browser
profile. If a role was registered in another browser, its new browser cannot
recover the old private key. After logging in, choose **Create new identity and
chat**. The partner must compare the displayed fingerprint with the new
browser's fingerprint using another channel and explicitly approve it.
Old messages remain encrypted for the original browser.

1. Bob sends a message. Alice sees it after the next poll and the delivery
   status changes after her browser verifies it.
2. Alice and Bob can select a message to inspect its signed ciphertext,
   nonce, session ID, and signature.
3. Mallory selects the message and runs replay, tampering, impersonation,
   stale delivery, eavesdropping, and key-substitution tests. Alice and Bob see
   recorded incidents after the next poll.
4. Replay, tampering, and impersonation quarantine the chat. Alice or Bob can
   verify the incident and rekey. Failed verification blocks the relationship.
   Destructive audit-record deletion is disabled on the central
   deployment because it requires restoring the database.

The backend checks role permissions independently of the UI. A role has one
active login. Logging out releases it immediately; after a closed browser,
presence and the role lock expire in 30 seconds. A password holder can select
**Sign out the other session and continue** to take over immediately; the
previous browser's session becomes invalid.

## Verification and limits

The automated HTTP suite covers both send directions, delivery, authorization,
malformed input, every Mallory command, rekeying, and audit failure. Disposable
local MySQL tests cover actual inserts, role-lock concurrency, replay persistence,
all attack commands, and audit-chain verification. The production Vercel
environment must still be updated with the tunnel URL and secret to complete a
three-computer live demonstration.

Cloudflare Quick Tunnels are meant for testing. Alice's MacBook, Docker, the
backend, and the tunnel must stay running for Bob and Mallory to use the demo.
Do not share `.env.central`, the Vercel proxy import file, private browser keys,
or screenshots showing credentials.


## Terminal UI and repeatable runs

The realtime interface is served from `cipherchat/realtime/static/`. Fonts and
pixel icons are bundled locally. The separate `cipherchat.ui.server` teaching
interface is not the three-role browser chat.

Both first contact and changed identities require approval. Compare the 64-digit
identity fingerprint shown in the inspector using a separate channel. The browser
fingerprint binds both X25519 and Ed25519 public keys. Old browser pins from the
previous interface must be verified once again. Never approve a fingerprint just
because the application displays it.

Each role uses a separate browser profile or device. Browser storage is scoped to
the website, not to server accounts. A role password does not unlock a private key
from another profile. Existing verified public-key material is retained locally
per session so earlier conversations can remain readable after context rekeying.
History requiring lost private keys remains ciphertext.

Normal sends include `X-CipherChat-Request-Id` matching the signed message ID.
Retrying the exact same envelope as its authenticated sender returns its existing
receipt. Mallory replay simulations continue through replay detection and cause
quarantine. Delivery acknowledgement failures are retried separately from
signature verification and decryption.

An operator can start a fresh run after a deliberately blocked scenario:

```bash
python -m cipherchat.realtime.admin verify
python -m cipherchat.realtime.admin new-run --expected-session alice-bob:5
```

Replace the expected session with the current value shown in the UI. This command
verifies the audit, records an operator action, increments the encryption context,
and retains messages, identities, sequence counters, and incident evidence. It is
not a successful recovery of the blocked relationship and is not exposed to
Mallory as a browser action. A broken audit must be restored from its trusted
snapshot before starting a new run.

Destructive audit deletion requires BOTH `CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO=1`
and `CIPHERCHAT_DISPOSABLE_LAB=1`. Use a separate disposable database with a backup;
these flags do not create or verify a snapshot. Leave both flags at zero on the
shared persistent deployment. The UI hides deletion when it is unavailable.

## Migration and database privileges

Run `python -m cipherchat.realtime.admin migrate` before starting the updated API.
The migration adds an indexed `audit_number` to messages and backfills it from the
audit trail. History uses this immutable order so equal timestamps cannot skip
messages during pagination. Back up the database before a deployed migration.
The HTTP server no longer performs DDL during requests.

Configure the runtime `CIPHERCHAT_MYSQL_USER` with SELECT, INSERT, and UPDATE on
this lab schema and DELETE only on `cc_role_sessions` (logout). A database
administrator must provision these grants; changing environment variable names
alone does not change existing grants. Give the migration account the DDL rights
required to create and alter tables. Optional `CIPHERCHAT_MIGRATION_MYSQL_USER`
and `CIPHERCHAT_MIGRATION_MYSQL_PASSWORD` are read only by the migration command.
Supply them during the migration step and omit them from the running API process
where possible. The default MySQL image's bootstrap user has broad privileges;
replace or restrict it before using the deployment beyond a disposable lab.

Keep any account allowed to delete audit records confined to the disposable lab.
All browser roles use authenticated APIs, never database credentials. This is one
three-role lab; multiple independent teams need separate schemas/deployments.

## Local preview and verification

For localhost preview, use a disposable MySQL schema, migrate it, then run:

```bash
# Set in the local environment only:
# CIPHERCHAT_CENTRAL_ONLY=0
# CIPHERCHAT_COOKIE_SECURE=0
# CIPHERCHAT_MYSQL_HOST=127.0.0.1
python -m uvicorn app:app --host 127.0.0.1 --port 8765
```

Open `http://localhost:8765`. Remote devices require HTTPS for browser cryptography;
do not reuse the insecure localhost cookie setting in the HTTPS deployment.

```bash
pip install -e ".[dev,browser]"
python -m playwright install chromium
pytest
# Opt in using your shell's environment syntax:
# CIPHERCHAT_TEST_BROWSER=1 pytest tests/test_terminal_browser.py
# CIPHERCHAT_TEST_MYSQL=1 pytest tests/test_realtime_mysql.py
```

The MySQL suite must point to an empty disposable schema: its cleanup deletes test
rows. Browser tests use isolated browser contexts and an in-memory HTTP test
backend; run the MySQL suite separately to verify persistence. Screenshots are
written under `output/terminal-ui/`.
