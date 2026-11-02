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
returns 404 for all other paths. The MySQL port is bound to `127.0.0.1` in the
existing Docker container; the tunnel targets only port 8765.

## Alice's MacBook

The previous local `cipherchat` schema has a broken audit chain from an earlier
record-deletion demonstration. The new `cipherchat_central` schema is clean;
the old schema was left untouched. The local `.env.central` file is ignored by
Git and contains the local MySQL credentials, login passwords, and proxy secret.
For a fresh checkout, copy `.env.example` to `.env.central` and fill its secrets.

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
profile. If a role's identity was registered from another browser earlier, that
new browser cannot recover its old private key; use the original profile or a
fresh demo database.

1. Bob sends a message. Alice sees it after the next poll and the delivery
   status changes after her browser verifies it.
2. Alice and Bob can select a message to inspect its signed ciphertext,
   nonce, session ID, and signature.
3. Mallory selects the message and runs replay, tampering, impersonation,
   stale delivery, eavesdropping, and key-substitution tests. Alice and Bob see
   recorded incidents after the next poll.
4. Replay, tampering, and impersonation block the chat. Alice or Bob can start
   a new session. Destructive audit-record deletion is disabled on the central
   deployment because it requires restoring the database.

The backend checks role permissions independently of the UI. A role has one
active login. Logging out releases it immediately; after a closed browser,
presence and the role lock expire in 30 seconds.

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
