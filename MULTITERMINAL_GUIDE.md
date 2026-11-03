# CipherChat three-person LAN lab

Alice, Bob, and Eva each run a Python process on their own laptop. Every person
opens the same styled UI at `http://127.0.0.1:8000` **on their own laptop**. Eva's
process also listens for Alice and Bob on TCP port `8765`.

```text
Alice browser → Alice local Python app → Eva relay → Bob local Python app → Bob browser
                                         ↑
                                  Eva local browser
```

The relay forwards signed, encrypted message envelopes. Alice and Bob hold
their own private keys, decrypt locally, and keep their own evidence logs. The
relay requires a signed join challenge before assigning either participant's
connection. Each participant checks the other's public keys against the files
exchanged separately. The current one-process UI remains available with
`python -m cipherchat.ui.server`. Stop it before starting a lab UI on the same
port.

## 1. Set up all three laptops

Copy this repository to each laptop. From its project directory, run:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

All laptops must be on the same LAN. Find Eva's LAN address (for example,
`192.168.1.10`). Alice and Bob will use that address, never `127.0.0.1`, for
the relay connection. Allow inbound TCP `8765` to Eva's laptop in its firewall.

## 2. Create and exchange public keys

Alice runs on her laptop:

```bash
python -m cipherchat.multiterminal.keys --role alice
```

Bob runs on his laptop:

```bash
python -m cipherchat.multiterminal.keys --role bob
```

Each command creates a **private** identity file and a shareable **public**
file in `.cipherchat-lab/`. Alice gives Bob `alice-public.json`; Bob gives Alice
`bob-public.json`. Place the received public file in the same directory on
each laptop. Compare the two printed SHA-256 fingerprints with the copy on the
other laptop. For example, Alice runs
`python -m cipherchat.multiterminal.keys --role bob --show-public .cipherchat-lab/bob-public.json`
and reads its output against Bob's original output through a trusted channel
before starting the chat. Keep `*-private.json` on its owner's laptop. Reuse these files on later
runs; the key command intentionally refuses to overwrite them.

## 3. Start Eva's relay and attacker UI

Eva runs:

```bash
. .venv/bin/activate
python -m cipherchat.multiterminal.relay --host 0.0.0.0 --port 8765 --ui-port 8000
```

Eva opens `http://127.0.0.1:8000`. The relay address shown to Alice and Bob is
`http://EVA_LAN_IP:8765`, with `EVA_LAN_IP` replaced by Eva's actual LAN IP.

## 4. Start Alice and Bob

Alice runs on her laptop:

```bash
. .venv/bin/activate
python -m cipherchat.multiterminal.participant \
  --role alice \
  --identity .cipherchat-lab/alice-private.json \
  --peer .cipherchat-lab/bob-public.json \
  --relay http://EVA_LAN_IP:8765 \
  --ui-port 8000
```

Bob runs on his laptop:

```bash
. .venv/bin/activate
python -m cipherchat.multiterminal.participant \
  --role bob \
  --identity .cipherchat-lab/bob-private.json \
  --peer .cipherchat-lab/alice-public.json \
  --relay http://EVA_LAN_IP:8765 \
  --ui-port 8000
```

Alice and Bob each open `http://127.0.0.1:8000` on their own laptop. The UI
keeps the existing chat, attacker, and audit styling. Each participant sees
their own chat screen and audit screen; Eva sees the attacker and audit screens.
Refresh if a page was open before its process started.

## Demonstration sequence

1. Alice sends a message. Bob sees it appear in his browser. Bob can reply.
2. Eva clicks **replay message** or a tampering control. The relay applies it to
   the last real encrypted envelope. The receiving participant records evidence
   and quarantines; a signed incident informs the other participant, who also
   quarantines.
3. Alice or Bob clicks **verify and rekey chat**. They exchange fresh signed
   X25519 public keys through the relay, invalidate the old sessions, and can
   send again when both sides finish.
4. Eva can run **replace peer key** or, after an incident, **delete evidence
   record (copy)**. These block the chat. **New session** starts over.

Eva cannot see Alice's or Bob's plaintext or private keys. The evidence
deletion control removes a record from a temporary copy on the participant's
laptop and checks that copy against its retained checkpoint; the original
evidence remains available for the audit screen.

## Running all roles on one computer

Use the same commands with `--relay http://127.0.0.1:8765`, and assign UI
ports `8001` for Alice, `8002` for Bob, and `8003` for Eva. Open each port in a
separate browser tab. Give each participant a separate identity directory and
copy the other's public file into it.

This is a classroom LAN demonstration. The local UI binds to `127.0.0.1`; the
relay binds to the selected LAN interface. Do not expose the relay to the
internet. The public pins must be exchanged independently of Eva's relay.
