# ParolNet Startup Guide

How to build and run your own ParolNet network from source.

**Current code status:** this guide describes the relay/PWA network that exists today plus some operational concepts from the protocol design. Before using this for real-world risk, read [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

---

## 1. What is ParolNet?

ParolNet is encrypted messaging infrastructure under active development. The current PWA sends encrypted payloads through a WebSocket relay and optional WebRTC data channels. The protocol design includes 3-hop onion relay circuits so no single relay can know both sides of a conversation, but that full routing path is not yet wired into normal PWA chat.

No tracking. No phone numbers. No registration. No names. Your identity is a cryptographic key that exists only on your device.

---

## 2. What You Need

**On your computer (for building):**

- Rust toolchain -- install from [https://rustup.rs](https://rustup.rs)
- `wasm-pack` -- install with: `curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh`
- Node.js (required by wasm-pack)
- the `denext` CLI, to build the web app: `curl -fsSL https://denext.dev/install.sh | sh`

**People:**

- 2 or 3 trusted people. Each one will hold one authority key.
- **These people must be on DIFFERENT machines.** Never put two authority keys on the same computer.
- **Never put authority keys on relay servers or in the PWA.**

**Servers (for relays):**

- 1 or more servers that can accept incoming connections. A VPS, a dedicated server, or even a home computer behind a router with port forwarding.

**For hosting the app:**

- Any way to serve static files over HTTPS for full PWA behavior. A USB stick or ZIP copy can be used for inspection or limited local use, but Service Worker installation requires HTTPS or `localhost`.

---

## 3. Generate Authority Keys

First, build the authority CLI tool:

```bash
cargo build --release -p parolnet-authority-cli
```

Then generate 3 keypairs:

```bash
./target/release/parolnet-authority init-network --count 3 --output-dir ./keys
```

This creates 6 files in `./keys/`:

| File | What it is | Who gets it |
|------|-----------|-------------|
| `authority-1.key` | Private key for authority 1 | Person 1 (KEEP SECRET) |
| `authority-1.pub` | Public key for authority 1 | Everyone (safe to share) |
| `authority-2.key` | Private key for authority 2 | Person 2 (KEEP SECRET) |
| `authority-2.pub` | Public key for authority 2 | Everyone (safe to share) |
| `authority-3.key` | Private key for authority 3 | Person 3 (KEEP SECRET) |
| `authority-3.pub` | Public key for authority 3 | Everyone (safe to share) |

The command prints output like this:

```
Authority 1: a1b2c3d4...  (64 hex characters)
Authority 2: e5f6a7b8...
Authority 3: c9d0e1f2...

Network ID: 1234abcd...
Authority count: 3

AUTHORITY_PUBKEYS=a1b2c3d4...,e5f6a7b8...,c9d0e1f2...

IMPORTANT: Distribute private key files to separate trusted people.
Each authority-N.key file should be held by a different operator.
Private keys must NEVER be placed on relay servers or in the PWA.
```

**Save the `AUTHORITY_PUBKEYS=...` line.** You need it for the next steps.

Give each `.key` file to a DIFFERENT trusted person. They must store it safely and never share it. The `.pub` files are public -- you can share them freely.

---

## 4. Build the PWA

The PWA (Progressive Web App, the web app in `web/`) is what your users will open in their browser. Building it bakes the authority public keys into its wasm core. Users who download this app can ONLY connect to relays endorsed by your authorities.

```bash
cd web
denext runtime install
AUTHORITY_PUBKEYS=KEY1,KEY2,KEY3 AUTHORITY_THRESHOLD=2 denext task build-wasm
denext task build
```

Replace `KEY1,KEY2,KEY3` with the actual hex public keys from the previous step (the `AUTHORITY_PUBKEYS` value, without the `AUTHORITY_PUBKEYS=` prefix). Empty keys mean the dev placeholder keys. The relay image (section 5, Option B) takes the same two values as build arguments and builds the app itself.

**Output:** Static files in `web/out`, to be served under `/pwa/`. This includes HTML, JavaScript, and a WASM binary. The app has no list of bootstrap relays: it uses the relay at the origin it was served from, and a person can name another in its settings.

---

## 5. Deploy Relay Servers

### Option A: Run the binary directly

Build the relay server:

```bash
cargo build --release -p parolnet-relay-server
```

Run it:

```bash
RELAY_PORT=9000 RELAY_PUBLIC_NAMES=relay.example.com ./target/release/parolnet-relay
```

`RELAY_PUBLIC_NAMES` is the host (and port, when it is not 443) that clients will dial this relay
under. A client signs its registration for the name it dialed and the relay refuses any other, so
a relay without it accepts only clients on the same machine (`localhost`, `127.0.0.1`).

### Option B: Run with Docker

A Dockerfile is included at the repository root. It builds the relay server and bundles it with Nginx to serve the PWA.

```bash
docker build -t parolnet-relay .
docker run -d -p 9000:80 \
  -e RELAY_PORT=9000 \
  -e RELAY_PUBLIC_NAMES=relay.example.com \
  parolnet-relay
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RELAY_PORT` | No | `9000` | Port the relay listens on. `0` lets the OS pick a free port. Once it serves, the relay prints `PAROLNET_RELAY_LISTENING=<addr>` (the address and port it bound) on stdout, at any log level. |
| `RELAY_PUBLIC_NAMES` | **Yes, on a public relay** | Loopback names only | Comma-separated `host` or `host:port` that clients dial this relay under; no port means 443. Example: `relay.example.com` for `wss://relay.example.com/ws`, `203.0.113.5:9000` for `ws://203.0.113.5:9000/ws`. A registration is signed for the dialed name and refused under any other (PNP-001 §10.7). Unset, only clients that dialed `localhost` / `127.0.0.1` / `[::1]` can register. A malformed entry stops the relay at startup. |
| `SIGNALING_ONLY` | No | `1` | `0` selects the relay profile (store-and-forward, tokens, federation, TURN credentials). The default serves signaling only. |
| `FEDERATION_PEER_KEYS` | No | Empty | Relay profile only. Comma-separated Ed25519 public keys (64 hex characters, the "Relay Ed25519 public key" a relay logs at startup) of the relays allowed to read this relay's `/peers/presence`. Empty means nobody is. |
| `RELAY_SECRET_KEY` | No | Random on each start | 64-char hex Ed25519 secret key for the relay's identity. Set this so the relay keeps the same PeerId across restarts. |
| `PEER_RELAY_URLS` | No | Empty | Comma-separated URLs of other relays for directory sync. Example: `https://relay2.example.com,https://relay3.example.com` |
| `ADMIN_TOKEN` | No | Empty | Secret token for admin endpoints |
| `CORS_ORIGINS` | No | Allow all | Comma-separated allowed CORS origins. Example: `https://app.example.com,https://backup.example.com` |
| `PAROLNET_ANALYTICS` | No | `0` | Set to `1` to enable the `/stats` endpoint (only works if built with `--features analytics`) |

### Get the relay's PeerId

When the relay starts, it prints its PeerId to the log:

```
Relay PeerId: 7a3f9b2c...  (64 hex characters)
```

**Save this PeerId.** You need it for the endorsement step.

If you did NOT set `RELAY_SECRET_KEY`, the PeerId changes every time the relay restarts. To keep a stable PeerId, generate a key and set it:

```bash
# Generate a random 32-byte hex key
openssl rand -hex 32
# Use the output as RELAY_SECRET_KEY
```

### Connect relays to each other

If you run more than one relay, they should know about each other for directory sync. Set `PEER_RELAY_URLS` on each relay, pointing to the other relays:

```bash
# On relay 1:
PEER_RELAY_URLS=https://relay2.example.com,https://relay3.example.com

# On relay 2:
PEER_RELAY_URLS=https://relay1.example.com,https://relay3.example.com
```

Relays sync their directory of endorsed relays every 60 seconds.

### Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/ws` | GET | WebSocket connection for messaging |
| `/health` | GET | Health check (returns "OK") |
| `/peers` | GET | List connected peers (operator only: needs `ADMIN_TOKEN`) |
| `/directory` | GET | Get the relay directory |
| `/endorse` | POST | Relay profile: submit an endorsed descriptor (CBOR body) |
| `/peers/presence`, `/peers/lookup` | GET | Relay profile: who is online, to signed requests only (PNP-008 §10.8). Not served by a signaling-only relay |
| `/bootstrap` | GET | Always `[]` (kept for older clients) |

---

## 6. Endorse Relays

A relay is not trusted until enough authorities endorse it. With a threshold of 2, at least 2 of your 3 authority holders must each create an endorsement for each relay.

An endorsement signs one **relay descriptor**: the relay's keys, address and timestamp, with the relay's own signature (PNP-008-MUST-002). It is valid for that descriptor only, and for as long as the descriptor is: seven days from its timestamp. A relay that publishes a new descriptor (a new address, new keys, or simply a newer timestamp) needs new endorsements, so plan for authorities to sign at least once a week per relay.

### Create an endorsement

Get the descriptor to endorse, for example from the relay's directory:

```bash
curl -s http://relay-address:9000/directory -o directory.cbor
```

Each authority holder runs this on their own machine (where their `.key` file is stored):

```bash
./target/release/parolnet-authority endorse-relay \
  --descriptor directory.cbor \
  --relay-peer-id RELAY_PEER_ID_HEX \
  --authority-key ./authority-1.key \
  --output endorsement-auth1.cbor
```

Replace:
- `directory.cbor` with the file holding the descriptor (one CBOR `RelayDescriptor`, or a list of them as `/directory` returns)
- `RELAY_PEER_ID_HEX` with the 64-character hex PeerId from the relay's startup log (it selects the descriptor in a list, and is checked against a single one)
- `./authority-1.key` with the path to that authority's private key file

The command refuses a descriptor that the relay's own key did not sign or that is older than seven days. It creates a CBOR-encoded endorsement file and prints what it endorsed to stderr; read it back before publishing:

```
Endorsement written to: endorsement-auth1.cbor
Endorsement (hex): a2...
Authority pubkey:  a1b2c3d4...
Relay PeerId:      7a3f9b2c...
Relay key:         5e6f...
Relay address:     203.0.113.5:9000
Descriptor time:   1713168000 (unix)
Valid until:       1713772800 (unix; the descriptor's seven days)
```

### Submit the endorsed descriptor to the relay

The relay's `/endorse` endpoint (relay profile) takes an `EndorsedDescriptor`: a CBOR map `{descriptor, endorsements}` holding the descriptor and at least the threshold number of endorsements of it.

```bash
curl -X POST http://relay-address:9000/endorse \
  --data-binary @endorsed-descriptor.cbor \
  -H "Content-Type: application/cbor"
```

### Verify an endorsement

You can check an endorsement against its descriptor at any time:

```bash
./target/release/parolnet-authority verify-endorsement \
  --endorsement endorsement-auth1.cbor \
  --descriptor directory.cbor \
  --relay-peer-id RELAY_PEER_ID_HEX
```

This shows the authority, the descriptor and whether the signature is valid for it.

---

## 7. Verify Everything Works

1. **Check the relay directory.** Open in a browser or use curl:

   ```bash
   curl http://relay-address:9000/directory
   ```

   You should see your relay listed with its endorsements.

2. **Check relay health:**

   ```bash
   curl http://relay-address:9000/health
   ```

   Should return `OK`.

3. **Open the PWA in a browser.** Go to wherever you hosted the PWA files. The app should load and connect to your relay.

4. **Send a test message.** Open the PWA on two devices. Create identities on both. Exchange contact information (QR code or passphrase). Send a message from one to the other.

---

## 8. Host the PWA

The PWA is just static files: HTML, JavaScript, and a WASM binary. You can host it anywhere that serves files over HTTPS.

**Options:**

- **Any web server:** Nginx, Apache, Caddy -- serve `web/out` under `/pwa/` with the headers in `web/nginx.example.conf` (the Content-Security-Policy, cache rules, `application/wasm`)
- **Cloudflare Pages:** Upload `web/out` (with the same headers)
- **GitHub Pages:** Push `web/out` to a GitHub repository with Pages enabled (Pages cannot set custom headers, so the Content-Security-Policy header is not sent)
- **IPFS:** `ipfs add -r web/out` -- decentralized and hard to take down
- **USB stick / ZIP file:** Copy or zip `web/out` for someone to re-host. The app does not run from `file://`; installable PWA behavior requires HTTPS or `localhost`.

**The PWA can cache app assets after the first load.** Once a user installs it as a Progressive Web App, cached copies can keep opening if the host disappears. Sending new messages still requires a reachable relay, direct WebRTC connection, or future mesh path.

Users install it by visiting the URL in their browser and clicking "Install" or "Add to Home Screen."

---

## 9. Day-to-Day Operations

**Adding a new relay:**
Endorse it (step 6). Once enough authorities have endorsed it and the endorsements are submitted, it syncs with existing relays automatically via directory sync.

**Removing a relay:**
Let its endorsement expire. Do not re-endorse it. After the expiration date passes, it is no longer trusted.

**An authority key holder disappears:**
With a 2-of-3 threshold, the network still works. Any 2 of the 3 remaining authorities can endorse relays. If you drop to only 1 authority, you cannot endorse new relays until you set up a new network with new keys.

**App update needed:**
Rebuild the PWA with the same public keys (`--pubkeys` must be the same). Re-host it. Users who visit the URL will get the update automatically. The network identity stays the same because the same authority keys are used.

**Relay address changes:**
Relay addresses are not baked into the app unless you used `--bootstrap-relays`. The current implementation also falls back to same-origin `/ws`. Relay directory sync is simple polling of configured `PEER_RELAY_URLS`, not the full PNP-008 federation design.

---

## 10. Emergency: Source Code Taken Down

If the website or source code is removed:

1. **Users export their data.** In the app: Settings -> Data Backup -> Export. The export file is encrypted and looks like random data. Safe to carry on a USB stick.

2. **Someone re-hosts the PWA.** From a backup, a mirror, or by rebuilding from source. If you have a copy of the built `web/out` directory, you can host it again immediately.

3. **Same authority public keys = same network.** As long as you build with the same `--pubkeys`, users' data is compatible. Nothing changes for them.

4. **Users import their data.** Open the new app, go to Settings -> Data Backup -> Import. Select the export file.

5. **Network continues as before.** All contacts, messages, and keys are restored.

**Preparation:** Keep a backup of:
- The source code (git clone)
- A built copy of the `web/out` directory
- The `.pub` files (authority public keys)
- The `AUTHORITY_PUBKEYS` string

Do NOT backup `.key` files together. Each authority holder backs up their own key separately.

---

## 11. Security Reminders

- **Authority `.key` files: treat like nuclear launch codes.** Separate people, separate machines, separate physical locations. If an attacker gets 2 of 3 keys, they can endorse fake relays.

- **Never put `.key` files on relay servers.** Never put them in the PWA. Never put them in a git repository. Never email them.

- **The export file is encrypted.** It looks like random data. Safe to carry on a USB stick, send through email, or store in cloud storage. Without the user's password, it is unreadable.

- **Messages are end-to-end encrypted after a secure session exists.** Relay operators should not be able to read encrypted message content. The current relay can still observe sender/recipient PeerIds, timing, and message volume.

- **PeerId = SHA-256(public_key).** There are no names, no phone numbers, no email addresses, nothing identifying in the system. Even relay operators do not know who their users are.

- **Padding exists in the protocol library.** The current PWA relay path does not yet apply the full fixed-cell, constant-rate padding design end to end.

- **Cover traffic is a protocol design target.** It is not yet implemented end to end in the current PWA relay path.

- **If your device is seized:** Use the panic wipe feature (if available in your build) to erase all keys and messages instantly.
