# M1, first slice: headless core and desktop chat

Status of the first M1 step (plan: `plans/parolnet-gpui.md` M1, revised for the signaling-only
relay). What runs, how it is tested, what it does not do yet.

## What runs end to end

- **Two `parolnet-app` instances against the relay binary in its default signaling-only profile**
  (`crates/parolnet-app/tests/two_peers.rs`): register by challenge; pair with the PWA's QR
  payload (presenter shows the code, scanner enters it); the scanner offers, the presenter accepts
  because its pairing window is open; the `parolnet` data channel opens; the bootstrap envelope
  materializes the presenter's session; chat flows both ways as PNP-001 TEXT envelopes; one side
  shuts down, the other's message waits in its sender queue; the first side restarts from its
  data directory (identity, contact, ratchet session restored), the relay's presence push tells
  the other side, the queue flushes. A second test checks that an offer from a stranger is
  ignored (answering would show the IP address).
- **Desktop UI v0** (`apps/desktop`, default mode): contact list with path badges, pairing screen
  (QR code of our code, the code as text with a copy button, code entry), chat view with delivery
  state (waiting / not sent), rename, retry, and the status line: "Direct connection",
  "Connecting", "Waiting for <name> to come online (n messages waiting)", "No direct path to
  <name>. Either side can add a TURN server in Settings." The window itself was not opened on the
  dev Mac (no GUI windows there); it compiles and its pure helpers are unit-tested. The M0 video
  view stays behind `--spike`.
- `cargo run -p parolnet-app --example bot -- --relay ws://HOST/ws --data-dir DIR` is a headless
  peer (JSON lines out, `send` / `code` / `pair` commands in) for scripts and the interop test.

## Interoperability with the PWA

By construction for the content layer: the app calls the same `parolnet-core` functions the
PWA's wasm calls (`generate_qr_payload_with_ratchet`, `process_qr` + `establish_session`,
`encrypt_for_peer` / `decrypt_for_peer`, `try_bootstrap_and_decrypt`), and sends the same relay
frames and data-channel JSON (`{"type":"identity","peerId"}`, `{"type":"chat","payload":<hex>}`,
text PPID). The wire-format unit tests pin those shapes against what `pwa/src/webrtc.js` sends.

Not yet proven against a real browser: the WebRTC layer between `webrtc-rs-rtc` and Chromium for
a data-channel-only connection (M0 proved Chromium → engine media). Known risks:

- Chromium hides host addresses behind mDNS (`*.local`) candidates; the engine does not resolve
  them yet, so two peers on one LAN may need srflx (hairpin NAT) or the mDNS work.
- The PWA's "Paste Code" tab (`connectViaPassphrase`) extracts only a peer id and does not
  establish a session; only its camera scan path (`handleScannedQR`) pairs. Desktop → PWA pairing
  by pasting needs that fixed in the PWA.

The interop test is a stub with its plan: `apps/desktop/interop/pwa-chat.mjs` (bot + PWA in
headless Chromium against a local relay, three cases). It needs `wasm-pack` for the PWA build.

## Not in this slice

- Data-channel DTLS fingerprint binding in the first ratchet message (needs the PWA side too).
- TURN candidates for a user-supplied TURN server (`rtc-turn` in `parolnet-rtc`); IPv6 host
  candidates and several sockets; ICE restart on network change (E9).
- Safety numbers, `parolnet-store` (SQLCipher, key in the OS keychain: today's JSON state file is
  owner-only but not encrypted), files (PNP-010), calls, multi-device.

## Next slice

1. The PWA interop test for real (wasm-pack on the linux pool; both pairing directions; fix the
   PWA paste path), plus mDNS candidate resolution or a documented flag.
2. Fingerprint binding on the data channel (desktop and PWA together), safety numbers.
3. `parolnet-store` behind the same `Store` interface; settings screen with the user's TURN
   server once `parolnet-rtc` gathers TURN candidates.
4. Calls: the spike's receive path becomes `parolnet-call` 1:1, call signals over the data channel.
