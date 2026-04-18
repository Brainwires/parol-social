# PWA end-to-end tests (Puppeteer)

Three-browser-context harness exercising the golden paths that unit tests can't
reach: WebRTC signaling, PNP-007 file transfer, PNP-009 group calls, TURN
round-trip through a compose `coturn` container.

## Why a separate test family

The unit suite (`pwa/tests/unit.test.mjs`) covers the JS modules in isolation,
stubbing WASM / IndexedDB / WebSocket. That catches logic regressions but not
WebRTC handshake bugs, codec regressions, or TURN credential drift. The E2E
suite drives three actual Chromium tabs against a local relay-server + coturn
so the signaling layer runs against its production transport.

## Running

```bash
# One-time: install puppeteer (200+ MB Chromium download).
cd pwa && npm install --save-dev puppeteer

# Separate shell: start the relay stack.
docker compose up -d relay coturn

# Back in pwa/:
npm run test:e2e
```

The harness boots three isolated browser contexts, registers distinct peer IDs
in each, exchanges QR codes programmatically, and runs:

1. **Golden-path text**: Alice → Bob direct WebRTC, Alice → Carol via relay.
2. **File transfer (PNP-007)**: Alice uploads a 2 MiB blob to Bob; reassembly
   exercises fragmentation (PNP-001 §3.9).
3. **1:1 call**: Alice calls Bob, both ICE-gather through coturn TURN, teardown
   verifies no lingering peer connections.
4. **Group call (PNP-009)**: Alice, Bob, Carol join a 3-person call; media
   streams flow each way.
5. **TURN round-trip**: A credential request → relay → coturn → allocation;
   assert the 5-tuple matches what coturn logs.

## Flakiness policy

Puppeteer-based tests are inherently flakier than unit tests. The harness:
- retries ICE gathering once before failing
- waits on explicit event fires (no `setTimeout` polling)
- runs with `--disable-features=IsolateOrigins,site-per-process` so the three
  contexts can share ICE candidates via the local signaling WebSocket

If an E2E test fails once in CI, re-run the job before filing a bug.

## Current status

**Scaffolding only**. The harness is wired and `e2e.test.mjs` contains the
test list as TODOs. The actual per-test implementation (launching puppeteer,
spawning the three contexts, driving the UI via `evaluate()`) lands in a
follow-up once the `npm install puppeteer` dependency is approved locally. The
scaffolding itself is runnable and will skip cleanly when puppeteer is not
installed.
