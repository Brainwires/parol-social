# Web port: the app on the engine

`web/` is the web client: the screens of [docs/ux/web-app.md](../ux/web-app.md) on the engine
of [engine.md](engine.md). This document says how the two are joined, what is tested, and what
is still owed before `web/` replaces `pwa/` in production.

## How it is joined

| File | What it holds |
|---|---|
| `src/state/store.ts` | `AppStore`: the one interface the screens know. Signals to read, intents to call |
| `src/state/engine-store.ts` | The real store: an adapter over `Engine`. Everything it needs from the page comes in through `StoreEnv`, so unit tests run it against a scripted engine |
| `src/platform/engine-env.ts` | The page's side of `StoreEnv`: loads the wasm core, opens the engine's storage, starts the engine, lets tabs talk to each other |
| `src/platform/playback.ts` | The media elements that play a call's streams, so the store can detach all of them in the turn the call ends |
| `src/state/fake.ts` | The state lab's made-up store (`#/lab`), in development and test builds only |
| `src/start.tsx` | Starts the app. `src/main.tsx` is the production entry; `src/main.dev.tsx` adds the lab and the test hooks |

**One store, fed by the snapshot and the events.** After every engine event the store reads
`engine.snapshot()` again for everything the snapshot carries (the relay, the contacts with
their path, queued and unread counts, the pairing code, the call). Message events
(`Message`, `MessageState`, `MessageEdited`, `MessageRemoved`) are applied to the threads,
which are loaded once at start (every contact's, so the list can show the last message of
each). A call that ended is not in the snapshot; the store keeps it for six seconds, or until
"Close", so the screen can say how it ended.

**When a call ends, the person sees it first and the media goes afterwards.** The engine
emits `Ended` before it stops the capture or closes the connection (engine.md, "The end of a
call"). In that same turn the store calls `StoreEnv.keepPlaying([])`, which detaches every
`<video>` of the call (`src/platform/playback.ts`: the call screen's elements
register there instead of setting `srcObject` themselves), and puts the ended call on screen.
Only in later tasks does the engine stop tracks and close the connection, and nothing in the
app waits for that. The same happens when the camera is switched (`CallMedia`:
`keepPlaying` with the streams the call still has) and when the tab hands the engine over.
It does not wait for the call screen to render again: an element that still plays a stream
whose track ends can freeze the page in WebKit on Linux (below, "Browsers").

**Phases.** `loading` (the wasm core, the storage) → `first-run` (no identity on this
device; `Engine.start` would create one, so it is not called until Start) → `ready`. Or
`other-tab`, or `failed` (the core did not load; storage is unavailable).

**One tab at a time.** The engine holds a Web Lock; a second tab gets `EngineError("Busy")`
and shows "ParolNet is open in another tab". The engine has no take-over of its own, so the
app adds one: "Use it here" asks the running tab over a `BroadcastChannel` to hand over; that
tab shuts its engine down (which releases the lock) and says "ParolNet moved to another tab";
the asking tab retries until the lock is free. A tab that ran an engine before reloads first,
so it starts with clean wasm state.

**The vocabulary is the engine's.** `src/state/model.ts` re-exports the engine's types; what
the first phase's fake store called differently is gone:

| Was (phase 1) | Is (the engine's) |
|---|---|
| `CallEnd` as a string, `"RemoteDeclined"` | `{ kind }`; they declined is `Rejected`, this device declined is `Declined`, plus `NoAnswer` and `Failed { reason }` |
| `Contact { name, kind, path }` | `ContactView { contact, path, queued, unread, lastActivityMs }`; `Contact` has `verified`, `identityKey`, `addedMs` |
| `ChatMessage.body` (text, file or call) | `ChatMessage.text`. The lab's made-up files and call invitations are an optional `attachment` only the fake store sets |
| `takeBack(peerId, id)`, `edit(peerId, id, text)`, synchronous | `takeBack(id)`, `edit(id, text)`: asynchronous, rejecting with `NotQueued` once the message has left |
| `addContact(name, code)` | `pair(code, via)`, then `rename`. The other side arrives through `ContactAdded` |
| a fixed code | `PairingCode { code, expiresAtMs }`; the same code after a reload within its lifetime (the engine stores its pending half), otherwise the screen asks for a new one |

**What the engine gained for the app** (see engine.md): `removeContact`, `replaceCamera`,
coded `Notice` events, `ContactRemoved`, and a call-failure reason for a refused microphone or
camera.

**Nothing secret leaves the engine.** The store never holds the identity; the TURN password
goes in through `setTurn` and is never read back into a signal or the page (an empty password
field means "the saved one"). The test hooks expose neither.

## Builds

| | `denext task build` | `denext task build:test` |
|---|---|---|
| Entry | `src/main.tsx` | `src/main.dev.tsx` (`PAROLNET_BUILD=test`) |
| Output | `web/out` | `web/out-test` |
| State lab (`#/lab`) | no | yes |
| `window.__parolnetTest` | no; `scripts/postexport.ts` fails the build if the bundle names it | yes |
| First-load JavaScript budget (150 KB gzip) | enforced | reported |

`denext task dev` serves the test build.

## Tests

| What | Where | Needs |
|---|---|---|
| Tokens and contrast, catalogue, components, QR encoder against the scanner's decoder, the state model, the store adapter against a scripted engine | `tests/unit` (`denext task test`) | the wasm build, for the engine tests that run with it |
| The engine: 80 tests over real wasm, fake socket / peer connection / clock | `tests/engine` (`denext task test:engine`, part of `test`) | `denext task build-wasm` |
| The platform (CSP, service worker, offline start, update flow, takeover from the previous PWA) on the production export; the design, on the lab build | `tests/e2e/*.spec.ts` | both builds |
| Real flows between two or three pages through a real relay, on the production export: first run, pairing by paste and by camera, chat, the queue with edit and take-back, unread counts and order, a video call, a second tab, settings, delete all data | `tests/e2e/real.flows.ts` (`--project=flows-<browser>`) | both builds and the relay binary |
| The seven desktop ↔ browser cases against the web app | `apps/desktop/interop/pwa-interop.mjs` with `INTEROP_APP=web` | the test build, the relay and the bot |
| The engine alone in a browser (no UI) against the relay and the bot | `tests/engine/e2e` (`denext task engine:e2e:build`, `engine:e2e`) | as above; not run in CI: the two rows above cover its scenarios through the app |

Every page in the real flows is watched: no Content-Security-Policy violation, no console
error, no request (WebSockets included) that leaves the test server. The call flow also
checks, on both pages, that after hang-up nothing plays the call, the capture's tracks are
ended and the call's connection is closed. From "their video is playing" to the end of the
call each step has a time limit, and a failure carries each page's `[Call]` log lines, its
`<video>` elements and whether the page still answers. One failure is expected and reported
as skipped, in WebKit only: the page frozen by the browser at "Turn camera off" (below).

## Browsers

- **Chromium, Firefox**: the flows and the interop cases run in both, on Linux in CI and on
  macOS.
- **WebKit on Linux** (WPE / WebKitGTK, GStreamer): what CI runs as "WebKit", and what
  GNOME Web and embedded WPE browsers are. Two ways this browser can block a page's main
  thread for good were found (engine.md, "Defects found"; `tests/e2e/repro` shows both
  without the app):
  - *A track ends while a `<video>` still plays its stream.* This froze the page at hang-up
    (6 of 36 runs of the call flow on a busy machine). The app avoids it: the elements are
    detached first. In 156 runs of the flow on the final code, none froze at hang-up.
  - *A stream is detached from its element right after its camera track was switched off.*
    This is "Turn camera off", where the self view goes away. It is not fixed: the page of
    the person who presses the button can freeze (3 of those 156 runs, 2 of 45 in another
    series, on a busy machine). Leaving the self view attached was tried and moved the
    freeze to the end of the call instead. The flow reports this one freeze as skipped, with
    its reason, and fails on any other.

  The QR scanner also stops its camera before it detaches its `<video>` (`src/qr/scan.ts`),
  the first of the two shapes; see "Owed".
- **Safari (macOS, iOS)**: not tested. No run of the flows, the interop cases or the
  reproduction has been made in a real Safari; Playwright's "WebKit" on Linux is a different
  media stack (GStreamer, not AVFoundation), so neither its passes nor this freeze carry
  over. The order the app now uses is the conservative one for any browser.

## Languages

`en` is complete. For the other eight primary locales, the old PWA's translation was taken
where a string's meaning is unchanged and a key maps cleanly (the table below); `ar` also
keeps the machine translation of the first phase's strings. Nothing new was machine-translated.
A missing key falls back to English, key by key.

| Locale | Keys | Coverage |
|---|---|---|
| `en` | 243 / 243 | 100% |
| `ar` | 88 / 243 | 36% |
| `de`, `es`, `fr`, `it` | 32 / 243 | 13% |
| `fa`, `ja`, `ko` | 26 / 243 | 11% |

(`fa`, `ja` and `ko` have six fewer because the old files left those six strings in English.)

| New key | Old key in `pwa/lang/*.json` |
|---|---|
| `action.remove` | `btn.remove` |
| `action.save`, `composer.save` | `btn.save` |
| `action.tryAgain` | `btn.retry` |
| `add.copy` | `btn.copyCode` |
| `add.title` | `heading.addContact` |
| `call.accept`, `call.decline`, `call.end` | `btn.accept`, `btn.decline`, `btn.hangup` |
| `call.ended.youEnded` | `toast.callEnded` |
| `composer.send` | `btn.send` |
| `list.addContact`, `paste.submit` | `btn.addContact` |
| `list.preview.none` | `empty.noMessages` |
| `list.settings`, `settings.title` | `heading.settings` |
| `name.empty` | `error.emptyName` |
| `notify.message` | `toast.newMessage` |
| `pair.own` | `error.ownCode` |
| `paste.empty` | `error.enterContactCode` |
| `scan.denied`, `scan.help` | `error.cameraDenied`, `qr.cameraPrompt` |
| `settings.about`, `settings.language`, `settings.version` | the same keys |
| `settings.relay.invalid` | `error.relayUrlInvalid` |
| `settings.turn.title`, `.username`, `.password` | `settings.relayOwnTurn`, `settings.ownTurnUsername`, `settings.ownTurnCredential` |
| `toast.codeCopied`, `toast.turnSaved` | the same keys |
| `toast.renamed`, `toast.turnRemoved` | `toast.contactRenamed`, `toast.turnCleared` |

## Owed before this replaces the old PWA

- **Encryption at rest and backup.** The identity key, the sessions and the TURN password are
  plain rows in IndexedDB (engine.md, "Storage schema"). There is no encrypted backup export
  or import yet: a "Back up this device" row is deliberately absent from Settings rather than
  shown as a dead control. Until both exist, clearing site data or losing the device loses the
  identity.
- **No migration from the old PWA.** A person who has the old PWA starts over in the new app
  (database `parolnet-web`; nothing is read from `parolnet`). Decide whether to migrate or to
  say so on first run.
- **Translations.** Thirteen percent of the catalogue outside English and Arabic.
- **Receiving while closed.** No push: the app rings and receives only while it is open (it
  says so). Notifications cover a tab in the background only.
- **Safari.** Untested (above, "Browsers").
- **"Turn camera off" on Linux WebKit** can freeze the page (above, "Browsers"). Not tried
  yet: showing the self view from a clone of the camera track, so that the element's stream
  never has a track switched off; detaching the self view before the track is switched off
  rather than after.
- **The scanner on Linux WebKit.** `src/qr/scan.ts` stops the camera's tracks while its
  `<video>` still plays them, the order that can freeze the page there (`tests/e2e/repro`,
  `camera-only`: 1 page of 30, five captures each, on a busy machine). Detach first, as the
  call screen does.
- **Groups, files, identity rotation**: not in the engine yet.
- **History.** No trimming and no deletion of single messages; threads are loaded whole at
  start.
- **The wasm core.** `bootstrap_decrypt` and per-session export / import are in the core but
  not used by the engine yet (engine.md, "wasm API gaps" #3 and #6). The stored pending
  bootstrap, like the identity, is plain in IndexedDB until encryption at rest exists.
