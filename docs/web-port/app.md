# Web port: the app on the engine

`web/` is the web client: the screens of [docs/ux/web-app.md](../ux/web-app.md) on the engine
of [engine.md](engine.md). This document says how the two are joined, what is tested, and what
is still owed. (`web/` has replaced the legacy vanilla-JS PWA, which has been removed from the
repository; "the old PWA" below is that client.)

## How it is joined

| File | What it holds |
|---|---|
| `src/state/store.ts` | `AppStore`: the one interface the screens know. Signals to read, intents to call |
| `src/state/engine-store.ts` | The real store: an adapter over `Engine`. Everything it needs from the page comes in through `StoreEnv`, so unit tests run it against a scripted engine |
| `src/platform/engine-env.ts` | The page's side of `StoreEnv`: loads the wasm core, opens the database's vault (sealing a plaintext database of the earlier version), starts the engine on the sealed storage, lets tabs talk to each other |
| `src/platform/device-vault.ts` | The rest of what the store does with protected storage: the passphrase lock, making a backup, restoring one |
| `src/screens/Protection.tsx` | The unlock form, the lock, backup and restore settings, and the restore sheet that first run opens too |
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

**Phases.** `loading` (the wasm core, the storage) → `locked` (a passphrase is set: nothing
can be read until it is typed; the phase carries when the next try is allowed) → `first-run`
(no identity on this device; `Engine.start` would create one, so it is not called until
Start; a backup can be restored here instead) → `ready`. Or `other-tab`, or `failed` (the
core did not load; storage is unavailable or does not decrypt).

**Protected storage.** Everything the engine keeps is sealed at rest, and a passphrase can
lock it ([at-rest.md](at-rest.md)); a device can be backed up to one encrypted file and
restored from it ([backup.md](backup.md)). The store's intents for these (`unlock`, `lock`,
`setPassphrase`, `changePassphrase`, `removePassphrase`, `makeBackup`, `restore`, `forget`)
go to `DeviceVault`, not to the engine. The engine keeps running through a change of
passphrase (the storage queues its writes behind the re-sealing). "Lock now" and a restore
end in a reload: the keys live only in the page, and a restored database must be read by a
fresh engine. After a restore the storage refuses every write of the engine that was still
running on the old rows.

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
field means "the saved one"). The test hooks expose neither. A passphrase passes through the
store as an argument and is kept nowhere; a backup's bytes are held only while its sheet is
open, behind the link that saves them. Nothing about either is logged.

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
| The engine: 112 tests over real wasm, fake socket / peer connection / clock. Among them the sealed form of a row, the migration of a plaintext database (and its failure and a race of two tabs), lock / unlock / wrong passphrase / backoff / change / remove, the backup file's round trip, wrong passphrase, tampering and version, and a restored device at work | `tests/engine` (`denext task test:engine`, part of `test`) | `denext task build-wasm` |
| The platform (CSP, service worker, offline start, update flow, takeover from the previous PWA) on the production export; the design, on the lab build | `tests/e2e/*.spec.ts` | both builds |
| Real flows between two or three pages through a real relay, on the production export: first run, pairing by paste and by camera, chat, the queue with edit and take-back, unread counts and order, a video call, a second tab, settings, delete all data; nothing readable in the database; the passphrase lock (wrong tries, the wait, lock now, change, remove, forgotten); back up, delete all data, restore, still paired and chatting; a plaintext database of the earlier version sealed at start | `tests/e2e/real.flows.ts` (`--project=flows-<browser>`) | both builds and the relay binary |
| The seven desktop ↔ browser cases against the web app | `apps/desktop/interop/pwa-interop.mjs` | the test build, the relay and the bot |
| The engine alone in a browser (no UI) against the relay and the bot | `tests/engine/e2e` (`denext task engine:e2e:build`, `engine:e2e`) | as above; not run in CI: the two rows above cover its scenarios through the app |

Every page in the real flows is watched: no Content-Security-Policy violation, no console
error, no request (WebSockets included) that leaves the test server. The call flow also
checks, on both pages, that after hang-up nothing plays the call, the capture's tracks are
ended and the call's connection is closed. From "their video is playing" to the end of the
call each step has a time limit, and a failure carries each page's `[Call]` log lines, its
`<video>` elements and whether the page still answers. No failure is expected or excused
any more (the freeze at "Turn camera off" in WebKit, below, used to be reported as skipped).

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
    This was "Turn camera off", where the self view goes away: the page of the person who
    pressed the button could freeze (6 of 261 runs of the call flow across three series).
    The app avoids it now: the store detaches the self view first and only then has the
    engine switch the track off, and allows the stream again before the track is switched
    back on (`setCameraOff` in `src/state/engine-store.ts`). In the reproduction that order
    froze 0 of 20 pages of 30 rounds each where the old one froze 15 of 20; in the call flow,
    0 of 240 runs froze there. Showing the self view from a clone of
    the camera track was measured too and is not needed (`tests/e2e/repro/README.md` has all
    the numbers). The flow no longer excuses a freeze at that step.

  The QR scanner follows the same rule: it detaches its `<video>` before it stops the camera
  (`src/qr/scan.ts`).
- **Safari (macOS, iOS)**: not tested. No run of the flows, the interop cases or the
  reproduction has been made in a real Safari; Playwright's "WebKit" on Linux is a different
  media stack (GStreamer, not AVFoundation), so neither its passes nor this freeze carry
  over. The order the app now uses is the conservative one for any browser.

## Languages

All nine catalogues are complete: every key of `en` is in every locale.

| Locale | Keys | Coverage | Translation |
|---|---|---|---|
| `en` | 344 / 344 | 100% | source |
| `ar`, `de`, `es`, `fa`, `fr`, `it`, `ja`, `ko` | 344 / 344 | 100% | **machine, not yet reviewed by a native speaker** |

**The eight translated catalogues are machine translations** (made with a language model from
the English catalogue, the design rules of [docs/ux/web-app.md](../ux/web-app.md) and a
glossary per language; the strings taken from the old PWA were kept where they still said what
the English says, and corrected where they did not). Each file says so in its first entry,
`"@meta.translation": "machine"`. A native speaker who has reviewed a file changes that value
to `"reviewed"`; a unit test accepts only those two. Until then, treat the wording, above all
of the security statements, as a draft. Choices a reviewer should look at first: the words for
"passphrase", "safety number" and "verified"; the word a person types to confirm deleting
(`settings.wipe.word`) and replacing (`restore.word`), which in `ja`, `ko`, `ar` and `fa` needs
that language's keyboard; Arabic and Persian sentences around `{name}`, written to avoid
grammatical gender where possible (masculine where not).

`tests/unit/i18n.test.ts` fails when a locale lacks a key, has one English lacks, uses a
message's arguments differently (a name, or plain where English has a plural), has unbalanced
braces, or lacks a plural branch for a category of its language. `denext deno run
--allow-read=. scripts/i18n-check.ts` prints the table above and the same problems. A key
added to English before it is translated still falls back to English, key by key.
Right-to-left layout of the new screens was looked at in the Arabic screenshots
(`tests/e2e/artifacts/<browser>/*-rtl-*/`: `locked`, `settings-protection`, `backup`,
`restore`, `lock-set`).

Where the old PWA's words came from, for the record:

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

## Still owed

- **Review of the translations** by native speakers (above, "Languages").
- **The lock.** No automatic lock after inactivity. The derivation runs on the main thread
  (a fraction of a second on a laptop, longer on a phone) and the wasm instance keeps the
  64 MiB it used. A worker would fix both.
- **Backups.** No reader or writer on the desktop; restoring replaces, it does not merge.
- **No migration from the old PWA.** A person who has the old PWA starts over in the new app
  (database `parolnet-web`; nothing is read from `parolnet`). Decide whether to migrate or to
  say so on first run.
- **Receiving while closed.** No push: the app rings and receives only while it is open (it
  says so). Notifications cover a tab in the background only.
- **Safari.** Untested (above, "Browsers").
- **Groups, files, identity rotation**: not in the engine yet.
- **History.** No trimming and no deletion of single messages; threads are loaded whole at
  start.
- **The wasm core.** `bootstrap_decrypt` and per-session export / import are in the core but
  not used by the engine yet (engine.md, "wasm API gaps" #3 and #6).
