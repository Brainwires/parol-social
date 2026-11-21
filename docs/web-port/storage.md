# Web port: storage, service worker, settings, i18n

Part of the [porting inventory](inventory.md). The conventions are explained there.

## 8. Storage

### 8.1 IndexedDB databases

| DB | Version | Owner | Disposition |
|---|---:|---|---|
| `parolnet` | 7 | `db.js:4-5` | main store; replace (§8.6) |
| `parolnet-sw` | 1 | `sw.source.js:589-592`, `boot.js:452-455` | SW inbox; **DROP** |
| `parolnet_settings` | 1 | `relay-client.js:855-900` | bridge relays (`bridge_relays` key); **DROP** |

### 8.2 `parolnet` object stores

The schema is created in `db.js:19-66`.

| Store | keyPath | Indexes | Record shape (written at) | Encrypted when the passphrase store is on |
|---|---|---|---|---|
| `contacts` | `peerId` | — | `{peerId, name, identityPubKey?, previousIdentityPubKey?, rotatedAt?, rotatedGraceExpiresAt?}` (`ui-chat.js:914-921`, `messaging.js:1650-1654,1527-1536`) | yes |
| `contact_state` | `peerId` | — | `{peerId, lastMessage, lastTime (formatted string), unread, lastActivityAt}` (`db.js:134-140`) | yes |
| `messages` | `id` (auto) | `peerId`, `timestamp` | `{id, peerId, direction:'sent'\|'received', content, timestamp}` (`ui-chat.js:284-289`, `messaging.js:1320-1325`) | yes (breaks the indexes, inventory §12.1 #7) |
| `settings` | `key` | — | `{key, value}`, keys in §10.1 | yes |
| `crypto_meta` | `key` | — | `salt`, `verifier`, `duress_salt`, `duress_verifier` as `{key, value: number[]}` (`crypto-store.js:65-80`) | no |
| `pending_sends` | `id` (auto) | — | `{id, toPeerId, payload, timestamp, nextTryAt, bootstrap?}` (`connection.js:341-354`) | yes |
| `groups` | `groupId` | — | `{groupId, name, members[], createdBy, createdAt, lastMessage, lastTime}` (`messaging.js:465-473`) | yes (DEFER) |
| `group_messages` | `id` (auto) | `groupId`, `timestamp` | `{groupId, sender, content, timestamp}` | yes (DEFER) |
| `peer_relay_cache` | `peerId` | — | federation lookup cache (`peer-relay-cache.js:75-90`) | no (DROP) |

Identity and sessions live in `settings` as `identity_secret` (hex Ed25519 secret, `boot.js:99`) and
`sessions_blob` (the wasm `export_sessions` JSON, `messaging.js:41`). Both are plaintext unless the
passphrase store is on. Neither is zeroizable in JS.

The interop driver reads `contacts` and `messages` directly with `indexedDB.open("parolnet")` and checks
`c.peerId`, `m.peerId`, `m.direction === "received"` and `m.content` (`pwa-interop.mjs:533-559` [s3]).
§11.3 proposes replacing that with a test hook, so the new schema is free.

### 8.3 Passphrase encryption (`crypto-store.js`)

- **Opt-in.** Settings asks for a passphrase of at least 4 characters (`settings.js:257-289`).
- **KDF:** PBKDF2-SHA-256, 600 000 iterations, random 16-byte salt, giving an AES-GCM-256 key
  (`crypto-store.js:5-17`).
- **Cipher:** AES-256-GCM with a random 12-byte IV per record. A record is stored as
  `{<keyField>: key, _enc: [iv ‖ ct …] as number[]}` (`crypto-store.js:19-29`, `db.js:165-174`). The
  plaintext is `JSON.stringify(record)`.
- **Verifier:** the encryption of `{verify:'parolnet'}` in `crypto_meta.verifier` (`crypto-store.js:68-69`).
- **Encrypted stores:** `contacts`, `messages`, `settings`, `groups`, `group_messages`, `contact_state`,
  `pending_sends` (`db.js:114-116`). Existing rows are re-written encrypted at setup
  (`settings.js:291-304`).
- **Duress slot** (DROP): a second salt and verifier, and unlock always runs both derivations
  (`crypto-store.js:133-190`). On a duress match it calls `panic_wipe` and goes to `kill-sw.html`
  (`boot.js:357-364`).
- **Auto-lock:** the key is dropped after 5 min hidden (`boot.js:702-712`).
- Keys are not wrapped. Losing the passphrase loses the data.

### 8.4 localStorage and other browser state

| Key | Where | Disposition |
|---|---|---|
| `parolnet_relay_directory` (6 h TTL) | `relay-client.js:7-8,722-745` | DROP |
| — | `localStorage.clear()` on "Clear cache" and in `kill-sw.html` (`index.html:38`, `kill-sw.html:36`) | — |

Also: `navigator.storage.persist()` at boot (`boot.js:669`; PORT); the SW cache `parolnet-v10`
(`sw.source.js:5`).

### 8.5 Export / import (`data-export.js`, `settings.js:307-428`)

**File layout:** `salt(16) ‖ iv(12) ‖ AES-256-GCM(ciphertext)`, with no header. The key is
PBKDF2-SHA-256 (600 000 iterations) from a prompted password (`data-export.js:1-46`).

**Plaintext:**

```json
{"version":1,"stores":{"contacts":[…],"messages":[…],"settings":[…],"crypto_meta":[…]},"identity":"<secret hex>","sessions":"<export_sessions json>"}
```

The rows are **raw** (`dbGetAllRaw`): still `_enc`-wrapped if the passphrase store is on
(`settings.js:322-325`).

**Import** clears each listed store, puts the raw rows back, calls `initialize_from_key(identity)` and
`import_sessions`, then reloads (`settings.js:394-421`).

**Hazards:**

- `contact_state`, `pending_sends` and groups are not exported.
- Restoring a ratchet snapshot on a second device, or after further use, desynchronises sessions.
- No desktop-compatible format exists.

### 8.6 What "panic wipe" deletes (DROP)

`executePanicWipe` (`settings.js:752-756`):

1. Lock the crypto store.
2. `wasm.panic_wipe()`, which clears the in-memory client, files, decoy hash and pending bootstrap
   (`lib.rs:1930-1945`).
3. Navigate to `kill-sw.html?panic=1`, which unregisters every SW, deletes every Cache, clears
   `localStorage` and `sessionStorage`, and calls `indexedDB.deleteDatabase` on every database
   (`kill-sw.html:22-43`). `deleteDatabase` is not awaited.

Triggers: the calculator panic code (default `999999`, `views.js:44,82-85`), the duress passphrase, and
the Settings button (`index.html:349`).

### 8.7 Recommended minimal schema for the new app

There is no migration, so start at version 1. Use one database, e.g. `parolnet-web`.

| Store | Key | Indexes | Record |
|---|---|---|---|
| `identity` | `'self'` | — | `{secretHex}` (or a wrapped key if at-rest encryption is kept) |
| `sessions` | `'blob'` | — | `{json}`: the `export_sessions()` output, written after every encrypt and decrypt (one row, atomically) |
| `contacts` | `peerId` | — | `{peerId, name, identityKeyHex, addedAt, verifiedAt?}`. Never overwritten by incoming traffic (inventory §12.1 #1) |
| `messages` | `id` (auto) | `[peerId, timestamp]` | `{id, peerId, direction, text, timestamp, state:'queued'\|'sent'\|'received'\|'dropped', queueId?}` |
| `outbox` | `id` (auto) | `peerId` | `{id, peerId, envelopeHex, createdAt, bootstrap, messageId?}`. FIFO per peer; limits 30 d / 500 per peer / 2000 / 50 MiB (`relay-profile.js:139-144`) |
| `contactState` | `peerId` | — | `{peerId, lastActivityAt, unread}` (the watch-list order uses `lastActivityAt`) |
| `settings` | `key` | — | `{key, value}` (§10.1 PORT keys) |

If at-rest encryption is kept, encrypt the `value` fields only and keep the key and index columns
clear. That fixes inventory §12.1 #7, at the cost of revealing peer ids and timestamps at rest.

---

## 9. Service-worker duties beyond caching

What `sw.source.js` does, and what depends on it:

| Duty | Where | Depends on it | Recommendation |
|---|---|---|---|
| Cache-first with background revalidate, for same-origin GETs, with an SRI hash check for listed assets (hashes substituted at build) | `sw.source.js:5-227`, `build.mjs` | offline launch | Keep (plain caching worker) |
| Offline HTML page with Retry / Reset (probe `/pwa/manifest.json` every 8 s) | `sw.source.js:213-324` | — | Optional |
| No `skipWaiting` on install; the page posts `'skipWaiting'` when a waiting worker exists; `reg.update()` hourly | `sw.source.js:94-98,625-628`, `boot.js:612-626` | updates | Framework default |
| **Relay WebSocket**: register, ping 20 s, dead after 40 s, backoff; forwards relay frames to every window client (`relay_msg`), broadcasts `relay_status` | `sw.source.js:381-578,642-711` | all signalling, presence, registration, and the interop `Registered with relay` line (logged by the page on `registered`, `messaging.js:330`) | **Move to the page** (wire.md §3). The intent was background delivery, but on a signaling-only relay nothing can arrive while the page is closed: there are no `message` frames (PNP-001-MUST-071), and offers need a live page to answer |
| **Inbox**: when no window client exists, relay frames go to IDB `parolnet-sw/sw-inbox` (cap 200, pruned to 150); the page drains it ack-after-decrypt at boot, on focus, and when live frames fail (`boot.js:204-213,415-562`) | `sw.source.js:569-621` | relay-profile store-and-forward | **DROP**. Buffered `rtc_offer` frames are stale by the time they are drained |
| `push` → `showNotification` | `sw.source.js:329-353` | nothing: no push subscription exists in the PWA (no `pushManager` use) | **DROP** |
| `notificationclick` → focus a window and post `{type:'openChat', peerId}`, or open `./index.html?chat=<peer>` | `sw.source.js:357-379` | page notifications (`utils.js:464-476` uses `reg.showNotification`, which needs a SW registration) | Keep, and actually handle `openChat` / `?chat=` in the page (no listener today) |
| `'panicWipe'` message: delete caches and unregister | `sw.source.js:630-636` | nothing posts it | **DROP** |
| `relay_disconnect` (suspend for onion mode) | `sw.source.js:540-559,653-655` | onion | **DROP** |

Net: the new worker only needs to cache. It also needs a `notificationclick` handler if the page shows
notifications through `registration.showNotification`, which is required on Android. Case 3 of the
interop suite (sender queue across a browser restart, `pwa-interop.mjs:674-687` [s3]) does not depend on
the SW: the *desktop* queues, and the PWA reconnects on relaunch.

---

## 10. Settings and i18n

### 10.1 Settings

All settings are stored as `settings` rows `{key, value}` with string values.

| Key | Default | Set at / read at | Disposition |
|---|---|---|---|
| `identity_secret` | generated | `boot.js:79,99`, `settings.js:404,687` | PORT (identity store) |
| `sessions_blob` | — | `messaging.js:41`, `boot.js:114` | PORT |
| `language` | detected from `navigator.languages` and persisted on first run | `boot.js:655-662,794` | PORT |
| `custom_stun_servers` | none. JSON array of `RTCIceServer` (the user's own TURN/STUN) | `webrtc.js:86-89,136,148` | PORT ("own TURN server") |
| `webrtc_relay_only` | `'false'`; effective only with own TURN | `webrtc.js:94-95,151,185` | PORT |
| `ip_notice_ack` | absent → show the one-time "direct connections reveal your IP" notice | `settings.js:117-131` | PORT |
| `custom_relay_url` | absent → same-origin `/ws` | `connection.js:59`, `settings.js:442` (UI broken, inventory §12.1 #11) | PORT (fix the UI) |
| `retired_identity` | — | `settings.js:689-693,728-749` | with identity rotation (inventory §12.2) |
| `cover_traffic_enabled` | `'false'` | `settings.js:38,51` | DROP |
| `onion_mode_enabled` | `'false'` | `settings.js:142,219` | DROP |
| `panic_code` | `999999` | `views.js:44-67` | DROP |
| (decoy unlock code) | `00000`; wasm memory only | `settings.js:641-655` | DROP |
| (passphrase store) | off | `crypto_meta` | inventory §12.2 |
| (notifications) | browser permission, requested at boot | `boot.js:201` | PORT (request on user action instead) |
| (webrtc privacy legacy) `webrtc_privacy_mode` | ignored on purpose | `webrtc.js:54-58` | DROP |

### 10.2 i18n

**Mechanism** (`i18n.js`):

- 16 supported codes (`i18n.js:4-7`): `en ru fa zh-CN zh-TW ko ja fr de it pt ar es tr my vi`.
- RTL for `ar` and `fa` (`i18n.js:9,124-126`).
- `en.json` always loads first and serves as the fallback; then the chosen locale loads.
- `t(key, params)` falls back current → en → key, with `{name}` replacement (`i18n.js:46-57`).
- The DOM is applied through the `data-i18n`, `data-i18n-placeholder`, `data-i18n-title` and
  `data-i18n-html` attributes (`i18n.js:123-141`). `data-i18n-html` uses `innerHTML`, so the port must
  sanitise it or avoid it.
- Detection (`detectLocale`, `i18n.js:81-114`): exact match, then the `zh` Hant/HK/TW/MO → `zh-TW` rule,
  then the base language, then `en`.
- The catalogs are flat JSON maps of `key → string`.

**Locale files** (`pwa/lang/`). Every file has the same **312 keys**: none missing, none extra (checked
against `en.json`). Completeness was checked by counting values byte-identical to English (excluding
strings with no Latin letters):

| Locale | Keys | Identical to en |
|---|---:|---:|
| en | 312 | (reference) |
| ru, pt | 312 | 7 |
| es | 312 | 8 |
| de, it | 312 | 10 |
| fr | 312 | 12 |
| ar, fa, ko, zh-CN, zh-TW | 312 | 34 |
| ja, my, tr, vi | 312 | 35 |

The roughly 28 extra untranslated strings in the 34/35 group are the newest signaling-only and TURN
strings, left in English. Examples: `settings.ownTurn*`, `settings.relayOwnTurn*`,
`settings.serverSignalingOnly`, `chat.waitingForPeer`, `chat.noDirectPath*`,
`toast.callNeedsDirectPath`, `notice.ip*`, `toast.turn*`. They read as translated in `ru`.

Many user-facing strings in the JS are hard-coded English and are not keyed at all, for example
`ui-chat.js:1053-1067,1098-1152`, `settings.js:264-357`, the file UI and the safety modal body.
