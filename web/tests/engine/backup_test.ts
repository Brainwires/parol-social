// The backup file (src/engine/backup.ts, docs/web-port/backup.md): what goes in, the
// round trip, every way a file can be wrong, and a restored device at work.
import { assert, assertEquals, assertRejects } from "@std/assert";
import {
  BACKUP_MAGIC,
  BACKUP_VERSION,
  type BackupContents,
  BackupError,
  backupHeader,
  collectBackup,
  decodeBackup,
  encodeBackup,
  restoredRows,
} from "../../src/engine/backup.ts";
import { RESTORED_PROVEN_MS } from "../../src/engine/engine.ts";
import { SealedStorage } from "../../src/engine/sealed-storage.ts";
import { MemoryStorage } from "../../src/engine/storage.ts";
import { Vault } from "../../src/engine/vault.ts";
import { type Device, withWorld, type World } from "./harness/world.ts";
import { FAST_KDF, testCrypto } from "./harness/vault.ts";

const PASS = "four random words here";

async function sealedDevice(w: World, name: string, raw = new MemoryStorage()) {
  const c = await testCrypto(w.clock);
  const storage = new SealedStorage(await Vault.open(raw, c));
  const device = await w.device(name, { storage: raw, engineStorage: storage });
  return { device, storage, c };
}

async function backupOf(
  w: World,
  device: Device,
  storage: SealedStorage,
  history: boolean,
): Promise<BackupContents> {
  return collectBackup(await storage.snapshot(), {
    history,
    peerId: device.id,
    now: w.clock.now(),
  });
}

/** Stop `device` and start a new one, on a new database, from `contents`. */
async function restoreOnNewDevice(w: World, device: Device, contents: BackupContents) {
  await device.engine.wipe();
  w.devices = w.devices.filter((d) => d !== device);
  await w.settle();
  const raw = new MemoryStorage();
  const c = await testCrypto(w.clock);
  const storage = new SealedStorage(await Vault.open(raw, c));
  await storage.replaceAll(restoredRows(contents, w.clock.now()));
  // The page reloads after a restore: a new storage object over the same database.
  const fresh = new SealedStorage(await Vault.open(raw, c));
  return await w.device(device.name, { storage: raw, engineStorage: fresh });
}

Deno.test(
  "backup: holds the identity, contacts with their verification, sessions and settings; history only when asked",
  withWorld(async (w) => {
    const { device: a, storage } = await sealedDevice(w, "a");
    const b = await w.device("b");
    await w.pair(a, b, "scan");
    await a.engine.renameContact(b.id, "Bo");
    await a.engine.setTurnSettings({
      uri: "turn:t.example:3478",
      username: "u",
      password: "p",
      relayOnly: false,
    });
    await a.engine.sendText(b.id, "kept only with history");
    await a.engine.createPairingCode();
    await storage.write([{
      op: "put",
      store: "settings",
      value: { key: "backup", value: { lastMs: 1 } },
    }]);
    await w.settle();

    const without = await backupOf(w, a, storage, false);
    assertEquals(without.version, 1);
    assertEquals(without.peerId, a.id);
    assertEquals(without.identity.secretHex, a.wasm.export_secret_key());
    assertEquals(JSON.parse(without.sessions)[b.id] !== undefined, true);
    assertEquals(without.contacts.length, 1);
    assertEquals(without.contacts[0].name, "Bo");
    // `b` scanned nothing: `a` showed the code, so `a` holds `b` as not verified yet.
    assertEquals(without.contacts[0].verified, "no");
    // The person's own relay server goes along; what belongs to the device does not.
    assertEquals(without.settings.map((s) => s.key), ["turn"]);
    assertEquals(without.history, null);
    assertEquals(JSON.stringify(without).includes("kept only with history"), false);
    // The code on screen is not part of a backup.
    assertEquals(JSON.stringify(without).includes("pendingHex"), false);

    const withHistory = await backupOf(w, a, storage, true);
    assertEquals(withHistory.history?.messages.map((m) => m.text), ["kept only with history"]);
    assertEquals(withHistory.history?.contactState.length, 1);
  }),
);

function sample(history: boolean): BackupContents {
  const peer = "b".repeat(64);
  return {
    version: 1,
    createdMs: 1_700_000_000_000,
    peerId: "a".repeat(64),
    identity: { secretHex: "11".repeat(32) },
    sessions: JSON.stringify({ [peer]: "00ff" }),
    contacts: [{
      peerId: peer,
      name: "Bo",
      identityKey: "22".repeat(32),
      addedMs: 5,
      verified: "compared",
      verifiedMs: 6,
    }],
    settings: [{
      key: "turn",
      value: { uri: "turn:x", username: "u", password: "p", relayOnly: true },
    }],
    history: history
      ? {
        messages: [{
          id: 1,
          peerId: peer,
          direction: "Received",
          text: "héllo ✓",
          timestampMs: 7,
          state: "Received",
        }],
        outbox: [],
        contactState: [{ peerId: peer, lastActivityMs: 7, unread: 1 }],
      }
      : null,
  };
}

Deno.test("backup file: round trip, with and without history", async () => {
  const c = await testCrypto();
  for (const history of [false, true]) {
    const contents = sample(history);
    const file = await encodeBackup(c, PASS, contents, FAST_KDF);
    assertEquals(new TextDecoder().decode(file.subarray(0, 8)), BACKUP_MAGIC);
    assertEquals(file[8], BACKUP_VERSION);
    const { header, head } = backupHeader(file);
    assertEquals(header.kdf, FAST_KDF);
    assertEquals(header.cipher, "AES-256-GCM");
    // The encrypted part comes in 4 KiB steps (plus the tag), whatever is inside.
    assertEquals((file.length - head.length - 16) % 4096, 0);
    assertEquals(await decodeBackup(c, PASS, file), contents);
    // Nothing of the contents is readable in the file.
    const text = new TextDecoder("latin1").decode(file);
    for (const secret of ["11".repeat(32), "Bo", "turn:x", "b".repeat(64)]) {
      assertEquals(text.includes(secret), false, secret);
    }
  }
  // Two backups of the same thing share no salt, nonce or ciphertext.
  const one = await encodeBackup(c, PASS, sample(false), FAST_KDF);
  const two = await encodeBackup(c, PASS, sample(false), FAST_KDF);
  assert(backupHeader(one).header.salt !== backupHeader(two).header.salt);
  assert(backupHeader(one).header.nonce !== backupHeader(two).header.nonce);
});

Deno.test("backup file: a short passphrase makes no backup", async () => {
  const c = await testCrypto();
  const error = await assertRejects(
    () => encodeBackup(c, "seven77", sample(false), FAST_KDF),
    BackupError,
  );
  assertEquals(error.code, "Weak");
});

Deno.test("backup file: wrong passphrase", async () => {
  const c = await testCrypto();
  const file = await encodeBackup(c, PASS, sample(true), FAST_KDF);
  const error = await assertRejects(() => decodeBackup(c, PASS + " ", file), BackupError);
  assertEquals(error.code, "WrongPassphrase");
});

Deno.test("backup file: a change anywhere in the file is noticed", async () => {
  const c = await testCrypto();
  const file = await encodeBackup(c, PASS, sample(true), FAST_KDF);
  const { head } = backupHeader(file);
  const codeAfter = async (change: (bytes: Uint8Array) => Uint8Array) => {
    const error = await assertRejects(
      () => decodeBackup(c, PASS, change(file.slice())),
      BackupError,
    );
    return error.code;
  };
  const flip = (at: number) => (bytes: Uint8Array) => {
    bytes[at] ^= 1;
    return bytes;
  };
  // The encrypted part: first byte, a middle one, the tag.
  for (const at of [head.length, head.length + 2000, file.length - 1]) {
    assertEquals(await codeAfter(flip(at)), "WrongPassphrase", `byte ${at}`);
  }
  // The header is authenticated too: a weaker cost, another salt, another nonce.
  const rewriteHeader =
    (edit: (header: Record<string, unknown>) => void) => (bytes: Uint8Array) => {
      const header = JSON.parse(new TextDecoder().decode(bytes.subarray(13, head.length)));
      edit(header);
      const text = new TextEncoder().encode(JSON.stringify(header));
      const out = new Uint8Array(13 + text.length + bytes.length - head.length);
      out.set(bytes.subarray(0, 13));
      new DataView(out.buffer).setUint32(9, text.length);
      out.set(text, 13);
      out.set(bytes.subarray(head.length), 13 + text.length);
      return out;
    };
  assertEquals(
    await codeAfter(rewriteHeader((h) => ((h.kdf as { passes: number }).passes = 2))),
    "WrongPassphrase",
  );
  assertEquals(
    await codeAfter(rewriteHeader((h) => (h.salt = "00".repeat(16)))),
    "WrongPassphrase",
  );
  assertEquals(
    await codeAfter(rewriteHeader((h) => (h.nonce = "00".repeat(12)))),
    "WrongPassphrase",
  );
  // A header that decrypts the same but reads differently (an added field) still fails.
  assertEquals(await codeAfter(rewriteHeader((h) => (h.note = "x"))), "WrongPassphrase");
  // Cut short, or with something appended.
  assertEquals(await codeAfter((bytes) => bytes.subarray(0, bytes.length - 1)), "WrongPassphrase");
  assertEquals(
    await codeAfter((bytes) => {
      const longer = new Uint8Array(bytes.length + 1);
      longer.set(bytes);
      return longer;
    }),
    "WrongPassphrase",
  );
});

Deno.test("backup file: another version, and files that are not backups", async () => {
  const c = await testCrypto();
  const file = await encodeBackup(c, PASS, sample(false), FAST_KDF);
  const code = async (bytes: Uint8Array) =>
    (await assertRejects(() => decodeBackup(c, PASS, bytes), BackupError)).code;
  const newer = file.slice();
  newer[8] = BACKUP_VERSION + 1;
  assertEquals(await code(newer), "Newer");
  const older = file.slice();
  older[8] = 0;
  assertEquals(await code(older), "NotABackup");
  assertEquals(await code(new Uint8Array(0)), "NotABackup");
  assertEquals(await code(new TextEncoder().encode("PNBACKUP")), "NotABackup");
  assertEquals(
    await code(new TextEncoder().encode('{"version":1,"stores":{}} an old export')),
    "NotABackup",
  );
  const noMagic = file.slice();
  noMagic[0] = 0x51;
  assertEquals(await code(noMagic), "NotABackup");
  const hugeHeader = file.slice();
  new DataView(hugeHeader.buffer).setUint32(9, 0x7fffffff);
  assertEquals(await code(hugeHeader), "NotABackup");
  // A cost no version 1 writer uses is a newer file, and is refused before deriving.
  const text = new TextDecoder().decode(file.subarray(13, backupHeader(file).head.length));
  const costly = new TextEncoder().encode(text.replace('"memoryKiB":64', '"memoryKiB":9999999999'));
  const big = new Uint8Array(13 + costly.length + 32);
  big.set(file.subarray(0, 13));
  new DataView(big.buffer).setUint32(9, costly.length);
  big.set(costly, 13);
  assertEquals(await code(big), "Newer");
});

Deno.test("backup file: contents that are not a backup are refused after decrypting", async () => {
  const c = await testCrypto();
  const bad: ((contents: Record<string, unknown>) => void)[] = [
    (x) => (x.version = 2),
    (x) => (x.identity = { secretHex: "zz" }),
    (x) => delete x.identity,
    (x) => (x.sessions = "not json"),
    (x) => (x.contacts = [{ peerId: "short" }]),
    (x) => (x.contacts = "none"),
    (
      x,
    ) => (x.history = {
      messages: [{ id: 1, peerId: "c".repeat(64), text: "x", timestampMs: 1 }],
      outbox: [],
      contactState: [],
    }),
    (x) => (x.history = { messages: "x" }),
  ];
  for (const [i, edit] of bad.entries()) {
    const contents = sample(false) as unknown as Record<string, unknown>;
    edit(contents);
    const file = await encodeBackup(c, PASS, contents as unknown as BackupContents, FAST_KDF);
    const error = await assertRejects(() => decodeBackup(c, PASS, file), BackupError);
    assertEquals(error.code, "Invalid", `case ${i}`);
  }
});

Deno.test("restore: the rows a restored device starts with", () => {
  const rows = restoredRows(sample(true), 99);
  assertEquals(rows.identity, [{ id: "self", secretHex: "11".repeat(32) }]);
  assertEquals((rows.contacts as { restoredMs: number }[])[0].restoredMs, 99);
  assertEquals((rows.contacts as { verified: string }[])[0].verified, "compared");
  assertEquals(rows.messages.length, 1);
  assertEquals(rows.contactState, [{ peerId: "b".repeat(64), lastActivityMs: 7, unread: 1 }]);
  const bare = restoredRows({
    ...sample(false),
    settings: [{ key: "backup", value: 1 }, ...sample(false).settings],
  }, 99);
  assertEquals(bare.messages, []);
  assertEquals(bare.outbox, []);
  // Every contact has its state row, and only the person's own settings come back.
  assertEquals(bare.contactState, [{ peerId: "b".repeat(64), lastActivityMs: 5, unread: 0 }]);
  assertEquals((bare.settings as { key: string }[]).map((s) => s.key), ["turn"]);
});

Deno.test(
  "restore: back up, wipe, restore: the same identity, still paired, and the two can chat",
  withWorld(async (w) => {
    const { device: a, storage, c } = await sealedDevice(w, "a");
    const b = await w.device("b");
    await w.pair(a, b, "scan");
    await a.engine.renameContact(b.id, "Bo");
    await a.engine.sendText(b.id, "before the backup");
    await w.settle();
    const id = a.id;
    const file = await encodeBackup(c, PASS, await backupOf(w, a, storage, true), FAST_KDF);

    const restored = await restoreOnNewDevice(w, a, await decodeBackup(c, PASS, file));
    assertEquals(restored.id, id);
    const view = restored.engine.snapshot().contacts[0];
    assertEquals(view.contact.name, "Bo");
    assertEquals(typeof view.contact.restoredMs, "number");
    assertEquals((await restored.engine.messages(b.id)).map((m) => m.text), ["before the backup"]);

    await w.advance(20_000);
    assertEquals(restored.path(b), "Direct");
    assertEquals(b.path(id), "Direct");
    await restored.engine.sendText(b.id, "from the restored device");
    await b.engine.sendText(id, "to the restored device");
    await w.settle();
    assertEquals((await b.engine.messages(id)).at(-1)?.text, "to the restored device");
    assertEquals((await b.engine.messages(id)).at(-2)?.text, "from the restored device");
    assertEquals((await restored.engine.messages(b.id)).at(-1)?.text, "to the restored device");
    // The connection held: the mark comes off, in memory and in the database.
    await w.advance(RESTORED_PROVEN_MS);
    assertEquals(restored.engine.snapshot().contacts[0].contact.restoredMs, undefined);
    assertEquals(restored.eventsOf("ContactUpdated").at(-1)?.contact.restoredMs, undefined);
  }),
);

Deno.test(
  "restore: a backup older than the conversation does not connect, and the contact stays marked until added again",
  withWorld(async (w) => {
    const { device: a, storage } = await sealedDevice(w, "a");
    const b = await w.device("b");
    await w.pair(a, b);
    const contents = await backupOf(w, a, storage, false);
    // The conversation goes on after the backup: both ratchets move.
    await a.engine.sendText(b.id, "one");
    await b.engine.sendText(a.id, "two");
    await a.engine.sendText(b.id, "three");
    await w.settle();
    const id = a.id;

    const restored = await restoreOnNewDevice(w, a, contents);
    assertEquals(restored.id, id);
    await w.advance(60_000);
    // Neither side reaches a verified line, and nothing is delivered as if it had.
    assert(restored.path(b) !== "Direct", `restored: ${restored.path(b)}`);
    assert(b.path(id) !== "Direct", `other: ${b.path(id)}`);
    assertEquals(typeof restored.engine.snapshot().contacts[0].contact.restoredMs, "number");
    await w.advance(RESTORED_PROVEN_MS * 3);
    assertEquals(typeof restored.engine.snapshot().contacts[0].contact.restoredMs, "number");

    // Adding each other again makes a new session: the line opens and the mark is gone.
    const { code } = await restored.engine.createPairingCode();
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.advance(30_000);
    assertEquals(restored.path(b), "Direct");
    assertEquals(restored.engine.snapshot().contacts[0].contact.restoredMs, undefined);
    await b.engine.sendText(id, "after adding again");
    await w.settle();
    assertEquals((await restored.engine.messages(b.id)).at(-1)?.text, "after adding again");
  }),
);
