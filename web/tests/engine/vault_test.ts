// Encryption at rest (src/engine/vault.ts, sealed-storage.ts): the sealed form of a row,
// the first sealing of a plaintext database, the passphrase lock, and an engine on top.
import { assert, assertEquals, assertNotEquals, assertRejects } from "@std/assert";
import type { StoreName } from "../../src/engine/platform.ts";
import { SealedStorage } from "../../src/engine/sealed-storage.ts";
import {
  type ContactRow,
  DATA_STORES,
  MemoryStorage,
  type MessageRow,
  VAULT_STORE,
} from "../../src/engine/storage.ts";
import {
  backoffMs,
  decodeRow,
  encodeRow,
  generateDeviceKeys,
  type KeysRow,
  PAD_BLOCK,
  Sealer,
  Vault,
  VaultError,
} from "../../src/engine/vault.ts";
import { FAST_KDF, testCrypto } from "./harness/vault.ts";
import { withWorld } from "./harness/world.ts";

const PEER_A = "a".repeat(64);
const PEER_B = "b".repeat(64);
const SECRET = "5e".repeat(32);

/** A version 1 database: every store, in plaintext. */
async function plaintextDatabase(): Promise<MemoryStorage> {
  const raw = new MemoryStorage();
  const contact = (peerId: string, name: string): ContactRow => ({
    peerId,
    name,
    identityKey: "c0".repeat(32),
    addedMs: 1000,
    verified: "no",
    verifiedMs: null,
  });
  const message = (id: number, peerId: string, text: string): MessageRow => ({
    id,
    peerId,
    direction: "Sent",
    text,
    timestampMs: 2000 + id,
    state: "Sent",
  });
  await raw.write([
    { op: "put", store: "identity", value: { id: "self", secretHex: SECRET } },
    {
      op: "put",
      store: "identity",
      value: { id: "pairing", code: "ab", expiresAtMs: 5, pendingHex: "feed" },
    },
    { op: "put", store: "sessions", value: { id: "blob", json: '{"x":"ratchet-state"}' } },
    { op: "put", store: "contacts", value: contact(PEER_B, "Bo Plaintext") },
    { op: "put", store: "contacts", value: contact(PEER_A, "Ana Plaintext") },
    { op: "put", store: "messages", value: message(1, PEER_A, "first words") },
    { op: "put", store: "messages", value: message(2, PEER_B, "second words") },
    { op: "put", store: "messages", value: message(10, PEER_A, "third words") },
    {
      op: "put",
      store: "outbox",
      value: {
        id: 3,
        peerId: PEER_A,
        kind: "text",
        messageId: 10,
        text: "third words",
        createdMs: 9,
      },
    },
    { op: "put", store: "contactState", value: { peerId: PEER_A, lastActivityMs: 7, unread: 2 } },
    {
      op: "put",
      store: "settings",
      value: {
        key: "turn",
        value: { uri: "turn:t.example", username: "u", password: "turn-secret", relayOnly: false },
      },
    },
  ]);
  return raw;
}

async function everything(storage: { getAll<T>(store: StoreName): Promise<T[]> }) {
  const out: Record<string, unknown[]> = {};
  for (const store of DATA_STORES) out[store] = await storage.getAll(store);
  return out;
}

/** Everything a copy of the database would show, as one text. */
async function asKept(raw: MemoryStorage): Promise<string> {
  const rows = await raw.dump([...DATA_STORES, VAULT_STORE]);
  return JSON.stringify(
    [...rows.entries()],
    (_key, value) =>
      value instanceof Uint8Array
        ? new TextDecoder("latin1").decode(value)
        : value instanceof CryptoKey
        ? "[CryptoKey]"
        : value,
  );
}

Deno.test("row text: JSON with bytes, and nothing it cannot hold", () => {
  const row = { id: 1, bytes: new Uint8Array([0, 255, 7]), nested: { list: [1, "a", null] } };
  const back = decodeRow(encodeRow(row)) as typeof row;
  assertEquals(back, row);
  assert(back.bytes instanceof Uint8Array);
  for (const bad of [new Map(), new Set(), new ArrayBuffer(2)]) {
    let thrown: unknown;
    try {
      encodeRow({ id: 1, bad });
    } catch (error) {
      thrown = error;
    }
    assert(thrown instanceof VaultError);
  }
});

Deno.test("sealed row: a fresh nonce, padded, bound to its store and key", async () => {
  const c = await testCrypto();
  const sealer = new Sealer(c, await generateDeviceKeys(c));
  const row = {
    id: 7,
    peerId: PEER_A,
    direction: "Sent",
    text: "hello",
    timestampMs: 1,
    state: "Sent",
  };
  const one = await sealer.seal("messages", row);
  const two = await sealer.seal("messages", row);
  assertEquals(await sealer.open("messages", one), row);
  assertNotEquals(one.n, two.n);
  assertNotEquals(one.c, two.c);
  assertEquals(one.n.length, 12);
  // Ciphertext is the padded text plus the 16-byte tag: lengths come in steps.
  assertEquals((one.c.length - 16) % PAD_BLOCK, 0);
  const long = await sealer.seal("messages", { ...row, text: "x".repeat(300) });
  assertEquals((long.c.length - 16) % PAD_BLOCK, 0);
  assert(long.c.length > one.c.length);
  // The number key stays; the contact is a tag, the same for the same contact in this store.
  assertEquals(one.id, 7);
  assertEquals(one.peerId, two.peerId);
  assert(/^[0-9a-f]{32}$/.test(one.peerId as string));
  assertNotEquals(one.peerId, PEER_A);
  assertNotEquals(one.peerId, await sealer.storedKey("outbox", PEER_A));
  assertNotEquals(one.peerId, await sealer.storedKey("contacts", PEER_A));

  const corrupt = (sealed: unknown, store: StoreName = "messages") =>
    assertRejects(() => sealer.open(store, sealed), VaultError, "does not decrypt");
  // Moved to another key, to another store, or changed.
  await corrupt({ ...one, id: 8 });
  await corrupt({ ...one }, "outbox");
  const flipped = one.c.slice();
  flipped[5] ^= 1;
  await corrupt({ ...one, c: flipped });
  await corrupt({ ...one, n: two.n });
  // Another device's keys.
  const other = new Sealer(c, await generateDeviceKeys(c));
  await assertRejects(() => other.open("messages", one), VaultError);
  // A plaintext row is not taken for a sealed one.
  await assertRejects(() => sealer.open("messages", row), VaultError, "not sealed");
});

Deno.test("sealed storage: behaves as the engine's storage does", async () => {
  const c = await testCrypto();
  const raw = new MemoryStorage();
  const storage = new SealedStorage(await Vault.open(raw, c));
  const message = (id: number, peerId: string) => ({ id, peerId, text: `m${id}` });
  await storage.write([
    { op: "put", store: "contacts", value: { peerId: PEER_B, name: "B" } },
    { op: "put", store: "contacts", value: { peerId: PEER_A, name: "A" } },
    { op: "put", store: "messages", value: message(2, PEER_A) },
    { op: "put", store: "messages", value: message(1, PEER_B) },
    { op: "put", store: "messages", value: message(5, PEER_A) },
    { op: "put", store: "settings", value: { key: "turn", value: { uri: "turn:x" } } },
  ]);
  assertEquals(await storage.get("contacts", PEER_A), { peerId: PEER_A, name: "A" });
  assertEquals(await storage.get("contacts", "c".repeat(64)), undefined);
  // In the order of the real keys, whatever order the tags sort in.
  assertEquals((await storage.getAll<{ name: string }>("contacts")).map((r) => r.name), ["A", "B"]);
  assertEquals((await storage.getAll<{ id: number }>("messages")).map((r) => r.id), [1, 2, 5]);
  assertEquals(
    (await storage.getAllByPeer<{ id: number }>("messages", PEER_A)).map((r) => r.id),
    [2, 5],
  );
  assertEquals(await storage.getAllByPeer("outbox", PEER_A), []);
  assertEquals(await storage.maxKey("messages"), 5);
  assertEquals(await storage.maxKey("outbox"), 0);
  await storage.write([
    { op: "delete", store: "contacts", key: PEER_B },
    { op: "delete", store: "messages", key: 2 },
    { op: "put", store: "contacts", value: { peerId: PEER_A, name: "A again" } },
  ]);
  assertEquals(await storage.getAll("contacts"), [{ peerId: PEER_A, name: "A again" }]);
  assertEquals((await storage.getAll<{ id: number }>("messages")).map((r) => r.id), [1, 5]);
  // All or nothing.
  raw.failNextWrite = true;
  await assertRejects(() =>
    storage.write([{ op: "put", store: "contacts", value: { peerId: PEER_B, name: "B" } }])
  );
  assertEquals((await storage.getAll("contacts")).length, 1);
  // A row someone changed on disk is an error, not a missing row.
  const kept = (await raw.getAll<Record<string, unknown>>("messages"))[0];
  await raw.write([{ op: "put", store: "messages", value: { ...kept, c: new Uint8Array(144) } }]);
  await assertRejects(() => storage.getAll("messages"), VaultError);
  await storage.destroy();
  assert(raw.destroyed);
});

Deno.test("first start: a new database gets keys the browser keeps, and nothing else", async () => {
  const c = await testCrypto();
  const raw = new MemoryStorage();
  const vault = await Vault.open(raw, c);
  assertEquals(vault.locked, false);
  assertEquals(vault.hasPassphrase, false);
  assertEquals(vault.migrated, 0);
  const keys = await raw.get<KeysRow>(VAULT_STORE, "keys");
  assert(keys && keys.mode === "device");
  assertEquals(keys.enc.extractable, false);
  assertEquals(keys.mac.extractable, false);
  assertEquals(keys.enc.algorithm.name, "AES-GCM");
  await assertRejects(() => crypto.subtle.exportKey("raw", keys.enc));
  for (const store of DATA_STORES) assertEquals(await raw.getAll(store), []);
});

Deno.test("migration: a plaintext database is sealed in place, nothing lost", async () => {
  const c = await testCrypto();
  const raw = await plaintextDatabase();
  const before = await everything(raw);
  const plain = await asKept(raw);
  for (
    const secret of [
      SECRET,
      "ratchet-state",
      "feed",
      "turn-secret",
      "Ana Plaintext",
      "first words",
      PEER_A,
    ]
  ) {
    assert(plain.includes(secret), secret);
  }

  const vault = await Vault.open(raw, c);
  assertEquals(vault.migrated, 11);
  const storage = new SealedStorage(vault);
  assertEquals(await everything(storage), before);
  assertEquals(
    (await storage.getAllByPeer<MessageRow>("messages", PEER_A)).map((m) => m.text),
    ["first words", "third words"],
  );
  assertEquals((await storage.get<{ secretHex: string }>("identity", "self"))?.secretHex, SECRET);

  // What a copy of the database shows now: none of it.
  const kept = await asKept(raw);
  for (
    const secret of [
      SECRET,
      "ratchet-state",
      "feed",
      "turn-secret",
      "Plaintext",
      "words",
      PEER_A,
      PEER_B,
      "self",
      "pairing",
      "blob",
      '"turn"',
      "timestampMs",
    ]
  ) {
    assertEquals(kept.includes(secret), false, secret);
  }
  // As many rows as before, and none under a clear text key.
  for (const store of DATA_STORES) {
    assertEquals((await raw.getAll(store)).length, before[store].length, store);
  }
  assertEquals(await raw.get("identity", "self"), undefined);
  assertEquals(await raw.get("contacts", PEER_A), undefined);

  // The next start reads the same rows with the stored keys and migrates nothing.
  const again = await Vault.open(raw, c);
  assertEquals(again.migrated, 0);
  assertEquals(await everything(new SealedStorage(again)), before);
});

Deno.test("migration: a write that fails leaves the plaintext database as it was", async () => {
  const c = await testCrypto();
  const raw = await plaintextDatabase();
  const before = await asKept(raw);
  raw.failNextWrite = true;
  await assertRejects(() => Vault.open(raw, c));
  assertEquals(await asKept(raw), before);
  assertEquals(await raw.get(VAULT_STORE, "keys"), undefined);
  const storage = new SealedStorage(await Vault.open(raw, c));
  assertEquals((await storage.getAll("messages")).length, 3);
});

Deno.test("migration: two tabs starting at once agree on one set of keys", async () => {
  const c = await testCrypto();
  const raw = await plaintextDatabase();
  const before = await everything(raw);
  const [one, two] = await Promise.all([Vault.open(raw, c), Vault.open(raw, c)]);
  assertEquals([one.migrated, two.migrated].sort(), [0, 11]);
  assertEquals(await everything(new SealedStorage(one)), before);
  assertEquals(await everything(new SealedStorage(two)), before);
});

Deno.test("migration: sealed rows without their keys are never overwritten", async () => {
  const c = await testCrypto();
  const raw = await plaintextDatabase();
  await Vault.open(raw, c);
  await raw.write([{ op: "delete", store: VAULT_STORE, key: "keys" }]);
  const before = await asKept(raw);
  await assertRejects(() => Vault.open(raw, c), VaultError, "keys are missing");
  assertEquals(await asKept(raw), before);
});

Deno.test("a database from a newer app is refused, not rewritten", async () => {
  const c = await testCrypto();
  const raw = new MemoryStorage();
  await Vault.open(raw, c);
  const keys = await raw.get<KeysRow>(VAULT_STORE, "keys");
  await raw.write([{ op: "put", store: VAULT_STORE, value: { ...keys, format: 2 } }]);
  const error = await assertRejects(() => Vault.open(raw, c), VaultError);
  assertEquals(error.code, "Unsupported");
});

Deno.test("passphrase: lock, unlock, wrong passphrase, change, remove", async () => {
  const clock = { t: 1_000_000, now: () => clock.t };
  const c = await testCrypto(clock);
  const raw = await plaintextDatabase();
  const before = await everything(raw);
  const vault = await Vault.open(raw, c);
  const storage = new SealedStorage(vault);
  const tagBefore = (await raw.getAll<{ peerId: string }>("contacts")).map((r) => r.peerId);

  const weak = await assertRejects(() => vault.setPassphrase("short", FAST_KDF), VaultError);
  assertEquals(weak.code, "Weak");
  await vault.setPassphrase("correct horse battery", FAST_KDF);
  assertEquals(vault.hasPassphrase, true);
  assertEquals(vault.locked, false);
  // Still readable in this session, and every row is under new keys.
  assertEquals(await everything(storage), before);
  const tagAfter = (await raw.getAll<{ peerId: string }>("contacts")).map((r) => r.peerId);
  assertEquals(tagAfter.filter((tag) => tagBefore.includes(tag)), []);
  for (const store of DATA_STORES) {
    assertEquals((await raw.getAll(store)).length, before[store].length, store);
  }
  // No key object is kept any more: only the wrapped bytes and how to derive their key.
  const row = await raw.get<KeysRow>(VAULT_STORE, "keys");
  assert(row && row.mode === "passphrase");
  assertEquals(Object.keys(row).sort(), [
    "format",
    "id",
    "kdf",
    "mode",
    "nonce",
    "salt",
    "wrapped",
  ]);
  assertEquals(row.wrapped.length, 64 + 16);
  assertEquals((await asKept(raw)).includes("correct horse"), false);
  const twice = await assertRejects(
    () => vault.setPassphrase("another passphrase", FAST_KDF),
    VaultError,
  );
  assertEquals(twice.code, "State");

  // The next start is locked.
  const locked = await Vault.open(raw, c);
  assertEquals(locked.locked, true);
  assertEquals(locked.hasPassphrase, true);
  const lockedStorage = new SealedStorage(locked);
  assertEquals(
    (await assertRejects(() => lockedStorage.getAll("contacts"), VaultError)).code,
    "Locked",
  );
  assertEquals(
    (await assertRejects(
      () => lockedStorage.write([{ op: "delete", store: "contacts", key: PEER_A }]),
      VaultError,
    )).code,
    "Locked",
  );
  const wrong = await assertRejects(() => locked.unlock("correct horse batterx"), VaultError);
  assertEquals(wrong.code, "WrongPassphrase");
  assertEquals(locked.locked, true);
  await locked.unlock("correct horse battery");
  assertEquals(locked.locked, false);
  assertEquals(await everything(lockedStorage), before);
  assertEquals(await raw.get(VAULT_STORE, "attempts"), undefined);
  // The same passphrase in another Unicode form is the same passphrase (NFKC).
  const composed = await Vault.open(raw, c);
  await composed.unlock("correct horse battery".normalize("NFD"));

  // Change: the current passphrase is asked for, and only the new one opens afterwards.
  const badChange = await assertRejects(
    () => locked.changePassphrase("not the passphrase", "a new passphrase", FAST_KDF),
    VaultError,
  );
  assertEquals(badChange.code, "WrongPassphrase");
  await locked.changePassphrase("correct horse battery", "a new passphrase", FAST_KDF);
  assertEquals(await everything(lockedStorage), before);
  const afterChange = await Vault.open(raw, c);
  assertEquals(
    (await assertRejects(() => afterChange.unlock("correct horse battery"), VaultError)).code,
    "WrongPassphrase",
  );
  await afterChange.unlock("a new passphrase");
  assertEquals(await everything(new SealedStorage(afterChange)), before);

  // Remove: back to keys the browser keeps; the next start needs no passphrase.
  const afterStorage = new SealedStorage(afterChange);
  assertEquals(
    (await assertRejects(() => afterChange.removePassphrase("wrong wrong wrong"), VaultError)).code,
    "WrongPassphrase",
  );
  await afterChange.removePassphrase("a new passphrase");
  assertEquals(afterChange.hasPassphrase, false);
  assertEquals(await everything(afterStorage), before);
  const open = await Vault.open(raw, c);
  assertEquals(open.locked, false);
  assertEquals(await everything(new SealedStorage(open)), before);
  assertEquals(
    (await assertRejects(() => open.removePassphrase("a new passphrase"), VaultError)).code,
    "State",
  );
});

Deno.test("passphrase: wrong ones are counted across restarts and slow the next try", async () => {
  const clock = { t: 5_000_000, now: () => clock.t };
  const c = await testCrypto(clock);
  const raw = new MemoryStorage();
  await (await Vault.open(raw, c)).setPassphrase("the right passphrase", FAST_KDF);
  assertEquals([0, 1, 2, 3, 4, 5, 9, 20].map(backoffMs), [
    0,
    0,
    0,
    5000,
    10000,
    20000,
    300000,
    300000,
  ]);

  const wrong = async () => {
    // A fresh start each time: the count is kept in the database, not in the page.
    const vault = await Vault.open(raw, c);
    return await assertRejects(() => vault.unlock("the wrong passphrase"), VaultError);
  };
  assertEquals((await wrong()).code, "WrongPassphrase");
  assertEquals((await wrong()).code, "WrongPassphrase");
  assertEquals(await (await Vault.open(raw, c)).retryAtMs(), 0);
  assertEquals((await wrong()).code, "WrongPassphrase");
  // Three in a row: five seconds, also for the right passphrase.
  const vault = await Vault.open(raw, c);
  assertEquals(await vault.retryAtMs(), clock.t + 5000);
  const soon = await assertRejects(() => vault.unlock("the right passphrase"), VaultError);
  assertEquals(soon.code, "TooSoon");
  assertEquals(soon.retryAtMs, clock.t + 5000);
  assertEquals(vault.locked, true);
  // Setting the clock back does not help.
  clock.t -= 60_000;
  assertEquals(
    (await assertRejects(() => vault.unlock("the right passphrase"), VaultError)).code,
    "TooSoon",
  );
  clock.t += 60_000 + 5000;
  assertEquals((await wrong()).code, "WrongPassphrase");
  assertEquals(await vault.retryAtMs(), clock.t + 10_000);
  clock.t += 10_000;
  await vault.unlock("the right passphrase");
  assertEquals(await vault.retryAtMs(), 0);
  assertEquals(await raw.get(VAULT_STORE, "attempts"), undefined);
});

Deno.test("passphrase: a changed keys row does not open", async () => {
  const c = await testCrypto();
  const raw = new MemoryStorage();
  await (await Vault.open(raw, c)).setPassphrase("the right passphrase", FAST_KDF);
  const row = await raw.get<Extract<KeysRow, { mode: "passphrase" }>>(VAULT_STORE, "keys");
  assert(row);
  const tries: KeysRow[] = [
    { ...row, kdf: { ...row.kdf, passes: 2 } },
    { ...row, salt: row.salt.map((b, i) => (i === 0 ? b ^ 1 : b)) },
    { ...row, wrapped: row.wrapped.map((b, i) => (i === 40 ? b ^ 1 : b)) },
    { ...row, nonce: row.nonce.map((b, i) => (i === 0 ? b ^ 1 : b)) },
  ];
  for (const changed of tries) {
    await raw.write([
      { op: "put", store: VAULT_STORE, value: changed },
      { op: "delete", store: VAULT_STORE, key: "attempts" },
    ]);
    const vault = await Vault.open(raw, c);
    const error = await assertRejects(() => vault.unlock("the right passphrase"), VaultError);
    assertEquals(error.code, "WrongPassphrase");
  }
  // Settings no version of this app writes are refused before anything is derived.
  await raw.write([
    { op: "put", store: VAULT_STORE, value: { ...row, kdf: { ...row.kdf, memoryKiB: 2 ** 30 } } },
    { op: "delete", store: VAULT_STORE, key: "attempts" },
  ]);
  const vault = await Vault.open(raw, c);
  assertEquals(
    (await assertRejects(() => vault.unlock("the right passphrase"), VaultError)).code,
    "Unsupported",
  );
});

Deno.test(
  "engine: runs on sealed storage, and what it keeps is unreadable in the database",
  withWorld(async (w) => {
    const c = await testCrypto(w.clock);
    const rawA = new MemoryStorage();
    const a = await w.device("a", {
      storage: rawA,
      engineStorage: new SealedStorage(await Vault.open(rawA, c)),
    });
    const b = await w.device("b");
    await w.pair(a, b);
    await a.engine.renameContact(b.id, "Bo Sealed");
    await a.engine.sendText(b.id, "over the sealed store");
    await b.engine.sendText(a.id, "and back again");
    await w.settle();
    assertEquals((await a.engine.messages(b.id)).map((m) => m.text), [
      "over the sealed store",
      "and back again",
    ]);
    const kept = await asKept(rawA);
    for (
      const secret of [a.wasm.export_secret_key(), "Bo Sealed", "sealed store", "back again", b.id]
    ) {
      assertEquals(kept.includes(secret), false, secret);
    }
    for (const line of a.logs) assertEquals(line.includes(a.wasm.export_secret_key()), false);

    // A restart from the same database: the same identity, contact, history and session.
    const id = a.id;
    await a.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== a);
    const again = await w.device("a", {
      storage: rawA,
      engineStorage: new SealedStorage(await Vault.open(rawA, c)),
    });
    assertEquals(again.id, id);
    await w.advance(20_000);
    assertEquals(again.path(b), "Direct");
    await again.engine.sendText(b.id, "after the restart");
    await w.settle();
    assertEquals((await b.engine.messages(id)).at(-1)?.text, "after the restart");
  }),
);

Deno.test(
  "engine: a plaintext database of the earlier version starts sealed, with everything in it",
  withWorld(async (w) => {
    const c = await testCrypto(w.clock);
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await a.engine.sendText(b.id, "written in plaintext");
    await w.settle();
    const id = a.id;
    const secret = a.wasm.export_secret_key();
    const raw = a.storage;
    assert((await asKept(raw)).includes(secret));
    await a.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== a);

    const vault = await Vault.open(raw, c);
    assert(vault.migrated > 0);
    assertEquals((await asKept(raw)).includes(secret), false);
    const again = await w.device("a", { storage: raw, engineStorage: new SealedStorage(vault) });
    assertEquals(again.id, id);
    assertEquals((await again.engine.messages(b.id)).map((m) => m.text), ["written in plaintext"]);
    await w.advance(20_000);
    assertEquals(again.path(b), "Direct");
    await b.engine.sendText(id, "read after the migration");
    await w.settle();
    assertEquals((await again.engine.messages(b.id)).at(-1)?.text, "read after the migration");
  }),
);
