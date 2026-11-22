// File transfer (PNP-010) in the web engine: offer, accept, decline, cancel, the record
// stream over a channel of its own, resume after a lost connection and after a reload,
// tampering, the limits, and what is stored. The crypto and the protocol rules are the real
// parolnet-wasm; the network, clock and storage are fakes.
import { assert, assertEquals, assertRejects } from "@std/assert";
import { MemoryFileStore } from "../../src/engine/files.ts";
import type { FileSource } from "../../src/engine/platform.ts";
import { SealedStorage } from "../../src/engine/sealed-storage.ts";
import { MemoryStorage, type SettingRow } from "../../src/engine/storage.ts";
import { Vault, VaultError } from "../../src/engine/vault.ts";
import { FAST_KDF, testCrypto } from "./harness/vault.ts";
import { SEGMENT_RECORDS, type TransferRow } from "../../src/engine/transfers.ts";
import { EngineError, type TransferInfo } from "../../src/engine/types.ts";
import type { FakeDc } from "./harness/fakes.ts";
import { type Device, withWorld, type World } from "./harness/world.ts";

const CHUNK = 65_519;

function bytes(size: number, seed = 1): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(size);
  let x = (0x9e3779b9 ^ seed) >>> 0;
  for (let i = 0; i < size; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

/** A picked file. `reads` counts the slices taken from it. */
function fileOf(
  name: string,
  data: Uint8Array<ArrayBuffer>,
  type = "",
): FileSource & { reads: number } {
  return {
    name,
    size: data.length,
    type,
    reads: 0,
    slice(start: number, end: number) {
      this.reads++;
      const part = data.slice(start, end);
      return { arrayBuffer: () => Promise.resolve(part.buffer) };
    },
  };
}

async function sha256(data: Uint8Array<ArrayBuffer>): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function received(d: Device, id: string): Promise<Uint8Array<ArrayBuffer>> {
  const blob = await d.engine.transferFile(id);
  assert(blob, "the received file is available");
  return new Uint8Array(await blob.arrayBuffer());
}

function last(d: Device, id: string): TransferInfo {
  const all = d.eventsOf("Transfer").filter((e) => e.transfer.id === id);
  assert(all.length > 0, `no transfer event for ${id} on ${d.name}`);
  return all.at(-1)!.transfer;
}

function states(d: Device, id: string): string[] {
  const out: string[] = [];
  for (const e of d.eventsOf("Transfer")) {
    if (e.transfer.id !== id) continue;
    const s = e.transfer.state.kind + (e.transfer.pending ? "*" : "");
    if (out.at(-1) !== s) out.push(s);
  }
  return out;
}

function fileChannels(d: Device): FakeDc[] {
  return d.pcs.flatMap((pc) => pc.channels).filter((c) => c.label.startsWith("pn-file/"));
}

async function rowOf(d: Device, id: string): Promise<TransferRow | undefined> {
  const s = await d.storage.get<SettingRow>("settings", `transfer:${id}`);
  return s?.value as TransferRow | undefined;
}

/**
 * Let a transfer run: `settle` until nothing moves any more (a record takes several turns
 * of the event loop, a file takes many records).
 */
async function flow(w: World): Promise<void> {
  const activity = () =>
    w.devices.reduce(
      (n, d) =>
        n + d.events.length +
        d.pcs.reduce((m, pc) => m + pc.channels.reduce((k, c) => k + c.sentBinary.length, 0), 0),
      w.rtc.heldBinary.length,
    );
  let quiet = 0;
  for (let i = 0; i < 20_000 && quiet < 3; i++) {
    const before = activity();
    await w.settle();
    quiet = activity() === before ? quiet + 1 : 0;
  }
}

/** Let exactly `count` held binary messages through (see `FakeRtc.holdBinary`). */
async function deliver(w: World, count: number): Promise<void> {
  let left = count;
  for (let idle = 0; left > 0 && idle < 5;) {
    const n = Math.min(left, w.rtc.heldBinary.length);
    if (n === 0) {
      idle++;
      await w.settle();
      continue;
    }
    idle = 0;
    w.rtc.releaseBinary(n);
    left -= n;
    await flow(w);
  }
  if (left > 0) throw new Error(`only ${count - left} of ${count} messages were sent`);
}

/** The transfer as the engine reports it now (events of progress are throttled). */
async function now(d: Device, id: string): Promise<TransferInfo> {
  const t = (await d.engine.transfers()).find((t) => t.id === id);
  assert(t, `no transfer ${id} on ${d.name}`);
  return t;
}

async function pairWithFiles(w: World): Promise<[Device, Device, MemoryFileStore]> {
  const a = await w.device("a");
  const store = new MemoryFileStore();
  const b = await w.device("b", { files: store });
  await w.pair(a, b);
  return [a, b, store];
}

Deno.test(
  "transfer: a file is offered in the session, flows on its own channel and verifies",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    const data = bytes(3 * CHUNK + 1234);
    const offered = await a.engine.offerFile(b.id, fileOf("holiday photo.jpg", data, "image/jpeg"));
    assertEquals(offered.direction, "Sent");
    assertEquals(offered.state.kind, "Offered");
    assertEquals(offered.pending, false, "delivered at once over the verified channel");
    await flow(w);

    const incoming = last(b, offered.id);
    assertEquals(incoming.direction, "Received");
    assertEquals(incoming.state.kind, "Offered");
    assertEquals(incoming.name, "holiday photo.jpg");
    assertEquals(incoming.size, data.length);
    assertEquals(incoming.mime, "image/jpeg");
    assertEquals(incoming.available, false);
    // An offer counts as something new in the conversation.
    assertEquals(b.engine.snapshot().contacts[0].unread, 1);
    assertEquals(
      fileChannels(a).length + fileChannels(b).length,
      0,
      "nothing flows before the accept",
    );

    await b.engine.acceptTransfer(offered.id);
    await flow(w);
    assertEquals(last(b, offered.id).state.kind, "Complete");
    assertEquals(last(b, offered.id).bytesDone, data.length);
    assertEquals(last(b, offered.id).available, true);
    assertEquals(await received(b, offered.id), data);
    // The sender is complete on the receiver's word.
    assertEquals(last(a, offered.id).state.kind, "Complete");
    assertEquals(states(a, offered.id), ["Offered*", "Offered", "Waiting", "Active", "Complete"]);
    assertEquals(states(b, offered.id), [
      "Offered",
      "Waiting*",
      "Waiting",
      "Active",
      "Complete*",
      "Complete",
    ]);

    // On the wire: one channel `pn-file/<id>`, opened by the receiver, 64 KiB records, and
    // nothing of the file or its name in the clear anywhere.
    const [channel] = fileChannels(b);
    assertEquals(channel.label, `pn-file/${offered.id}`);
    assertEquals(channel.sentBinary.length, 1, "the receiver sends RESUME and nothing else");
    assertEquals(channel.sentBinary[0].length, 21);
    assertEquals(channel.sentBinary[0][0], 0x01);
    const sent = fileChannels(a)[0].sentBinary;
    assertEquals(sent.map((m) => m[0]), [0x02, 0x03, 0x03, 0x03, 0x03]);
    assertEquals(sent.slice(1).map((m) => m.length), [65536, 65536, 65536, 1 + 1234 + 16]);
    const wire = a.pcs.flatMap((pc) => pc.channels).flatMap((c) => c.sent).join("");
    assert(!wire.includes("holiday"));
    const plain = Array.from(data.subarray(0, 32)).join(",");
    assert(!sent.some((m) => Array.from(m).join(",").includes(plain)));

    // The keys are gone from storage once the transfer is over, on both sides.
    assertEquals((await rowOf(a, offered.id))?.key, null);
    assertEquals((await rowOf(b, offered.id))?.key, null);
    assertEquals((await a.engine.transfers(b.id)).length, 1);
  }),
);

Deno.test(
  "transfer: empty, one-byte and exactly-one-record files",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    for (const size of [0, 1, CHUNK, CHUNK + 1]) {
      const data = bytes(size, size);
      const o = await a.engine.offerFile(b.id, fileOf(`f${size}.bin`, data));
      await flow(w);
      await b.engine.acceptTransfer(o.id);
      await flow(w);
      assertEquals(last(b, o.id).state.kind, "Complete", `size ${size}`);
      assertEquals(last(a, o.id).state.kind, "Complete", `size ${size}`);
      if (size === 0) {
        // Nothing to store: the transfer is complete and there is no file to save.
        assertEquals((await received(b, o.id)).length, 0);
      } else {
        assertEquals(await received(b, o.id), data);
      }
    }
  }),
);

Deno.test(
  "transfer: decline, cancel by either side, and commands that do not apply",
  withWorld(async (w) => {
    const [a, b, store] = await pairWithFiles(w);
    const data = bytes(2 * CHUNK);

    const declined = await a.engine.offerFile(b.id, fileOf("a.bin", data));
    await flow(w);
    assertEquals((await b.engine.declineTransfer(declined.id)).state.kind, "Declined");
    await flow(w);
    assertEquals(last(a, declined.id).state.kind, "Declined");
    await assertRejects(() => b.engine.acceptTransfer(declined.id), EngineError);
    assertEquals(fileChannels(b).length, 0);

    // Withdrawn by the sender before an answer.
    const withdrawn = await a.engine.offerFile(b.id, fileOf("b.bin", data));
    await flow(w);
    const c = await a.engine.cancelTransfer(withdrawn.id);
    assertEquals(c.state, { kind: "Cancelled", byPeer: false, reason: "User" });
    await flow(w);
    assertEquals(last(b, withdrawn.id).state, { kind: "Cancelled", byPeer: true, reason: "User" });
    await assertRejects(() => b.engine.acceptTransfer(withdrawn.id), EngineError);
    await assertRejects(() => a.engine.cancelTransfer(withdrawn.id), EngineError);

    // Cancelled by the receiver in the middle: the records stop and nothing is kept.
    w.rtc.holdBinary = true;
    const cut = await a.engine.offerFile(b.id, fileOf("c.bin", bytes(40 * CHUNK)));
    await flow(w);
    await b.engine.acceptTransfer(cut.id);
    await flow(w);
    w.rtc.releaseBinary(6); // RESUME, START and a few records
    await flow(w);
    assertEquals(last(b, cut.id).state.kind, "Active");
    await b.engine.cancelTransfer(cut.id);
    w.rtc.holdBinary = false;
    w.rtc.releaseBinary();
    await flow(w);
    assertEquals(last(b, cut.id).state, { kind: "Cancelled", byPeer: false, reason: "User" });
    assertEquals(last(a, cut.id).state, { kind: "Cancelled", byPeer: true, reason: "User" });
    assertEquals(await store.segments(cut.id), 0, "what was received is removed");
    assertEquals(await b.engine.transferFile(cut.id), null);
    assert(fileChannels(a).every((ch) => ch.readyState === "closed"));
    const sentBefore = fileChannels(a).at(-1)!.sentBinary.length;
    await w.advance(5_000);
    await flow(w);
    assertEquals(
      fileChannels(a).at(-1)!.sentBinary.length,
      sentBefore,
      "no record after the cancel",
    );

    // What cannot be offered or acted on.
    await assertRejects(() => a.engine.offerFile("00".repeat(32), fileOf("x", data)), EngineError);
    await assertRejects(() => a.engine.acceptTransfer("nope"), EngineError);
    await assertRejects(() => a.engine.acceptTransfer(cut.id), EngineError);
    await assertRejects(() => b.engine.removeTransfer("nope"), EngineError);

    // A finished transfer can be taken out of the conversation.
    await b.engine.removeTransfer(cut.id);
    assertEquals((await b.engine.transfers()).map((t) => t.id), [declined.id, withdrawn.id]);
    assertEquals(b.eventsOf("TransferRemoved").map((e) => e.id), [cut.id]);
    assertEquals(await rowOf(b, cut.id), undefined);
  }),
);

Deno.test(
  "transfer: an offer made while the contact is away waits on this device and survives nothing less than a reload",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    for (const pc of b.pcs) pc.close();
    w.relay.down = true;
    w.relay.socketOf(b.id)?.drop();
    await flow(w);
    const data = bytes(CHUNK + 5);
    const o = await a.engine.offerFile(b.id, fileOf("later.txt", data, "text/plain"));
    assertEquals(o.pending, true, "the offer waits on this device");
    assertEquals(o.state.kind, "Offered");
    assertEquals((await rowOf(a, o.id))?.pending, { t: "offer" });
    assertEquals(b.eventsOf("Transfer").length, 0);

    w.relay.down = false;
    await w.advance(120_000);
    await flow(w);
    assertEquals(a.path(b), "Direct");
    assertEquals(last(a, o.id).pending, false);
    assertEquals(last(b, o.id).state.kind, "Offered");
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    assertEquals(await received(b, o.id), data);
  }),
);

Deno.test(
  "transfer: a lost connection resumes at the record the receiver names",
  withWorld(async (w) => {
    const [a, b, store] = await pairWithFiles(w);
    const records = 2 * SEGMENT_RECORDS + 40;
    const data = bytes(records * CHUNK - 99);
    const source = fileOf("big.bin", data);
    const o = await a.engine.offerFile(b.id, source);
    await flow(w);
    w.rtc.holdBinary = true;
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    // RESUME, START and 300 records arrive; then the connection is cut.
    await deliver(w, 2 + 300);
    assertEquals((await now(b, o.id)).state.kind, "Active");
    assertEquals((await now(b, o.id)).bytesDone, 300 * CHUNK);
    w.rtc.heldBinary = [];
    b.cut();
    await flow(w);
    assertEquals(last(b, o.id).state.kind, "Waiting");
    assertEquals(last(a, o.id).state.kind, "Waiting");
    // What arrived is stored: one full segment, and the rest of the attempt as another.
    assertEquals((await rowOf(b, o.id))?.segs, [SEGMENT_RECORDS, 300 - SEGMENT_RECORDS]);
    assertEquals(await store.segments(o.id), 2);

    w.rtc.holdBinary = false;
    await w.advance(60_000);
    await flow(w);
    assertEquals(a.path(b), "Direct", "the connection came back");
    assertEquals(last(b, o.id).state.kind, "Complete");
    assertEquals(last(a, o.id).state.kind, "Complete");
    assertEquals(await received(b, o.id), data);

    // The second channel started at record 300: RESUME says so and START repeats it, and
    // only the missing records were sealed again.
    const channels = fileChannels(b);
    assertEquals(channels.length, 2);
    const resume = channels[1].sentBinary[0];
    assertEquals(new DataView(resume.buffer).getUint32(1), 300);
    const second = fileChannels(a)[1].sentBinary;
    assertEquals(new DataView(second[0].buffer).getUint32(1), 300);
    assertEquals(second.length, 1 + records - 300);
    // The two attempts used different nonces and salts.
    assert(resume.slice(5).join() !== channels[0].sentBinary[0].slice(5).join());
    assert(second[0].slice(5).join() !== fileChannels(a)[0].sentBinary[0].slice(5).join());
  }),
);

Deno.test(
  "transfer: a received part survives a reload when the store does, and is hashed again",
  withWorld(async (w) => {
    const [a, b, store] = await pairWithFiles(w);
    const records = SEGMENT_RECORDS + 30;
    const data = bytes(records * CHUNK);
    const o = await a.engine.offerFile(b.id, fileOf("part.bin", data));
    await flow(w);
    w.rtc.holdBinary = true;
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    await deliver(w, 2 + SEGMENT_RECORDS + 10);
    w.rtc.heldBinary = [];

    // The page reloads: a new engine over the same storage and the same file store.
    // (Nothing is delivered for now, so that the state after the reload can be looked at.)
    const b2 = await w.restart(b, { files: store });
    const kept = (await b2.engine.transfers())[0];
    assert(kept.state.kind === "Waiting" || kept.state.kind === "Active", kept.state.kind);
    assertEquals(kept.bytesDone, (SEGMENT_RECORDS + 10) * CHUNK);
    assertEquals((await rowOf(b2, o.id))?.key?.length, 64, "the key is still stored");
    assertEquals((await rowOf(b2, o.id))?.segs, [SEGMENT_RECORDS, 10]);
    w.rtc.holdBinary = false;
    w.rtc.releaseBinary();
    await w.advance(120_000);
    await flow(w);
    assertEquals(last(b2, o.id).state.kind, "Complete");
    assertEquals(await received(b2, o.id), data);
    assertEquals(last(a, o.id).state.kind, "Complete");
    const resume = fileChannels(b2).at(-1)!.sentBinary[0];
    assertEquals(new DataView(resume.buffer).getUint32(1), SEGMENT_RECORDS + 10);
  }),
);

Deno.test(
  "transfer: a stored part that changed at rest is not used, and the file starts over",
  withWorld(async (w) => {
    const [a, b, store] = await pairWithFiles(w);
    const data = bytes(40 * CHUNK);
    const o = await a.engine.offerFile(b.id, fileOf("x.bin", data));
    await flow(w);
    w.rtc.holdBinary = true;
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    await deliver(w, 2 + 20);
    w.rtc.heldBinary = [];
    w.rtc.holdBinary = false;
    const b2shutdown = b.engine.shutdown();
    await b2shutdown;
    assertEquals((await rowOf(b, o.id))?.segs, [20]);
    // Someone edits the stored segment while the app is closed.
    const stored = await store.readSegment(o.id, 0);
    stored[1000] ^= 0x01;
    const writer = await store.writer(o.id, 0);
    await writer.write(stored);
    await writer.close();
    w.devices = w.devices.filter((d) => d !== b);
    const b2 = await w.device("b", { storage: b.storage, files: store });
    await w.advance(120_000);
    await flow(w);
    // The segment does not open, so nothing of it reaches the hash or the person: the
    // receiver asks for the file from its first record and ends with the genuine one.
    assertEquals(last(b2, o.id).state.kind, "Complete");
    assertEquals(last(a, o.id).state.kind, "Complete");
    assertEquals(await received(b2, o.id), data);
    assertEquals(new DataView(fileChannels(b2).at(-1)!.sentBinary[0].buffer).getUint32(1), 0);
    assertEquals((await rowOf(b2, o.id))?.segs, [40]);
    assert(!b2.eventsOf("Notice").some((n) => n.code === "Transfer"));

    // The same once the file is complete: a changed segment is no file to save.
    const whole = await store.readSegment(o.id, 0);
    whole[whole.length - 1] ^= 0x01;
    const again = await store.writer(o.id, 0);
    await again.write(whole);
    await again.close();
    assertEquals(await b2.engine.transferFile(o.id), null);
  }),
);

Deno.test(
  "transfer: what is stored of a file is sealed, and follows the lock and a change of keys",
  withWorld(async (w) => {
    const c = await testCrypto(w.clock);
    const raw = new MemoryStorage();
    const vault = await Vault.open(raw, c);
    // One view of the database per vault: the engine's, which this test reads through too.
    const sealed = new SealedStorage(vault);
    const store = new MemoryFileStore();
    const a = await w.device("a");
    const b = await w.device("b", { storage: raw, engineStorage: sealed, files: store });
    await w.pair(a, b);
    const records = SEGMENT_RECORDS + 30;
    const data = bytes(records * CHUNK);
    const o = await a.engine.offerFile(b.id, fileOf("sealed.bin", data));
    await flow(w);
    w.rtc.holdBinary = true;
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    await deliver(w, 2 + SEGMENT_RECORDS + 10);
    w.rtc.heldBinary = [];

    // The first segment is stored: a header, and every record with a tag of its own.
    // Nothing of the file is in it.
    assertEquals(await store.segments(o.id), 1);
    const kept = await store.readSegment(o.id, 0);
    assertEquals(kept.length, 17 + SEGMENT_RECORDS * (CHUNK + 16));
    const latin1 = new TextDecoder("latin1");
    const text = latin1.decode(kept);
    for (const at of [0, CHUNK, 77 * CHUNK + 5, SEGMENT_RECORDS * CHUNK - 32]) {
      assert(!text.includes(latin1.decode(data.subarray(at, at + 32))), `plaintext at ${at}`);
    }
    // Its key is in the transfer's row and nowhere readable.
    const row = (await sealed.get<SettingRow>("settings", `transfer:${o.id}`))?.value as
      | TransferRow
      | undefined;
    assertEquals(row?.storeKey?.length, 64);
    assert(row?.storeKey !== row?.key, "not the transfer's own file key");
    const database = JSON.stringify(
      [...(await raw.dump(["settings"])).entries()],
      (_key, value) => value instanceof Uint8Array ? latin1.decode(value) : value,
    );
    assert(!database.includes(row!.storeKey!));
    assert(!database.includes("sealed.bin"));

    // A passphrase is set while the transfer waits: every row is sealed again under new
    // keys, the file's key with them. Then the page reloads.
    await vault.setPassphrase("four unrelated plain words", FAST_KDF);
    await b.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== b);
    await w.settle();
    const locked = await Vault.open(raw, c);
    assert(locked.locked);
    const reopened = new SealedStorage(locked);
    // Locked, nothing says what the key is: the stored part cannot be opened.
    const error = await assertRejects(
      () => reopened.get("settings", `transfer:${o.id}`),
      VaultError,
    );
    assertEquals(error.code, "Locked");

    await locked.unlock("four unrelated plain words");
    const b2 = await w.device("b", { storage: raw, engineStorage: reopened, files: store });
    const waiting = (await b2.engine.transfers())[0];
    assertEquals(waiting.bytesDone, (SEGMENT_RECORDS + 10) * CHUNK);
    w.rtc.holdBinary = false;
    w.rtc.releaseBinary();
    await w.advance(120_000);
    await flow(w);
    assertEquals(last(b2, o.id).state.kind, "Complete");
    assertEquals(last(a, o.id).state.kind, "Complete");
    assertEquals(await received(b2, o.id), data);
    // It went on where it was: the part stored before the change of keys was read back.
    const resume = fileChannels(b2).at(-1)!.sentBinary[0];
    assertEquals(new DataView(resume.buffer).getUint32(1), SEGMENT_RECORDS + 10);

    // Cancelled or removed, a transfer leaves neither a file nor its key.
    await b2.engine.removeTransfer(o.id);
    assertEquals(await store.segments(o.id), 0);
    assertEquals(await reopened.get("settings", `transfer:${o.id}`), undefined);
  }),
);

Deno.test(
  "transfer: without a persistent store a reload starts the file over",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    const data = bytes(30 * CHUNK);
    const o = await a.engine.offerFile(b.id, fileOf("mem.bin", data));
    await flow(w);
    w.rtc.holdBinary = true;
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    await deliver(w, 2 + 12);
    w.rtc.heldBinary = [];
    // A fresh memory store, as after a reload of a browser without OPFS.
    const b2 = await w.restart(b, { files: new MemoryFileStore() });
    assertEquals((await b2.engine.transfers())[0].bytesDone, 0);
    assertEquals((await rowOf(b2, o.id))?.segs, []);
    w.rtc.holdBinary = false;
    w.rtc.releaseBinary();
    await w.advance(120_000);
    await flow(w);
    assertEquals(last(b2, o.id).state.kind, "Complete");
    assertEquals(await received(b2, o.id), data);
    assertEquals(new DataView(fileChannels(b2).at(-1)!.sentBinary[0].buffer).getUint32(1), 0);
  }),
);

Deno.test(
  "transfer: a reload of the sending page cancels what it was sending",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    const o = await a.engine.offerFile(b.id, fileOf("gone.bin", bytes(5 * CHUNK)));
    await flow(w);
    assertEquals(last(b, o.id).state.kind, "Offered");
    const a2 = await w.restart(a);
    const mine = (await a2.engine.transfers())[0];
    assertEquals(mine.state, { kind: "Cancelled", byPeer: false, reason: "Unavailable" });
    await w.advance(120_000);
    await flow(w);
    assertEquals(last(b, o.id).state, { kind: "Cancelled", byPeer: true, reason: "Unavailable" });
    assertEquals((await a2.engine.transfers())[0].pending, false);
    await assertRejects(() => b.engine.acceptTransfer(o.id), EngineError);
  }),
);

Deno.test(
  "transfer: a tampered record is refused whole and the genuine one arrives on a new channel",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    const data = bytes(12 * CHUNK + 7);
    let hit = 0;
    let seen = 0;
    w.rtc.tamper = (_from, _label, m) => {
      // The fifth record of the first attempt.
      if (m[0] === 0x03 && ++seen === 5) {
        hit++;
        const bad = new Uint8Array(m);
        bad[100] ^= 0x20;
        return bad;
      }
      return m;
    };
    const o = await a.engine.offerFile(b.id, fileOf("doc.pdf", data));
    await flow(w);
    await b.engine.acceptTransfer(o.id);
    await w.advance(5_000);
    await flow(w);
    assertEquals(hit, 1);
    assertEquals(last(b, o.id).state.kind, "Complete");
    assertEquals(await received(b, o.id), data, "no changed byte reached the file");
    const channels = fileChannels(b);
    assertEquals(channels.length, 2, "the attempt with the bad record ended");
    assertEquals(new DataView(channels[1].sentBinary[0].buffer).getUint32(1), 4);
    assertEquals(b.notices(), []);
  }),
);

Deno.test(
  "transfer: records that keep failing end the transfer with reason integrity",
  withWorld(async (w) => {
    const [a, b, store] = await pairWithFiles(w);
    w.rtc.tamper = (_from, _label, m) => {
      if (m[0] !== 0x03) return m;
      const bad = new Uint8Array(m);
      bad[bad.length - 1] ^= 0x01;
      return bad;
    };
    const o = await a.engine.offerFile(b.id, fileOf("doc.pdf", bytes(3 * CHUNK)));
    await flow(w);
    await b.engine.acceptTransfer(o.id);
    await w.advance(30_000);
    await flow(w);
    assertEquals(last(b, o.id).state, { kind: "Cancelled", byPeer: false, reason: "Integrity" });
    assertEquals(last(a, o.id).state, { kind: "Cancelled", byPeer: true, reason: "Integrity" });
    assertEquals(fileChannels(b).length, 3, "three attempts in a row ended on a bad record");
    assertEquals(await store.segments(o.id), 0);
    assert(b.eventsOf("Notice").some((n) => n.code === "Transfer"));
  }),
);

Deno.test(
  "transfer: frames out of place, text and unknown channels end only the attempt or are closed",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    const data = bytes(4 * CHUNK);
    const o = await a.engine.offerFile(b.id, fileOf("f.bin", data));
    await flow(w);

    // A channel for a transfer that is not accepted yet, an unknown id, another reserved
    // label, the wrong direction: all closed by the side that did not open them.
    const bPc = b.pcs.at(-1)!;
    const aPc = a.pcs.at(-1)!;
    for (
      const label of [
        `pn-file/${o.id}`,
        "pn-file/00000000000000000000000000000000",
        "pn-file/NOTHEX",
        "pn-other",
        "anything",
      ]
    ) {
      const dc = bPc.createDataChannel(label) as FakeDc;
      await flow(w);
      assertEquals(dc.readyState, "closed", label);
    }
    const wrongWay = aPc.createDataChannel(`pn-file/${o.id}`) as FakeDc;
    await flow(w);
    assertEquals(wrongWay.readyState, "closed", "only the receiver opens the channel");
    assertEquals(a.path(b), "Direct", "the connection is untouched");

    // After the accept: a second message from the receiver ends the attempt, not the transfer.
    w.rtc.holdBinary = true;
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    w.rtc.releaseBinary(1);
    await flow(w);
    const mine = fileChannels(b).at(-1)!;
    assertEquals(mine.readyState, "open");
    mine.inject(new Uint8Array(21).fill(1).buffer);
    await flow(w);
    assertEquals(mine.readyState, "closed");
    assertEquals(last(a, o.id).state.kind, "Waiting");
    w.rtc.heldBinary = [];
    w.rtc.holdBinary = false;

    // A text message or garbage from the sender ends the receiver's attempt.
    await w.advance(1_000);
    await flow(w);
    assertEquals(last(b, o.id).state.kind, "Complete");
    assertEquals(await received(b, o.id), data);
  }),
);

Deno.test(
  "transfer: offers over a limit are declined without showing them",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b", {
      config: { maxAcceptSize: 100_000 },
      files: new MemoryFileStore(),
    });
    await w.pair(a, b);
    const big = await a.engine.offerFile(b.id, fileOf("big.bin", bytes(100_001)));
    await flow(w);
    assertEquals(last(a, big.id).state.kind, "Declined");
    assertEquals(b.eventsOf("Transfer").length, 0);
    assertEquals((await b.engine.transfers()).length, 0);

    // Sixteen offers may wait; the seventeenth is declined. (The clock moves so that the
    // rate limit of ten at once, one more every six seconds, is not what stops them.)
    const ids: string[] = [];
    for (let i = 0; i < 17; i++) {
      ids.push((await a.engine.offerFile(b.id, fileOf(`f${i}`, bytes(10, i)))).id);
      await w.advance(6_100);
      await flow(w);
    }
    assertEquals((await b.engine.transfers()).length, 16);
    assertEquals(last(a, ids[16]).state.kind, "Declined");
    assertEquals(last(a, ids[15]).state.kind, "Offered");

    // The rate limit: after answering them all, a burst of twelve lets ten in.
    for (const id of ids.slice(0, 16)) await b.engine.declineTransfer(id);
    await w.advance(120_000);
    await flow(w);
    const burst: string[] = [];
    for (let i = 0; i < 12; i++) {
      burst.push((await a.engine.offerFile(b.id, fileOf(`g${i}`, bytes(10, 100 + i)))).id);
    }
    await flow(w);
    assertEquals(
      burst.map((id) => last(a, id).state.kind).filter((s) => s === "Declined").length,
      2,
    );
  }),
);

Deno.test(
  "transfer: at most four channels at once; the rest wait their turn",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    const files = [...Array(6).keys()].map((i) => bytes(3 * CHUNK + i, i));
    const ids: string[] = [];
    for (const [i, data] of files.entries()) {
      ids.push((await a.engine.offerFile(b.id, fileOf(`n${i}.bin`, data))).id);
    }
    await flow(w);
    w.rtc.holdBinary = true;
    for (const id of ids) await b.engine.acceptTransfer(id);
    await flow(w);
    assertEquals(fileChannels(b).filter((c) => c.readyState === "open").length, 4);
    w.rtc.holdBinary = false;
    w.rtc.releaseBinary();
    await w.advance(2_000);
    await flow(w);
    for (const [i, id] of ids.entries()) {
      assertEquals(last(b, id).state.kind, "Complete", `file ${i}`);
      assertEquals(await received(b, id), files[i]);
    }
  }),
);

Deno.test(
  "transfer: the sender pauses on the channel's buffer and reads the file as it goes",
  withWorld(async (w) => {
    const [a, b] = await pairWithFiles(w);
    const records = 200; // 12.5 MiB: three times the high mark
    const data = bytes(records * CHUNK);
    const source = fileOf("flow.bin", data);
    const o = await a.engine.offerFile(b.id, source);
    const hashingReads = source.reads;
    await flow(w);
    w.rtc.holdBinary = true;
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    await deliver(w, 1); // RESUME
    // Nothing leaves the sender's buffer: it must stop a little above 4 MiB.
    await w.advance(1_000);
    await flow(w);
    const dc = fileChannels(a).at(-1)!;
    const sentWhileStuck = dc.sentBinary.length;
    assert(dc.bufferedAmount > 4 << 20, `buffered ${dc.bufferedAmount}`);
    assert(dc.bufferedAmount <= (4 << 20) + 65536, `buffered ${dc.bufferedAmount}`);
    assert(sentWhileStuck < records, "not everything was read and sealed up front");
    // It read only what it sent (in 1 MiB blocks), not the whole file.
    assert(source.reads - hashingReads <= Math.ceil(sentWhileStuck / 16) + 1);
    await w.advance(5_000);
    await flow(w);
    assertEquals(dc.sentBinary.length, sentWhileStuck, "paused while the buffer is full");
    w.rtc.holdBinary = false;
    w.rtc.releaseBinary();
    await w.advance(5_000);
    await flow(w);
    assertEquals(last(b, o.id).state.kind, "Complete");
    assertEquals(await sha256(await received(b, o.id)), await sha256(data));
  }),
);

Deno.test(
  "transfer: removing a contact removes its transfers and their files; wipe clears the store",
  withWorld(async (w) => {
    const [a, b, store] = await pairWithFiles(w);
    const o = await a.engine.offerFile(b.id, fileOf("keep.bin", bytes(2 * CHUNK)));
    await flow(w);
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    assertEquals(await store.segments(o.id), 1);
    await b.engine.removeContact(a.id);
    assertEquals(await store.segments(o.id), 0);
    assertEquals((await b.engine.transfers()).length, 0);
    assertEquals(await rowOf(b, o.id), undefined);

    const c = await w.device("c", { files: store });
    await w.pair(a, c);
    const o2 = await a.engine.offerFile(c.id, fileOf("wipe.bin", bytes(CHUNK)));
    await flow(w);
    await c.engine.acceptTransfer(o2.id);
    await flow(w);
    assertEquals(await store.segments(o2.id), 1);
    await c.engine.wipe();
    assertEquals(await store.segments(o2.id), 0);
  }),
);

Deno.test(
  "transfer: a full disk stops the transfer with reason storage",
  withWorld(async (w) => {
    const [a, b, store] = await pairWithFiles(w);
    const o = await a.engine.offerFile(b.id, fileOf("full.bin", bytes(5 * CHUNK)));
    await flow(w);
    store.failNextWrite = true;
    await b.engine.acceptTransfer(o.id);
    await flow(w);
    assertEquals(last(b, o.id).state, { kind: "Cancelled", byPeer: false, reason: "Storage" });
    assertEquals(last(a, o.id).state, { kind: "Cancelled", byPeer: true, reason: "Storage" });
    assert(b.eventsOf("Notice").some((n) => n.code === "Storage"));
  }),
);
