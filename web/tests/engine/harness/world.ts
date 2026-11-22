// A small world for engine tests: a fake clock, relay and WebRTC network, and "devices" that
// each run a real engine over a real parolnet-wasm instance (so the crypto, the pairing code
// and the channel binding are the real thing) with in-memory storage.
//
// The wasm package is the one `denext task build-wasm` builds (web/.wasm-pkg), or the one
// PAROLNET_WASM_PKG names.
import { Engine, type EngineConfig } from "../../../src/engine/engine.ts";
import type {
  FetchResponse,
  FileStore,
  Logger,
  MediaDevices,
  Platform,
  Storage,
  WasmApi,
} from "../../../src/engine/platform.ts";
import { MemoryStorage } from "../../../src/engine/storage.ts";
import type { AppEvent, PathState, SasCheck } from "../../../src/engine/types.ts";
import { wasmApi } from "../../../src/engine/browser.ts";
import {
  FakeClock,
  type FakePc,
  FakeRelay,
  FakeRtc,
  FakeStream,
  FakeTrack,
  tick,
} from "./fakes.ts";

/** PAROLNET_WASM_PKG, else the app's own build (`denext task build-wasm` writes web/.wasm-pkg). */
const pkgDir = Deno.env.get("PAROLNET_WASM_PKG") ??
  new URL("../../../.wasm-pkg", import.meta.url).pathname;
let wasmBytes: Uint8Array | null = null;
let instances = 0;

/** A fresh parolnet-wasm instance: its own identity and sessions. */
export async function newWasm(): Promise<WasmApi> {
  try {
    wasmBytes ??= await Deno.readFile(`${pkgDir}/parolnet_wasm_bg.wasm`);
  } catch {
    throw new Error(
      `parolnet-wasm is not built: run \`denext task build-wasm\` (looked in ${pkgDir})`,
    );
  }
  // A distinct module specifier gives a distinct module instance, and with it a distinct
  // wasm memory.
  const mod = await import(
    `file://${pkgDir}/parolnet_wasm.js?instance=${++instances}`
  );
  await mod.default({ module_or_path: wasmBytes });
  return wasmApi(mod);
}

export const RELAY_URL = "ws://relay.test/ws";

export interface DeviceOptions {
  storage?: MemoryStorage;
  /** What the engine is given instead of `storage` (a `SealedStorage` over it, say). */
  engineStorage?: Storage;
  config?: Partial<EngineConfig>;
  /** Give the device a microphone and camera. */
  media?: boolean;
  /** Exports this device's core lacks: the engine runs as on an older parolnet-wasm. */
  without?: readonly (keyof WasmApi)[];
  /** Where received files are kept (default: the engine's own memory store). */
  files?: FileStore;
}

/** `wasm` without some of its exports (they read as missing, as on an older core). */
function withoutExports(wasm: WasmApi, names: readonly (keyof WasmApi)[] = []): WasmApi {
  if (names.length === 0) return wasm;
  const copy: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(wasm)) {
    if (!names.includes(name as keyof WasmApi)) copy[name] = value;
  }
  return copy as unknown as WasmApi;
}

export class Device {
  events: AppEvent[] = [];
  logs: string[] = [];
  fetched: string[] = [];
  /** What `GET /turn-credentials` answers. */
  turnCredentials: string = JSON.stringify({
    uris: [],
    profile: "signaling-only",
  });
  streams: FakeStream[] = [];
  /** Every peer connection this device made, oldest first. */
  pcs: FakePc[] = [];

  constructor(
    readonly world: World,
    readonly name: string,
    readonly engine: Engine,
    readonly storage: MemoryStorage,
    readonly wasm: WasmApi,
    readonly platform: Platform,
  ) {}

  get id(): string {
    return this.engine.peerId;
  }

  path(peer: Device | string): PathState {
    const id = typeof peer === "string" ? peer : peer.id;
    return this.engine.snapshot().contacts.find((c) => c.contact.peerId === id)
      ?.path ?? "Unknown";
  }

  /** The verification code this device shows for its pairing with `peer`, if any. */
  sas(peer: Device | string): SasCheck | null {
    const id = typeof peer === "string" ? peer : peer.id;
    return this.eventsOf("Sas").findLast((e) => e.sas.peerId === id && this.pairingWith(id))
      ?.sas ?? null;
  }

  /** A pairing with `peer` is under way on this device. */
  pairingWith(peer: Device | string): boolean {
    const id = typeof peer === "string" ? peer : peer.id;
    return this.wasm.pairing_state(id) !== undefined;
  }

  contact(peer: Device | string) {
    const id = typeof peer === "string" ? peer : peer.id;
    return this.engine.snapshot().contacts.find((c) => c.contact.peerId === id)?.contact;
  }

  /** Break every live connection of this device (both ends notice). */
  cut(): void {
    for (const pc of this.pcs) if (pc.connectionState !== "closed") pc.sever();
  }

  eventsOf<K extends AppEvent["kind"]>(
    kind: K,
  ): Extract<AppEvent, { kind: K }>[] {
    return this.events.filter((e): e is Extract<AppEvent, { kind: K }> => e.kind === kind);
  }

  notices(): string[] {
    return this.eventsOf("Notice").map((n) => n.text);
  }
}

export class World {
  clock = new FakeClock();
  relay = new FakeRelay();
  rtc = new FakeRtc();
  devices: Device[] = [];
  /** What `Random.next` returns (jitter). */
  jitter = 0;

  /** Let every queued task, promise chain and digest finish. */
  settle = async (): Promise<void> => {
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 3; i++) await tick();
      for (const d of this.devices) await d.engine.idle().catch(() => {});
    }
  };

  advance(ms: number): Promise<void> {
    return this.clock.advance(ms, this.settle);
  }

  async device(name: string, options: DeviceOptions = {}): Promise<Device> {
    const wasm = withoutExports(await newWasm(), options.without);
    const storage = options.storage ?? new MemoryStorage();
    const logs: string[] = [];
    const log: Logger = {
      debug: (...a) => logs.push(a.join(" ")),
      info: (...a) => logs.push(a.join(" ")),
      warn: (...a) => logs.push(a.join(" ")),
    };
    const fetched: string[] = [];
    const holder: { device: Device | null } = { device: null };
    const media: MediaDevices | undefined = options.media
      ? {
        getUserMedia: (c) => {
          const tracks = [new FakeTrack("audio")];
          if (c.video) tracks.push(new FakeTrack("video"));
          const stream = new FakeStream(tracks);
          holder.device?.streams.push(stream);
          return Promise.resolve(stream);
        },
      }
      : undefined;
    const platform: Platform = {
      wasm,
      storage: options.engineStorage ?? storage,
      sockets: this.relay.factory,
      peerConnections: (config) => {
        const pc = this.rtc.factory(config);
        holder.device?.pcs.push(pc as FakePc);
        return pc;
      },
      clock: this.clock,
      random: {
        next: () => this.jitter,
        bytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
      },
      fetch: (url) => {
        fetched.push(url);
        const body = holder.device?.turnCredentials ?? "{}";
        const response: FetchResponse = {
          ok: true,
          status: 200,
          text: () => Promise.resolve(body),
        };
        return Promise.resolve(response);
      },
      sha256: async (data) =>
        new Uint8Array(
          await crypto.subtle.digest("SHA-256", data as BufferSource),
        ),
      subtle: crypto.subtle,
      log,
      media,
      files: options.files,
    };
    const engine = await Engine.start(platform, {
      relayUrl: RELAY_URL,
      stunServers: [],
      ...options.config,
    });
    const device = new Device(this, name, engine, storage, wasm, platform);
    device.logs = logs;
    device.fetched = fetched;
    holder.device = device;
    engine.subscribe((ev) => device.events.push(ev));
    this.devices.push(device);
    await this.settle();
    return device;
  }

  /** Stop a device and start it again from the same storage with a fresh wasm instance. */
  async restart(device: Device, options: DeviceOptions = {}): Promise<Device> {
    await device.engine.shutdown();
    this.devices = this.devices.filter((d) => d !== device);
    await this.settle();
    return await this.device(device.name, {
      ...options,
      storage: device.storage,
    });
  }

  /**
   * `a` shows a code, `b` pairs with it, both people confirm the verification code, and both
   * end with the contact and a verified direct channel. A scan reads the code itself, a paste
   * gets its text form.
   */
  async pair(
    a: Device,
    b: Device,
    via: "scan" | "paste" = "paste",
  ): Promise<void> {
    const { code, text } = await a.engine.createPairingCode();
    await b.engine.pairWithCode(via === "scan" ? code : text, { via });
    await this.settle();
    await this.confirmSas(a, b);
    for (let i = 0; i < 5 && !(a.path(b) === "Direct" && b.path(a) === "Direct"); i++) {
      await this.settle();
    }
    if (a.path(b) !== "Direct" || b.path(a) !== "Direct") {
      throw new Error(
        `pairing did not reach Direct: ${a.name}=${a.path(b)} ${b.name}=${b.path(a)}`,
      );
    }
  }

  /**
   * The two people compare the verification code and both say it matches. Throws when the
   * two devices do not show the same one. Nothing to do when neither device asked for it.
   */
  async confirmSas(a: Device, b: Device): Promise<void> {
    for (let i = 0; i < 5 && !(a.sas(b) && b.sas(a)); i++) await this.settle();
    const [shownA, shownB] = [a.sas(b), b.sas(a)];
    if (!shownA && !shownB) return;
    if (
      !shownA || !shownB || shownA.digits !== shownB.digits || shownA.emoji !== shownB.emoji
    ) {
      throw new Error("the two devices do not show the same verification code");
    }
    await a.engine.confirmSas(b.id);
    await b.engine.confirmSas(a.id);
    await this.settle();
  }

  async shutdown(): Promise<void> {
    for (const d of this.devices) await d.engine.shutdown();
    this.devices = [];
    await this.settle();
  }
}

/** Run a test in a fresh world and stop its engines afterwards. */
export function withWorld(
  fn: (w: World) => Promise<void>,
): () => Promise<void> {
  return async () => {
    const world = new World();
    try {
      await fn(world);
    } finally {
      await world.shutdown();
    }
  };
}

/** Two devices ordered so that the first has the smaller PeerId (it is the initiator). */
export async function orderedPair(
  w: World,
  options: DeviceOptions = {},
): Promise<[Device, Device]> {
  const x = await w.device("x", options);
  const y = await w.device("y", options);
  return x.id < y.id ? [x, y] : [y, x];
}
