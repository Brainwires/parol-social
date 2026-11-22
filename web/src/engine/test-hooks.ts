// The `window.__parolnetTest` contract of docs/web-port/interop.md §11.4, for test builds
// only. Nothing installs it by default: the app calls `installTestHooks(engine)` when it was
// built for tests. It exposes nothing the UI does not already show (no keys, no session
// state, no TURN credential).
import type { Engine } from "./engine.ts";
import type { IceServer } from "./platform.ts";
import type { AppEvent, DeliveryState, Direction, PathState } from "./types.ts";

export type TestPathState =
  | "offline"
  | "connecting"
  | "direct"
  | "failed"
  | "binding-failed";
export type TestCallState =
  | "idle"
  | "outgoing"
  | "incoming"
  | "connecting"
  | "active";

export interface ParolnetTestHooks {
  version: 1;
  ready(): Promise<{ peerId: string }>;
  relayRegistered(): boolean;
  /** The code in its form for copying as text (the picture holds the same code). */
  showPairingCode(): Promise<string>;
  /**
   * Starts adding the contact whose code this is. The contact is added once both devices'
   * verification codes were confirmed (`sas`, `confirmSas`).
   */
  pairWithCode(code: string): Promise<void>;
  /**
   * Not in §11.4: the verification code this device shows for a pairing that waits for it
   * (PNP-003 §5.5), or null. Both devices must show the same one.
   */
  sas(): { peerId: string; digits: string; emoji: string; confirmed: boolean } | null;
  /** Not in §11.4: the person says the code shown is the one on the contact's device. */
  confirmSas(): Promise<void>;
  /** Not in §11.4: the person says the codes differ; the contact is not added. */
  rejectSas(): Promise<void>;
  contacts(): Promise<string[]>;
  messages(
    peerId: string,
  ): Promise<
    { direction: "sent" | "received"; text: string; state: DeliveryState }[]
  >;
  sendText(peerId: string, text: string): Promise<{ state: DeliveryState }>;
  pathState(peerId: string): TestPathState;
  incomingCall(): { peerId: string; callId: string; video: boolean } | null;
  acceptCall(): Promise<void>;
  rejectCall(): Promise<void>;
  startCall(peerId: string, video: boolean): Promise<void>;
  hangup(): Promise<void>;
  callState(): TestCallState;
  iceServers(): IceServer[];
  /** Not in §11.4: the engine's own path vocabulary, for tests that need `NoDirectPath`. */
  rawPathState(peerId: string): PathState;
  /** Not in §11.4: the file transfers (PNP-010) with one contact or all, oldest first. */
  transfers(peerId?: string): Promise<TestTransfer[]>;
  /**
   * Not in §11.4: SHA-256 (hex) and length of a received, complete file as it is stored on
   * this device; null when there is none.
   */
  transferDigest(id: string): Promise<{ sha256: string; size: number } | null>;
  /** Not in §11.4: received parts survive a reload (OPFS) or not (memory). */
  filesPersist(): boolean;
  /** Not in §11.4: take the hooks away again. */
  uninstall(): void;
}

export interface TestTransfer {
  id: string;
  peerId: string;
  direction: "sent" | "received";
  name: string;
  size: number;
  /** `offered`, `waiting`, `active`, `complete`, `declined` or `cancelled`. */
  state: string;
  /** `Cancelled` only: who and why, e.g. `peer:Integrity`. */
  cancelled: string | null;
  bytesDone: number;
  pending: boolean;
  available: boolean;
}

function testPath(path: PathState): TestPathState {
  switch (path) {
    case "Direct":
      return "direct";
    case "Connecting":
      return "connecting";
    case "NoDirectPath":
      return "failed";
    case "BindingFailed":
      return "binding-failed";
    default:
      return "offline";
  }
}

interface HookTarget {
  __parolnetTest?: ParolnetTestHooks;
  dispatchEvent?(ev: unknown): boolean;
  CustomEvent?: new (type: string, init: { detail: unknown }) => unknown;
}

/**
 * Install `__parolnetTest` on `target` (default `globalThis`) and announce state changes as
 * `parolnet:test` events (`detail: {kind:'relay', state}`, `{kind:'path', peerId, state}`,
 * `{kind:'message', peerId}`, `{kind:'call', state}`, `{kind:'sas', peerId}`,
 * `{kind:'paired', peerId, sasVerified}`, `{kind:'pairing-failed', peerId, reason}`).
 */
export function installTestHooks(
  engine: Engine,
  target: HookTarget = globalThis as HookTarget,
): ParolnetTestHooks {
  const announce = (detail: Record<string, unknown>) => {
    if (
      typeof target.CustomEvent === "function" &&
      typeof target.dispatchEvent === "function"
    ) {
      target.dispatchEvent(new target.CustomEvent("parolnet:test", { detail }));
    }
  };
  const callState = (): TestCallState => {
    const call = engine.snapshot().call;
    return call ? (call.state.kind.toLowerCase() as TestCallState) : "idle";
  };
  const unsubscribe = engine.subscribe((ev: AppEvent) => {
    switch (ev.kind) {
      case "Relay":
        announce({
          kind: "relay",
          state: ev.state.kind === "Registered" ? "registered" : "disconnected",
        });
        break;
      case "Path":
        announce({
          kind: "path",
          peerId: ev.peerId,
          state: testPath(ev.state),
        });
        break;
      case "Message":
        announce({ kind: "message", peerId: ev.message.peerId });
        break;
      case "Sas":
        announce({ kind: "sas", peerId: ev.sas.peerId });
        break;
      case "PairingComplete":
        announce({ kind: "paired", peerId: ev.peerId, sasVerified: ev.sasVerified });
        break;
      case "PairingFailed":
        announce({ kind: "pairing-failed", peerId: ev.peerId, reason: ev.reason });
        break;
      case "Call":
        announce({
          kind: "call",
          state: ev.call.state.kind === "Ended" ? "idle" : callState(),
        });
        break;
      case "Transfer":
        announce({
          kind: "transfer",
          id: ev.transfer.id,
          peerId: ev.transfer.peerId,
          state: ev.transfer.state.kind.toLowerCase(),
        });
        break;
    }
  });
  const pathOf = (peerId: string): PathState =>
    engine.snapshot().contacts.find((c) => c.contact.peerId === peerId)?.path ??
      "Unknown";
  const currentCall = () => engine.snapshot().call;
  const lower = (d: Direction) => (d === "Sent" ? "sent" : "received") as "sent" | "received";

  const hooks: ParolnetTestHooks = {
    version: 1,
    ready: () => Promise.resolve({ peerId: engine.peerId }),
    relayRegistered: () => engine.snapshot().relay.kind === "Registered",
    showPairingCode: async () => (await engine.createPairingCode()).text,
    pairWithCode: async (code) => {
      await engine.pairWithCode(code, { via: "paste" });
    },
    sas: () => {
      const sas = engine.snapshot().sas;
      return sas ? { ...sas } : null;
    },
    confirmSas: async () => {
      const sas = engine.snapshot().sas;
      if (sas) await engine.confirmSas(sas.peerId);
    },
    rejectSas: async () => {
      const sas = engine.snapshot().sas;
      if (sas) await engine.rejectSas(sas.peerId);
    },
    contacts: () => Promise.resolve(engine.snapshot().contacts.map((c) => c.contact.peerId)),
    messages: async (peerId) =>
      (await engine.messages(peerId)).map((m) => ({
        direction: lower(m.direction),
        text: m.text,
        state: m.state,
      })),
    sendText: async (peerId, text) => ({
      state: (await engine.sendText(peerId, text)).state,
    }),
    pathState: (peerId) => testPath(pathOf(peerId)),
    rawPathState: pathOf,
    incomingCall: () => {
      const c = currentCall();
      return c && c.state.kind === "Incoming"
        ? { peerId: c.peerId, callId: c.callId, video: c.video }
        : null;
    },
    acceptCall: async () => {
      const c = currentCall();
      if (c) await engine.acceptCall(c.callId);
    },
    rejectCall: async () => {
      const c = currentCall();
      if (c) await engine.rejectCall(c.callId);
    },
    startCall: async (peerId, video) => {
      await engine.startCall(peerId, video);
    },
    hangup: async () => {
      const c = currentCall();
      if (c) await engine.hangup(c.callId);
    },
    callState,
    iceServers: () => engine.iceServers(),
    transfers: async (peerId) =>
      (await engine.transfers(peerId)).map((t) => ({
        id: t.id,
        peerId: t.peerId,
        direction: lower(t.direction),
        name: t.name,
        size: t.size,
        state: t.state.kind.toLowerCase(),
        cancelled: t.state.kind === "Cancelled"
          ? `${t.state.byPeer ? "peer" : "self"}:${t.state.reason}`
          : null,
        bytesDone: t.bytesDone,
        pending: t.pending,
        available: t.available,
      })),
    transferDigest: async (id) => {
      const blob = await engine.transferFile(id);
      if (!blob) return null;
      const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", await blob.arrayBuffer()),
      );
      return {
        sha256: [...digest].map((b) => b.toString(16).padStart(2, "0")).join(""),
        size: blob.size,
      };
    },
    filesPersist: () => engine.receivedFilesPersist(),
    uninstall: () => {
      unsubscribe();
      if (target.__parolnetTest === hooks) delete target.__parolnetTest;
    },
  };
  target.__parolnetTest = hooks;
  return hooks;
}
