// An in-memory AppStore with made-up people: the state lab's fixture (#/lab, development and
// test builds only). It behaves like the engine where the screens can tell: a message sent on
// an open line is delivered, anything else waits; when a line opens, what waited is delivered.
import { batch, signal } from "denext/signals";
import { BackupError } from "../engine/backup.ts";
import { EngineError } from "../engine/types.ts";
import { VaultError } from "../engine/vault.ts";
import type {
  Attachment,
  CallInfo,
  ChatMessage,
  Contact,
  ContactView,
  PairingCode,
  PathState,
  RelayState,
  Verification,
} from "./model.ts";
import type { AppStore, CallMediaStreams, FakeControls, Notice, Phase, TurnView } from "./store.ts";

const MINUTE = 60_000;

function peerId(seed: string): string {
  return seed.repeat(32);
}

export const FAKE_PEERS = {
  mira: peerId("a1"),
  tomasz: peerId("b2"),
  readers: peerId("c3"),
  ines: peerId("d4"),
  kofi: peerId("e5"),
  sana: peerId("f6"),
  jun: peerId("07"),
} as const;

/** A fixed clock for the seed, so screenshots and tests do not depend on the time of day. */
const SEED_EPOCH_MS = Date.UTC(2026, 10, 20, 9, 0, 0);

const SEED_CONTACTS: Array<[string, string, PathState, Verification]> = [
  [FAKE_PEERS.mira, "Mira", "Direct", "in-person"],
  [FAKE_PEERS.tomasz, "Tomasz", "Offline", "compared"],
  [FAKE_PEERS.readers, "Reading group", "Direct", "in-person"],
  [FAKE_PEERS.ines, "Ines", "Connecting", "in-person"],
  [FAKE_PEERS.kofi, "Kofi", "NoDirectPath", "in-person"],
  [FAKE_PEERS.sana, "Sana", "BindingFailed", "compared"],
  [FAKE_PEERS.jun, "Jun", "Offline", "no"],
];

type Line = ["in" | "out" | "held", string | Attachment];

const SEED_MESSAGES: Record<string, Line[]> = {
  [FAKE_PEERS.mira]: [
    ["in", "Are you still coming on Saturday?"],
    ["out", "Yes. I can bring the projector."],
    ["in", "Perfect. Here is the route."],
    ["in", { kind: "file", name: "route-saturday.pdf", bytes: 184_320 }],
    ["out", "Got it, thank you."],
  ],
  [FAKE_PEERS.tomasz]: [
    ["in", "Landing in an hour. Talk tomorrow?"],
    ["out", "Safe flight."],
    ["held", "The keys are with the neighbour at number 4."],
    ["held", "Call me when you are back online."],
    ["held", { kind: "call", media: "voice" }],
  ],
  [FAKE_PEERS.readers]: [
    ["in", "Chapter six for Thursday."],
    ["out", "I will have read it by then."],
  ],
  [FAKE_PEERS.ines]: [
    ["in", "One moment, switching to the laptop."],
    ["held", "No rush."],
  ],
  [FAKE_PEERS.kofi]: [
    ["in", "Did the photos arrive?"],
    ["held", "Not yet. Sending mine now."],
    ["held", { kind: "file", name: "harbour.jpg", bytes: 2_411_724 }],
  ],
  [FAKE_PEERS.sana]: [
    ["in", "Trying again from the office network."],
    ["held", "I am here."],
  ],
};

function seedMessages(): Map<string, ChatMessage[]> {
  let id = 0;
  const all = new Map<string, ChatMessage[]>();
  for (const [peer, lines] of Object.entries(SEED_MESSAGES)) {
    all.set(
      peer,
      lines.map(([how, content], index): ChatMessage => ({
        id: ++id,
        peerId: peer,
        direction: how === "in" ? "Received" : "Sent",
        text: typeof content === "string" ? content : "",
        ...(typeof content === "string" ? {} : { attachment: content }),
        timestampMs: SEED_EPOCH_MS + index * 3 * MINUTE,
        state: how === "in" ? "Received" : how === "out" ? "Sent" : "Queued",
      })),
    );
  }
  return all;
}

function seedContacts(): Contact[] {
  return SEED_CONTACTS.map(([id, name, , verified], index): Contact => ({
    peerId: id,
    name,
    identityKey: null,
    // Seeded in list order, newest activity first.
    addedMs: SEED_EPOCH_MS - index * MINUTE,
    verified,
    verifiedMs: verified === "no" ? null : SEED_EPOCH_MS,
  }));
}

// As long as the longest real code (about 170 bytes), so the lab shows the real layout.
const FAKE_CODE =
  "d606ec3b56b70ae22e4c0ebacc3d86fa6442c75a4e7ad57c4e3e5d7718cf89ecc77f4da6a8f4c05e" +
  "b26ddcdcd0b521c0e9c567b8ded3adbe28d64f0013f03b5f723a0bfac6e6505f05d16a809879611e" +
  "3cd756615268194fed484666e6e7f08ed09f7380b17d4c63881100ac75bec091ed2f637de928e906" +
  "987a4d604a365cc80d5832a3aaeaf85ddbb19af07196447e6b6134a0cda4f9ea5386f8a9c9c93391" +
  "d76b05bfa4fdae88d44083af";
/** Who "used this device's code" in the lab. */
export const USED_CODE_PEER = "c3".repeat(32);
const FAKE_SAFETY_NUMBER = "385729104466271839500471626839157203948561027384951620";

export interface FakeStoreOptions {
  /** How long a retried connection takes before it fails the same way again. */
  retryDelayMs?: number;
  /** Start with no contacts (the empty state). */
  empty?: boolean;
}

export function createFakeStore(options: FakeStoreOptions = {}): AppStore & FakeControls {
  const retryDelayMs = options.retryDelayMs ?? 1500;
  const phase = signal<Phase>({ kind: "ready" });
  const passphraseSet = signal(false);
  const lastBackupMs = signal<number | null>(null);
  const relay = signal<RelayState>({ kind: "Registered", profile: "signaling-only" });
  const selfOnline = signal(true);
  const people = signal<readonly Contact[]>(options.empty ? [] : seedContacts());
  const paths = signal<ReadonlyMap<string, PathState>>(
    new Map(options.empty ? [] : SEED_CONTACTS.map(([id, , path]) => [id, path])),
  );
  const messages = signal<ReadonlyMap<string, readonly ChatMessage[]>>(
    options.empty ? new Map() : seedMessages(),
  );
  const contacts = signal<readonly ContactView[]>([]);
  const call = signal<CallInfo | null>(null);
  const callMedia = signal<CallMediaStreams>({ local: null, remote: null });
  const pairing = signal<PairingCode | null>(null);
  const turn = signal<TurnView | null>(null);
  const notice = signal<Notice | null>(null);
  let nextId = 1000;

  const pathOf = (peer: string): PathState => paths.value.get(peer) ?? "Unknown";
  const lineOpen = (peer: string) => selfOnline.value && pathOf(peer) === "Direct";

  /** The contact views, derived the way the engine's snapshot derives them. */
  function publish(): void {
    contacts.value = people.value.map((contact): ContactView => {
      const list = messages.value.get(contact.peerId) ?? [];
      return {
        contact,
        path: pathOf(contact.peerId),
        queued: list.filter((m) => m.direction === "Sent" && m.state === "Queued").length,
        unread: 0,
        lastActivityMs: list.at(-1)?.timestampMs ?? contact.addedMs,
      };
    });
  }
  publish();

  function update(peer: string, change: (list: readonly ChatMessage[]) => ChatMessage[]): void {
    const next = new Map(messages.value);
    next.set(peer, change(next.get(peer) ?? []));
    messages.value = next;
    publish();
  }

  function find(messageId: number): ChatMessage {
    for (const list of messages.value.values()) {
      const message = list.find((m) => m.id === messageId);
      if (message) {
        if (message.state !== "Queued") break;
        return message;
      }
    }
    throw new EngineError("NotQueued", "that message has already left this device");
  }

  /** Deliver what waited for this contact. */
  function flush(peer: string): void {
    if (!lineOpen(peer)) return;
    update(peer, (list) => list.map((m) => (m.state === "Queued" ? { ...m, state: "Sent" } : m)));
  }

  function setPath(peer: string, path: PathState): void {
    batch(() => {
      paths.value = new Map(paths.value).set(peer, path);
      publish();
      flush(peer);
      if (path !== "Direct" && call.value?.peerId === peer) call.value = null;
    });
  }

  function person(change: (list: readonly Contact[]) => Contact[]): void {
    people.value = change(people.value);
    publish();
  }

  return {
    phase,
    relay,
    selfOnline,
    contacts,
    messages,
    call,
    callMedia,
    pairing,
    turn,
    notice,

    passphraseSet,
    lastBackupMs,
    begin: () => Promise.resolve(),
    // The lab's passphrase rules: "wrong" is the wrong one, anything else is right.
    unlock(passphrase) {
      if (passphrase === "wrong") {
        phase.value = { kind: "locked", retryAtMs: 0 };
        return Promise.reject(new VaultError("WrongPassphrase", "that is not the passphrase"));
      }
      phase.value = { kind: "ready" };
      return Promise.resolve();
    },
    forget() {
      this.clear();
      phase.value = { kind: "first-run" };
      return Promise.resolve();
    },
    lock() {
      if (passphraseSet.value) phase.value = { kind: "locked", retryAtMs: 0 };
    },
    setPassphrase() {
      passphraseSet.value = true;
      return Promise.resolve();
    },
    changePassphrase(current) {
      return current === "wrong"
        ? Promise.reject(new VaultError("WrongPassphrase", "that is not the passphrase"))
        : Promise.resolve();
    },
    removePassphrase(current) {
      if (current === "wrong") {
        return Promise.reject(new VaultError("WrongPassphrase", "that is not the passphrase"));
      }
      passphraseSet.value = false;
      return Promise.resolve();
    },
    makeBackup() {
      const madeMs = Date.now();
      lastBackupMs.value = madeMs;
      return Promise.resolve({ bytes: new TextEncoder().encode("a made-up backup"), madeMs });
    },
    restore(_file, passphrase) {
      if (passphrase === "wrong") {
        return Promise.reject(new BackupError("WrongPassphrase", "wrong passphrase"));
      }
      phase.value = { kind: "ready" };
      return Promise.resolve();
    },
    takeOver() {},

    send(peer, text) {
      const message: ChatMessage = {
        id: ++nextId,
        peerId: peer,
        direction: "Sent",
        text,
        timestampMs: Date.now(),
        state: lineOpen(peer) ? "Sent" : "Queued",
      };
      update(peer, (list) => [...list, message]);
      return Promise.resolve();
    },

    takeBack(messageId) {
      try {
        const message = find(messageId);
        update(message.peerId, (list) => list.filter((m) => m.id !== messageId));
        return Promise.resolve();
      } catch (error) {
        return Promise.reject(error);
      }
    },

    edit(messageId, text) {
      try {
        const message = find(messageId);
        update(
          message.peerId,
          (list) =>
            list.map((m) => (m.id === messageId ? { ...m, text, editedMs: Date.now() } : m)),
        );
        return Promise.resolve();
      } catch (error) {
        return Promise.reject(error);
      }
    },

    connect(peer) {
      const before = pathOf(peer);
      if (before !== "NoDirectPath" && before !== "BindingFailed") return;
      setPath(peer, "Connecting");
      // The fake network has not changed: the attempt ends the way the last one did.
      setTimeout(() => {
        if (pathOf(peer) === "Connecting") setPath(peer, before);
      }, retryDelayMs);
    },

    markRead() {},

    createPairingCode() {
      const code: PairingCode = { code: FAKE_CODE, expiresAtMs: Date.now() + 28 * MINUTE };
      pairing.value = code;
      return Promise.resolve(code);
    },

    cancelPairing() {
      pairing.value = null;
      return Promise.resolve();
    },

    pair(code, via) {
      const clean = code.replace(/[^0-9a-f]/gi, "").toLowerCase();
      if (clean.length < 64) {
        return Promise.reject(new EngineError("InvalidCode", "not a pairing code"));
      }
      const contact: Contact = {
        peerId: clean.slice(0, 64),
        name: "",
        identityKey: null,
        addedMs: Date.now(),
        verified: via === "scan" ? "in-person" : "no",
        verifiedMs: via === "scan" ? Date.now() : null,
      };
      batch(() => {
        paths.value = new Map(paths.value).set(contact.peerId, "Offline");
        person((list) => [...list.filter((c) => c.peerId !== contact.peerId), contact]);
      });
      return Promise.resolve(contact);
    },

    rename(peer, name) {
      person((list) => list.map((c) => (c.peerId === peer ? { ...c, name: name.trim() } : c)));
      return Promise.resolve();
    },

    setCompared(peer, compared) {
      person((list) =>
        list.map((c) =>
          c.peerId === peer && c.verified !== "in-person"
            ? {
              ...c,
              verified: compared ? "compared" : "no",
              verifiedMs: compared ? Date.now() : null,
            }
            : c
        )
      );
      return Promise.resolve();
    },

    safetyNumber: () => FAKE_SAFETY_NUMBER.padEnd(60, "7"),

    removeContact(peer) {
      batch(() => {
        const next = new Map(messages.value);
        next.delete(peer);
        messages.value = next;
        person((list) => list.filter((c) => c.peerId !== peer));
      });
      return Promise.resolve();
    },

    startCall(peer, video) {
      if (lineOpen(peer)) {
        call.value = {
          callId: "c0".repeat(16),
          peerId: peer,
          video,
          incoming: false,
          state: { kind: "Outgoing" },
          muted: false,
          cameraOff: false,
        };
      }
      return Promise.resolve();
    },
    acceptCall() {
      if (call.value) call.value = { ...call.value, state: { kind: "Active" } };
      return Promise.resolve();
    },
    declineCall() {
      call.value = null;
      return Promise.resolve();
    },
    hangup() {
      call.value = null;
      return Promise.resolve();
    },
    setMuted(muted) {
      if (call.value) call.value = { ...call.value, muted };
    },
    setCameraOff(off) {
      if (call.value) call.value = { ...call.value, cameraOff: off };
    },
    replaceCamera(stream) {
      for (const track of stream.getTracks()) track.stop();
      return Promise.resolve();
    },
    dismissCall() {
      call.value = null;
    },

    setTurn(settings) {
      turn.value = settings
        ? { uri: settings.uri, username: settings.username, relayOnly: settings.relayOnly }
        : null;
      return Promise.resolve();
    },
    dismissNotice() {
      notice.value = null;
    },
    wipe() {
      this.clear();
      return Promise.resolve();
    },

    setPath,

    setPhase(next) {
      phase.value = next;
    },

    setCall(next) {
      call.value = next;
    },

    setSelfOnline(online) {
      batch(() => {
        selfOnline.value = online;
        relay.value = online
          ? { kind: "Registered", profile: "signaling-only" }
          : { kind: "Disconnected", reason: "network" };
        if (online) { for (const c of people.value) flush(c.peerId); }
        else call.value = null;
      });
    },

    someoneUsedCode() {
      const contact: Contact = {
        peerId: USED_CODE_PEER,
        name: "",
        identityKey: null,
        addedMs: Date.now(),
        verified: "no",
        verifiedMs: null,
      };
      batch(() => {
        // The code is used up, as a real one is.
        pairing.value = null;
        paths.value = new Map(paths.value).set(contact.peerId, "Offline");
        person((list) => [...list.filter((c) => c.peerId !== contact.peerId), contact]);
      });
      return contact.peerId;
    },

    clear() {
      batch(() => {
        people.value = [];
        paths.value = new Map();
        messages.value = new Map();
        call.value = null;
        publish();
      });
    },

    reset() {
      batch(() => {
        relay.value = { kind: "Registered", profile: "signaling-only" };
        selfOnline.value = true;
        people.value = options.empty ? [] : seedContacts();
        paths.value = new Map(options.empty ? [] : SEED_CONTACTS.map(([id, , path]) => [id, path]));
        messages.value = options.empty ? new Map() : seedMessages();
        call.value = null;
        pairing.value = null;
        publish();
      });
    },
  };
}
