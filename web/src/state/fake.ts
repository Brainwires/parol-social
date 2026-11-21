// An in-memory AppStore with made-up people, for building and testing the screens before the
// real services exist. It behaves like the core where the UI can tell: a message sent on an
// open line is delivered, anything else waits; when a line opens, what waited is delivered.
import { batch, signal } from "denext/signals";
import type {
  ActiveCall,
  CallMedia,
  ChatMessage,
  Contact,
  MessageBody,
  PathState,
  RelayState,
} from "./model.ts";
import type { AppStore, FakeControls } from "./store.ts";

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

const SEED_CONTACTS: Contact[] = [
  { peerId: FAKE_PEERS.mira, name: "Mira", kind: "person", path: "Direct" },
  { peerId: FAKE_PEERS.tomasz, name: "Tomasz", kind: "person", path: "Offline" },
  { peerId: FAKE_PEERS.readers, name: "Reading group", kind: "group", path: "Direct" },
  { peerId: FAKE_PEERS.ines, name: "Ines", kind: "person", path: "Connecting" },
  { peerId: FAKE_PEERS.kofi, name: "Kofi", kind: "person", path: "NoDirectPath" },
  { peerId: FAKE_PEERS.sana, name: "Sana", kind: "person", path: "BindingFailed" },
  { peerId: FAKE_PEERS.jun, name: "Jun", kind: "person", path: "Offline" },
];

type Line = ["in" | "out" | "held", string | MessageBody];

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

/** A fixed clock for the seed, so screenshots and tests do not depend on the time of day. */
const SEED_EPOCH_MS = Date.UTC(2026, 10, 20, 9, 0, 0);

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
        body: typeof content === "string" ? { kind: "text", text: content } : content,
        timestampMs: SEED_EPOCH_MS + index * 3 * MINUTE,
        state: how === "in" ? "Received" : how === "out" ? "Sent" : "Queued",
      })),
    );
  }
  return all;
}

export interface FakeStoreOptions {
  /** How long a retried connection takes before it fails the same way again. */
  retryDelayMs?: number;
  /** Start with no contacts (the empty state). */
  empty?: boolean;
}

export function createFakeStore(options: FakeStoreOptions = {}): AppStore & FakeControls {
  const retryDelayMs = options.retryDelayMs ?? 1500;
  const relay = signal<RelayState>({ kind: "Registered", profile: "signaling-only" });
  const selfOnline = signal(true);
  const contacts = signal<readonly Contact[]>(options.empty ? [] : SEED_CONTACTS);
  const messages = signal<ReadonlyMap<string, readonly ChatMessage[]>>(
    options.empty ? new Map() : seedMessages(),
  );
  const call = signal<ActiveCall | null>(null);
  let nextId = 1000;

  const pathOf = (peer: string) => contacts.value.find((c) => c.peerId === peer)?.path;
  const lineOpen = (peer: string) => selfOnline.value && pathOf(peer) === "Direct";

  function update(peer: string, change: (list: readonly ChatMessage[]) => ChatMessage[]): void {
    const next = new Map(messages.value);
    next.set(peer, change(next.get(peer) ?? []));
    messages.value = next;
  }

  /** Deliver what waited for this contact. */
  function flush(peer: string): void {
    if (!lineOpen(peer)) return;
    update(peer, (list) => list.map((m) => (m.state === "Queued" ? { ...m, state: "Sent" } : m)));
  }

  function setPath(peer: string, path: PathState): void {
    batch(() => {
      contacts.value = contacts.value.map((c) => (c.peerId === peer ? { ...c, path } : c));
      flush(peer);
      if (path !== "Direct" && call.value?.peerId === peer) call.value = null;
    });
  }

  return {
    relay,
    selfOnline,
    contacts,
    messages,
    call,

    send(peer, text) {
      const message: ChatMessage = {
        id: ++nextId,
        peerId: peer,
        direction: "Sent",
        body: { kind: "text", text },
        timestampMs: Date.now(),
        state: lineOpen(peer) ? "Sent" : "Queued",
      };
      update(peer, (list) => [...list, message]);
    },

    takeBack(peer, messageId) {
      update(peer, (list) => list.filter((m) => !(m.id === messageId && m.state === "Queued")));
    },

    edit(peer, messageId, text) {
      update(
        peer,
        (list) =>
          list.map((m) =>
            m.id === messageId && m.state === "Queued" ? { ...m, body: { kind: "text", text } } : m
          ),
      );
    },

    retryPath(peer) {
      const before = pathOf(peer);
      if (before !== "NoDirectPath" && before !== "BindingFailed") return;
      setPath(peer, "Connecting");
      // The fake network has not changed: the attempt ends the way the last one did.
      setTimeout(() => {
        if (pathOf(peer) === "Connecting") setPath(peer, before);
      }, retryDelayMs);
    },

    addContact(name, code) {
      const contact: Contact = {
        peerId: code.replace(/[^0-9a-f]/gi, "").toLowerCase().padEnd(64, "0").slice(0, 64),
        name,
        kind: "person",
        path: "Offline",
      };
      contacts.value = [...contacts.value, contact];
      return contact;
    },

    startCall(peer, media: CallMedia) {
      if (lineOpen(peer)) call.value = { peerId: peer, media, state: { kind: "Outgoing" } };
    },

    endCall() {
      call.value = null;
    },

    setPath,

    setSelfOnline(online) {
      batch(() => {
        selfOnline.value = online;
        relay.value = online
          ? { kind: "Registered", profile: "signaling-only" }
          : { kind: "Disconnected", reason: "network" };
        if (online) { for (const c of contacts.value) flush(c.peerId); }
        else call.value = null;
      });
    },

    clear() {
      batch(() => {
        contacts.value = [];
        messages.value = new Map();
        call.value = null;
      });
    },

    reset() {
      batch(() => {
        relay.value = { kind: "Registered", profile: "signaling-only" };
        selfOnline.value = true;
        contacts.value = options.empty ? [] : SEED_CONTACTS;
        messages.value = options.empty ? new Map() : seedMessages();
        call.value = null;
      });
    },
  };
}
