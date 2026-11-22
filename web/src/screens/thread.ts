// How a conversation's messages become bubbles, and the one animated moment of the app:
// when the line opens, the messages that waited fill in one after another.
import { useEffect, useLayoutEffect, useRef, useState } from "denext";
import type { BubbleKind } from "../components/Bubble.tsx";
import { transferKind } from "../components/FileBubble.tsx";
import type { ChatMessage, DeliveryState, TransferInfo } from "../state/model.ts";

/** Time between one waiting bubble starting to fill and the next (tokens: motion.fill-stagger). */
export const FILL_STAGGER_MS = 350;

export interface ThreadItem {
  message: ChatMessage;
  kind: BubbleKind;
  /** First bubble of a run from the same side: gets more space above. */
  groupStart: boolean;
  /** Last bubble of a run: gets the tail corner. */
  groupEnd: boolean;
}

export type Caption = "waiting" | "delivered" | "dropped";

export function bubbleKind(message: ChatMessage, stillOutlined: ReadonlySet<number>): BubbleKind {
  if (message.direction === "Received") return "received";
  if (message.state === "Dropped") return "dropped";
  if (message.state === "Queued" || stillOutlined.has(message.id)) return "held";
  return "delivered";
}

export function threadItems(
  messages: readonly ChatMessage[],
  stillOutlined: ReadonlySet<number> = new Set(),
): ThreadItem[] {
  return messages.map((message, i) => ({
    message,
    kind: bubbleKind(message, stillOutlined),
    groupStart: messages[i - 1]?.direction !== message.direction,
    groupEnd: messages[i + 1]?.direction !== message.direction,
  }));
}

/**
 * The single caption of a thread sits under our last message and says where it is. Returns
 * the index of the item it follows, or null when we have sent nothing.
 */
export function captionOf(
  items: readonly ThreadItem[],
): { after: number; caption: Caption } | null {
  for (let i = items.length - 1; i >= 0; i--) {
    const kind = items[i].kind;
    if (kind === "received") continue;
    if (kind === "stopped") continue;
    return { after: i, caption: kind === "held" ? "waiting" : kind };
  }
  return null;
}

/** One entry of a conversation's timeline: a message, or a file transfer. */
export type Entry =
  | { type: "message"; message: ChatMessage }
  | { type: "transfer"; transfer: TransferInfo };

function entryDirection(entry: Entry): ChatMessage["direction"] {
  return entry.type === "message" ? entry.message.direction : entry.transfer.direction;
}

/**
 * Messages and transfers in one timeline, by time (a message's `timestampMs`, a transfer's
 * `createdMs`). Both lists are oldest first; at the same moment the message comes first, and
 * each list keeps its own order.
 */
export function timeline(
  messages: readonly ChatMessage[],
  transfers: readonly TransferInfo[],
): Entry[] {
  const out: Entry[] = [];
  let m = 0;
  let f = 0;
  while (m < messages.length || f < transfers.length) {
    const message = messages[m];
    const transfer = transfers[f];
    if (
      transfer === undefined || (message !== undefined && message.timestampMs <= transfer.createdMs)
    ) {
      out.push({ type: "message", message });
      m++;
    } else {
      out.push({ type: "transfer", transfer });
      f++;
    }
  }
  return out;
}

export interface TimelineItem {
  entry: Entry;
  kind: BubbleKind;
  groupStart: boolean;
  groupEnd: boolean;
}

/** The timeline as bubbles: each with its form, and grouped by side across both kinds. */
export function timelineItems(
  messages: readonly ChatMessage[],
  transfers: readonly TransferInfo[],
  stillOutlined: ReadonlySet<number> = new Set(),
): TimelineItem[] {
  const entries = timeline(messages, transfers);
  return entries.map((entry, i) => ({
    entry,
    kind: entry.type === "message"
      ? bubbleKind(entry.message, stillOutlined)
      : transferKind(entry.transfer),
    groupStart: entries[i - 1] === undefined ||
      entryDirection(entries[i - 1]) !== entryDirection(entry),
    groupEnd: entries[i + 1] === undefined ||
      entryDirection(entries[i + 1]) !== entryDirection(entry),
  }));
}

/**
 * The thread's caption follows the last of our messages. A file has its own status line, so
 * transfers neither carry the caption nor move it.
 */
export function timelineCaption(
  items: readonly TimelineItem[],
): { after: number; caption: Caption } | null {
  for (let i = items.length - 1; i >= 0; i--) {
    const { entry, kind } = items[i];
    if (entry.type !== "message" || kind === "received" || kind === "stopped") continue;
    return { after: i, caption: kind === "held" ? "waiting" : kind };
  }
  return null;
}

/** The newest entry of a conversation: what its row in the list shows. */
export function lastEntry(
  messages: readonly ChatMessage[],
  transfers: readonly TransferInfo[],
): Entry | undefined {
  return timeline(messages, transfers).at(-1);
}

function reducedMotion(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Watches a conversation's messages for the moment waiting ones are delivered and plays them
 * out in order. Returns the ids that are delivered but still drawn outlined (their turn has
 * not come) and the ids that take part in the animation at all. With reduced motion both stay
 * empty: the bubbles simply change.
 */
export function useFillSequence(messages: readonly ChatMessage[]): {
  stillOutlined: ReadonlySet<number>;
  animated: ReadonlySet<number>;
} {
  const previous = useRef<Map<number, DeliveryState> | null>(null);
  const animated = useRef(new Set<number>());
  const [queue, setQueue] = useState<{ ids: number[]; started: boolean }>({
    ids: [],
    started: false,
  });

  // Before paint, so a delivered bubble never flashes filled ahead of its turn.
  useLayoutEffect(() => {
    const before = previous.current;
    previous.current = new Map(messages.map((m) => [m.id, m.state]));
    if (!before || reducedMotion()) return;
    const delivered = messages
      .filter((m) => m.direction === "Sent" && m.state === "Sent" && before.get(m.id) === "Queued")
      .map((m) => m.id);
    if (delivered.length === 0) return;
    for (const id of delivered) animated.current.add(id);
    setQueue((q) => ({ ids: [...q.ids, ...delivered], started: q.ids.length > 0 && q.started }));
  }, [messages]);

  useEffect(() => {
    if (queue.ids.length === 0) return;
    // The first bubble starts on the next frame (so its outlined state is painted first and
    // the transition runs), each later one a stagger after the one before.
    const timer = setTimeout(
      () => setQueue((q) => ({ ids: q.ids.slice(1), started: true })),
      queue.started ? FILL_STAGGER_MS : 30,
    );
    return () => clearTimeout(timer);
  }, [queue]);

  return { stillOutlined: new Set(queue.ids), animated: animated.current };
}
