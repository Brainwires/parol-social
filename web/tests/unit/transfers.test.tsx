// File transfers in the interface: where a file sits in the timeline, the form and words of
// its bubble in every state, its actions, saving it, and the fake store the lab runs on.
import { assert, assertEquals, assertRejects } from "@std/assert";
import { fireEvent, render, type TestElement } from "denext/testing";
import { Composer } from "../../src/components/Composer.tsx";
import {
  FileBubble,
  type TransferAction,
  transferActions,
  transferKind,
  transferStatus,
} from "../../src/components/FileBubble.tsx";
import type { ChatMessage, TransferInfo, TransferState } from "../../src/engine/types.ts";
import { previewOfEntry } from "../../src/screens/ConversationList.tsx";
import { errorText } from "../../src/screens/errors.ts";
import { lastEntry, timeline, timelineCaption, timelineItems } from "../../src/screens/thread.ts";
import { EngineError } from "../../src/engine/types.ts";
import { createFakeStore, FAKE_PEERS } from "../../src/state/fake.ts";
import {
  REVOKE_AFTER_MS,
  type SaveDeps,
  saveFile,
  type SaveHandle,
} from "../../src/state/save-file.ts";
import { transfersOf } from "../../src/state/store.ts";

const PEER = "a1".repeat(32);

function message(id: number, timestampMs: number, sent = false): ChatMessage {
  return {
    id,
    peerId: PEER,
    direction: sent ? "Sent" : "Received",
    text: `m${id}`,
    timestampMs,
    state: sent ? "Sent" : "Received",
  };
}

function transfer(fields: Partial<TransferInfo> = {}): TransferInfo {
  return {
    id: "f0".repeat(16),
    peerId: PEER,
    direction: "Sent",
    name: "report.pdf",
    size: 48_000_000,
    mime: "application/pdf",
    state: { kind: "Offered" },
    bytesDone: 0,
    pending: false,
    createdMs: 0,
    available: false,
    ...fields,
  };
}

const cancelled = (byPeer: boolean, reason: string): TransferState =>
  ({ kind: "Cancelled", byPeer, reason }) as TransferState;

// --- The timeline -------------------------------------------------------------------------

Deno.test("timeline: messages and transfers merge by time; a tie keeps the message first", () => {
  const entries = timeline(
    [message(1, 10), message(2, 30, true), message(3, 50)],
    [
      transfer({ id: "a", createdMs: 5 }),
      transfer({ id: "b", createdMs: 30 }),
      transfer({ id: "c", createdMs: 60 }),
    ],
  );
  assertEquals(
    entries.map((e) => e.type === "message" ? `m${e.message.id}` : `t${e.transfer.id}`),
    ["ta", "m1", "m2", "tb", "m3", "tc"],
  );
  assertEquals(timeline([], []), []);
  assertEquals(
    lastEntry([message(1, 10)], [transfer({ id: "z", createdMs: 11 })])?.type,
    "transfer",
  );
  assertEquals(
    lastEntry([message(1, 12)], [transfer({ id: "z", createdMs: 11 })])?.type,
    "message",
  );
});

Deno.test("timeline: groups run across messages and files from the same side", () => {
  const items = timelineItems(
    [message(1, 10, true), message(2, 30)],
    [transfer({ id: "a", createdMs: 20, direction: "Sent" })],
  );
  assertEquals(items.map((i) => [i.groupStart, i.groupEnd]), [
    [true, false],
    [false, true],
    [true, true],
  ]);
  assertEquals(items.map((i) => i.kind), ["delivered", "held", "received"]);
});

Deno.test("timeline: the caption follows our last message, never a file", () => {
  const items = timelineItems(
    [message(1, 10, true)],
    [
      transfer({ id: "a", createdMs: 20 }),
      transfer({ id: "b", createdMs: 30, direction: "Received" }),
    ],
  );
  assertEquals(timelineCaption(items), { after: 0, caption: "delivered" });
  assertEquals(timelineCaption(timelineItems([], [transfer()])), null);
});

// --- Outlined here, filled there -----------------------------------------------------------

Deno.test("transferKind: outlined until it is on their device, filled once it is", () => {
  const rows: Array<[Partial<TransferInfo>, string]> = [
    // A file we send is here until their device has all of it.
    [{ direction: "Sent", state: { kind: "Offered" } }, "held"],
    [{ direction: "Sent", state: { kind: "Offered" }, pending: true }, "held"],
    [{ direction: "Sent", state: { kind: "Waiting" } }, "held"],
    [{ direction: "Sent", state: { kind: "Active" } }, "held"],
    [{ direction: "Sent", state: { kind: "Complete" } }, "delivered"],
    [{ direction: "Sent", state: { kind: "Declined" } }, "stopped"],
    [{ direction: "Sent", state: cancelled(false, "Unavailable") }, "stopped"],
    // A file offered to us is a received bubble, outlined only while our answer waits here.
    [{ direction: "Received", state: { kind: "Offered" } }, "received"],
    [{ direction: "Received", state: { kind: "Waiting" }, pending: true }, "held"],
    [{ direction: "Received", state: { kind: "Active" } }, "received"],
    [{ direction: "Received", state: { kind: "Complete" }, available: true }, "received"],
    [{ direction: "Received", state: { kind: "Declined" }, pending: true }, "stopped"],
    [{ direction: "Received", state: cancelled(true, "User") }, "stopped"],
  ];
  for (const [fields, kind] of rows) {
    assertEquals(transferKind(transfer(fields)), kind, JSON.stringify(fields));
  }
});

// --- The words -------------------------------------------------------------------------------

Deno.test("transferStatus: one sentence for every state, from either side", () => {
  const rows: Array<[Partial<TransferInfo>, string]> = [
    [
      { direction: "Sent", state: { kind: "Offered" }, pending: true },
      "Waiting on this device until Mira is reachable",
    ],
    [{ direction: "Sent", state: { kind: "Offered" } }, "Offered: waiting for Mira to accept"],
    [{ direction: "Sent", state: { kind: "Waiting" } }, "Waiting for a direct connection"],
    [{ direction: "Sent", state: { kind: "Active" }, bytesDone: 12_000_000 }, "12 MB of 48 MB"],
    [{ direction: "Sent", state: { kind: "Complete" } }, "On Mira's device"],
    [{ direction: "Sent", state: { kind: "Declined" } }, "Mira declined"],
    [{ direction: "Sent", state: cancelled(false, "User") }, "You cancelled"],
    [{ direction: "Sent", state: cancelled(true, "User") }, "Mira cancelled"],
    [
      { direction: "Sent", state: cancelled(false, "Unavailable") },
      "This page was reloaded before the file was sent. Send it again.",
    ],
    [
      { direction: "Sent", state: cancelled(true, "Storage") },
      "Stopped: Mira's device could not store it",
    ],
    [
      { direction: "Sent", state: cancelled(true, "Integrity") },
      "Stopped: what arrived did not verify",
    ],
    [
      { direction: "Sent", state: cancelled(true, "Limit") },
      "Stopped: it is over a limit of Mira's device",
    ],
    [
      { direction: "Sent", state: cancelled(false, "Limit") },
      "Stopped: it is over a limit of this device",
    ],
    [{ direction: "Sent", state: cancelled(true, "Other") }, "Stopped before it was complete"],
    [
      { direction: "Received", state: { kind: "Offered" } },
      "Mira offers this file. Accept to receive it.",
    ],
    [
      { direction: "Received", state: { kind: "Waiting" }, pending: true },
      "Waiting on this device until Mira is reachable",
    ],
    [{ direction: "Received", state: { kind: "Waiting" } }, "Waiting for a direct connection"],
    [{ direction: "Received", state: { kind: "Active" }, bytesDone: 2_500_000 }, "2.5 MB of 48 MB"],
    [{ direction: "Received", state: { kind: "Complete" }, available: true }, "On this device"],
    [
      { direction: "Received", state: { kind: "Complete" }, available: false },
      "Received. The file is no longer on this device.",
    ],
    [{ direction: "Received", state: { kind: "Declined" } }, "You declined"],
    [{ direction: "Received", state: cancelled(false, "User") }, "You cancelled"],
    [{ direction: "Received", state: cancelled(true, "User") }, "Mira cancelled"],
    [
      { direction: "Received", state: cancelled(true, "Unavailable") },
      "Stopped: the file is no longer available on Mira's device",
    ],
    [
      { direction: "Received", state: cancelled(false, "Unavailable") },
      "Stopped: the file is no longer available on this device",
    ],
    [
      { direction: "Received", state: cancelled(false, "Integrity") },
      "Stopped: what arrived did not verify",
    ],
    [
      { direction: "Received", state: cancelled(false, "Storage") },
      "Stopped: this device could not store it",
    ],
    [{ direction: "Received", state: cancelled(false, "Other") }, "Stopped before it was complete"],
  ];
  for (const [fields, words] of rows) {
    assertEquals(
      transferStatus(transfer(fields), "Mira", true, "en"),
      words,
      JSON.stringify(fields),
    );
  }
  // Where received files do not survive a reload, the words say so.
  assertEquals(
    transferStatus(
      transfer({ direction: "Received", state: { kind: "Complete" }, available: true }),
      "Mira",
      false,
      "en",
    ),
    "On this device until this page is closed or reloaded",
  );
});

Deno.test("transferActions: what each state offers", () => {
  const rows: Array<[Partial<TransferInfo>, TransferAction[]]> = [
    [{ direction: "Received", state: { kind: "Offered" } }, ["accept", "decline"]],
    [{ direction: "Received", state: { kind: "Waiting" } }, ["cancel"]],
    [{ direction: "Received", state: { kind: "Active" } }, ["cancel"]],
    [{ direction: "Received", state: { kind: "Complete" }, available: true }, ["save", "remove"]],
    [{ direction: "Received", state: { kind: "Complete" }, available: false }, ["remove"]],
    [{ direction: "Received", state: { kind: "Declined" } }, ["remove"]],
    [{ direction: "Sent", state: { kind: "Offered" }, pending: true }, ["cancel"]],
    [{ direction: "Sent", state: { kind: "Active" } }, ["cancel"]],
    [{ direction: "Sent", state: { kind: "Complete" } }, ["remove"]],
    [{ direction: "Sent", state: cancelled(true, "User") }, ["remove"]],
  ];
  for (const [fields, actions] of rows) {
    assertEquals(transferActions(transfer(fields)), actions, JSON.stringify(fields));
  }
});

Deno.test("errors: what offering a file can say", () => {
  assertEquals(
    errorText(new EngineError("Transfer", "x")),
    "This file cannot be sent. Check that it opens and is not too large.",
  );
  assertEquals(
    errorText(new EngineError("NoSession", "x"), { name: "Mira" }),
    "The secure line to Mira is not set up yet. Try again in a moment.",
  );
  assertEquals(
    errorText(new EngineError("UnknownContact", "x")),
    "This contact is not on this device.",
  );
});

Deno.test("list preview: the newest entry, a file by its name", () => {
  assertEquals(
    previewOfEntry({ type: "transfer", transfer: transfer({ direction: "Received" }) }),
    "File: report.pdf",
  );
  assertEquals(previewOfEntry({ type: "transfer", transfer: transfer() }), "You: File: report.pdf");
  assertEquals(previewOfEntry({ type: "message", message: message(1, 1) }), "m1");
  assertEquals(previewOfEntry(undefined), "No messages yet");
});

/** The first descendant that matches (the test DOM has no selectors). */
function find(el: TestElement, match: (el: TestElement) => boolean): TestElement | null {
  for (const child of el.children) {
    if (match(child)) return child;
    const deeper = find(child, match);
    if (deeper) return deeper;
  }
  return null;
}

// --- The component ---------------------------------------------------------------------------

Deno.test("FileBubble: test ids, attributes and the form of each state", async () => {
  const screen = await render(
    <FileBubble
      transfer={transfer({ state: { kind: "Active" }, bytesDone: 12_000_000, pending: false })}
      name="Mira"
      tail="end"
      onAction={() => {}}
    />,
  );
  const root = screen.getByTestId("transfer-bubble");
  assertEquals(root.getAttribute("data-transfer-id"), "f0".repeat(16));
  assertEquals(root.getAttribute("data-direction"), "sent");
  assertEquals(root.getAttribute("data-state"), "active");
  assertEquals(root.getAttribute("data-pending"), "false");
  assertEquals(root.getAttribute("data-kind"), "held");
  assertEquals(
    find(root, (el) => el.getAttribute("class")?.startsWith("bubble ") ?? false)?.getAttribute(
      "class",
    ),
    "bubble bubble--held bubble--tail-end bubble--file",
  );
  assertEquals(screen.getByTestId("transfer-name").textContent, "report.pdf");
  assertEquals(screen.getByTestId("transfer-status").textContent, "12 MB of 48 MB");
  const bar = find(root, (el) => el.localName === "progress");
  assert(bar, "a progress bar while it moves");
  assertEquals(bar.getAttribute("max"), "48000000");
  assertEquals(bar.getAttribute("value"), "12000000");
  assertEquals(screen.getByTestId("transfer-cancel").textContent, "Cancel");

  await screen.rerender(
    <FileBubble
      transfer={transfer({ state: { kind: "Complete" }, bytesDone: 48_000_000 })}
      name="Mira"
      onAction={() => {}}
    />,
  );
  const done = screen.getByTestId("transfer-bubble");
  assertEquals(done.getAttribute("data-kind"), "delivered");
  assertEquals(done.getAttribute("data-state"), "complete");
  assertEquals(find(done, (el) => el.localName === "progress"), null);
  assertEquals(screen.queryByTestId("transfer-cancel"), null);
  assertEquals(screen.getByTestId("transfer-status").textContent, "On Mira's device");
});

Deno.test("FileBubble: its buttons per state, each reporting its action", async () => {
  const cases: Array<[Partial<TransferInfo>, TransferAction[]]> = [
    [{ direction: "Received", state: { kind: "Offered" } }, ["accept", "decline"]],
    [{ direction: "Received", state: { kind: "Waiting" }, pending: true }, ["cancel"]],
    [{ direction: "Received", state: { kind: "Complete" }, available: true }, ["save", "remove"]],
    [{ direction: "Sent", state: { kind: "Declined" } }, ["remove"]],
  ];
  const all: TransferAction[] = ["accept", "decline", "cancel", "save", "remove"];
  for (const [fields, actions] of cases) {
    const chosen: TransferAction[] = [];
    const screen = await render(
      <FileBubble transfer={transfer(fields)} name="Mira" onAction={(a) => void chosen.push(a)} />,
    );
    for (const action of all) {
      const button = screen.queryByTestId(`transfer-${action}`);
      assertEquals(
        button !== null,
        actions.includes(action),
        `${JSON.stringify(fields)} ${action}`,
      );
      if (button) {
        assertEquals(button.tagName, "BUTTON");
        await fireEvent.click(button);
      }
    }
    assertEquals(chosen, actions);
    await screen.unmount();
  }
});

Deno.test("FileBubble: the name is text, never markup", async () => {
  const screen = await render(
    <FileBubble
      transfer={transfer({ name: "<img src=x onerror=alert(1)>.png" })}
      name="Mira"
      onAction={() => {}}
    />,
  );
  const name = screen.getByTestId("transfer-name");
  assertEquals(name.textContent, "<img src=x onerror=alert(1)>.png");
  assertEquals(find(name, (el) => el.localName === "img"), null);
});

Deno.test("Composer: an attach button with a name, a real file input, and Preparing …", async () => {
  const chosen: string[][] = [];
  const screen = await render(
    <Composer
      name="Mira"
      state="open"
      onSend={() => {}}
      onAttach={(files) => void chosen.push(files.map((f) => f.name))}
      preparing={["big.iso"]}
    />,
  );
  assertEquals(screen.getByTestId("composer-attach").getAttribute("aria-label"), "Send a file");
  const input = screen.getByTestId("composer-file");
  assertEquals(input.tagName, "INPUT");
  assertEquals(input.getAttribute("type"), "file");
  assertEquals(screen.getByTestId("composer-preparing").textContent, "Preparing big.iso…");
  // The field stays usable meanwhile.
  assertEquals(screen.getByTestId("composer-input").hasAttribute("disabled"), false);

  // Without onAttach there is no attach control.
  await screen.rerender(<Composer name="Mira" state="open" onSend={() => {}} />);
  assertEquals(screen.queryByTestId("composer-attach"), null);
  assertEquals(screen.queryByTestId("composer-file"), null);
  assertEquals(screen.queryByTestId("composer-preparing"), null);
  assertEquals(chosen, []);
});

// --- Saving ------------------------------------------------------------------------------------

function fakeDeps(picker?: SaveDeps["showSaveFilePicker"]) {
  const log: string[] = [];
  const timers: Array<{ fn: () => void; ms: number }> = [];
  const deps: SaveDeps = {
    showSaveFilePicker: picker,
    createObjectURL: (blob) => {
      log.push(`url:${blob.type}:${blob.size}`);
      return "blob:fake/1";
    },
    revokeObjectURL: (url) => void log.push(`revoke:${url}`),
    download: (url, name) => void log.push(`download:${url}:${name}`),
    setTimeout: (fn, ms) => void timers.push({ fn, ms }),
  };
  return { deps, log, timers };
}

Deno.test("saveFile: with a save dialog, the blob is streamed into what the person chose", async () => {
  const written: Uint8Array[] = [];
  let closed = false;
  const asked: string[] = [];
  const order: string[] = [];
  const { deps, log } = fakeDeps((options) => {
    asked.push(options.suggestedName);
    order.push("picker");
    const handle: SaveHandle = {
      createWritable: () =>
        Promise.resolve(
          new WritableStream<Uint8Array>({
            write: (chunk) => void written.push(chunk),
            close: () => void (closed = true),
          }),
        ),
    };
    return Promise.resolve(handle);
  });
  const outcome = await saveFile("report.pdf", () => {
    order.push("blob");
    return Promise.resolve(new Blob(["%PDF-1.7"], { type: "application/pdf" }));
  }, deps);
  assertEquals(outcome, "saved");
  assertEquals(asked, ["report.pdf"]);
  // The dialog opens first, while the click still counts.
  assertEquals(order, ["picker", "blob"]);
  assertEquals(new TextDecoder().decode(written[0]), "%PDF-1.7");
  assertEquals(closed, true);
  assertEquals(log, [], "no download link when there is a dialog");
});

Deno.test("saveFile: closing the dialog is not an error; other failures are", async () => {
  const abort = new DOMException("closed", "AbortError");
  const quiet = fakeDeps(() => Promise.reject(abort));
  let read = false;
  const outcome = await saveFile("a.txt", () => {
    read = true;
    return Promise.resolve(new Blob(["x"]));
  }, quiet.deps);
  assertEquals(outcome, "cancelled");
  assertEquals(read, false, "nothing is read when nothing will be written");

  const broken = fakeDeps(() => Promise.reject(new DOMException("no", "SecurityError")));
  await assertRejects(() => saveFile("a.txt", () => Promise.resolve(new Blob(["x"])), broken.deps));
});

Deno.test("saveFile: without a dialog, a download link to an object URL, revoked afterwards", async () => {
  const { deps, log, timers } = fakeDeps();
  const outcome = await saveFile(
    "photo.jpg",
    () => Promise.resolve(new Blob(["jpeg"], { type: "image/jpeg" })),
    deps,
  );
  assertEquals(outcome, "saved");
  // The type is the engine's blob's own.
  assertEquals(log, ["url:image/jpeg:4", "download:blob:fake/1:photo.jpg"]);
  assertEquals(timers.map((t) => t.ms), [REVOKE_AFTER_MS]);
  timers[0].fn();
  assertEquals(log.at(-1), "revoke:blob:fake/1");
});

Deno.test("saveFile: no file means nothing is saved", async () => {
  const { deps, log } = fakeDeps();
  assertEquals(await saveFile("gone.bin", () => Promise.resolve(null), deps), "missing");
  assertEquals(log, []);
});

// --- The fake store ------------------------------------------------------------------------

Deno.test("fake store: seeded transfers, and each command moves a transfer the engine's way", async () => {
  const store = createFakeStore({ hashDelayMs: 0 });
  const mira = () => transfersOf(store, FAKE_PEERS.mira);
  assertEquals(mira().map((t) => `${t.direction}:${t.state.kind}`), [
    "Received:Complete",
    "Sent:Active",
    "Received:Offered",
  ]);
  const offered = mira()[2];
  await store.acceptTransfer(offered.id);
  // Mira's line is open: it moves at once.
  assertEquals(mira()[2].state.kind, "Active");
  await store.cancelTransfer(offered.id);
  assertEquals(mira()[2].state, { kind: "Cancelled", byPeer: false, reason: "User" });
  await store.removeTransfer(offered.id);
  assertEquals(mira().length, 2);
  // Only a finished transfer can be removed.
  await assertRejects(() => store.removeTransfer(mira()[1].id), EngineError);

  // Offering on a line that is not open waits on this device.
  const sent = await store.offerFile(FAKE_PEERS.tomasz, new File(["x"], "keys.txt"));
  assertEquals([sent.state.kind, sent.pending], ["Offered", true]);
  store.setPath(FAKE_PEERS.tomasz, "Direct");
  assertEquals(transfersOf(store, FAKE_PEERS.tomasz)[0].pending, false);

  store.reset();
  assertEquals(mira().length, 3);
  assertEquals(transfersOf(store, FAKE_PEERS.tomasz), []);
});
