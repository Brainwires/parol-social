import { assertEquals } from "@std/assert";
import { fireEvent, render, userEvent } from "denext/testing";
import { Bubble, formatBytes, HeldBubble } from "../../src/components/Bubble.tsx";
import { Button, IconButton } from "../../src/components/Button.tsx";
import { CodeBlock, groups, SafetyNumber } from "../../src/components/Codes.tsx";
import { Composer } from "../../src/components/Composer.tsx";
import { ConversationRow, initial } from "../../src/components/ConversationRow.tsx";
import { Line } from "../../src/components/Line.tsx";
import { Panel } from "../../src/components/Panel.tsx";
import { QrCode } from "../../src/components/QrCode.tsx";
import type { ContactView, LineState, PathState } from "../../src/state/model.ts";

Deno.test("Line: a polite status with the words of each state", async () => {
  const words: Record<LineState, string> = {
    "open": "Direct, end-to-end encrypted",
    "waiting": "Waiting for Mira to come online",
    "connecting": "Connecting to Mira",
    "no-path": "No direct path to Mira",
    "blocked": "Blocked for your safety",
    "self-offline": "You are offline",
  };
  for (const [state, text] of Object.entries(words)) {
    const screen = await render(<Line state={state as LineState} name="Mira" />);
    const line = screen.getByRole("status");
    assertEquals(line.getAttribute("aria-live"), "polite");
    assertEquals(line.getAttribute("data-state"), state);
    assertEquals(line.textContent, text);
    await screen.unmount();
  }
});

Deno.test("Button and IconButton: test ids and accessible names", async () => {
  const screen = await render(
    <div>
      <Button variant="danger" testId="end">End call</Button>
      <IconButton icon="phone" label="Call Mira" testId="call" unavailable />
    </div>,
  );
  assertEquals(screen.getByTestId("end").getAttribute("class"), "btn btn--danger");
  const call = screen.getByTestId("call");
  assertEquals(call.getAttribute("aria-label"), "Call Mira");
  // Unavailable, not disabled: it stays focusable so it can say why.
  assertEquals(call.getAttribute("aria-disabled"), "true");
  assertEquals(call.hasAttribute("disabled"), false);
});

Deno.test("Bubble: the form says where the message is", async () => {
  const screen = await render(
    <div>
      <Bubble kind="received" content={{ text: "in" }} testId="a" />
      <Bubble kind="delivered" content={{ text: "out" }} tail="end" testId="b" />
      <Bubble
        kind="held"
        content={{ text: "", attachment: { kind: "file", name: "a.pdf", bytes: 184_320 } }}
        fill
        testId="c"
      />
    </div>,
  );
  assertEquals(screen.getByTestId("a").getAttribute("class"), "bubble bubble--received");
  assertEquals(
    screen.getByTestId("b").getAttribute("class"),
    "bubble bubble--delivered bubble--tail-end",
  );
  assertEquals(screen.getByTestId("c").getAttribute("class"), "bubble bubble--held");
  assertEquals(screen.getByTestId("c").hasAttribute("data-fill"), true);
  assertEquals(screen.getByTestId("a").hasAttribute("data-fill"), false);
  assertEquals(screen.getByTestId("c").textContent?.includes("a.pdf"), true);
});

// Opening the menu moves focus into it, which denext/testing's DOM cannot do (its elements
// have no focus()); tests/e2e/design.spec.ts covers the menu in real browsers.
Deno.test("HeldBubble: a button that announces its menu", async () => {
  const screen = await render(
    <HeldBubble
      content={{ text: "wait" }}
      testId="held"
      onTakeBack={() => {}}
      onEdit={() => {}}
    />,
  );
  const bubble = screen.getByTestId("held");
  assertEquals(bubble.tagName, "BUTTON");
  assertEquals(bubble.getAttribute("aria-haspopup"), "menu");
  assertEquals(bubble.getAttribute("aria-expanded"), "false");
  assertEquals(bubble.getAttribute("class"), "bubble bubble--held");
  assertEquals(screen.queryByRole("menu"), null);
});

Deno.test("Composer: never disabled; the placeholder says what will happen", async () => {
  const sent: string[] = [];
  const screen = await render(
    <Composer name="Mira" state="away" onSend={(text) => void sent.push(text)} />,
  );
  const field = screen.getByTestId("composer-input");
  assertEquals(field.hasAttribute("disabled"), false);
  assertEquals(field.getAttribute("placeholder"), "Mira is away. Your message will wait here.");
  await userEvent.type(field, "  hello  ");
  // Enter sends (the test DOM does not submit a form from its button; browsers do, see e2e).
  await fireEvent.keyDown(field, { key: "Enter" });
  assertEquals(sent, ["hello"]);

  await screen.rerender(<Composer name="Mira" state="open" onSend={() => {}} />);
  assertEquals(screen.getByTestId("composer-input").getAttribute("placeholder"), "Message Mira");

  // Online but unreachable: "Mira is away" would be untrue.
  await screen.rerender(<Composer name="Mira" state="no-path" onSend={() => {}} />);
  assertEquals(
    screen.getByTestId("composer-input").getAttribute("placeholder"),
    "Your message will wait here until a path exists.",
  );
});

Deno.test("Composer: the field empties at once; a message that was not sent comes back", async () => {
  let fail = true;
  const sent: string[] = [];
  const screen = await render(
    <Composer
      name="Mira"
      state="open"
      onSend={(text) => {
        sent.push(text);
        return fail ? Promise.reject(new Error("no")) : Promise.resolve();
      }}
    />,
  );
  const value = () => (screen.getByTestId("composer-input") as unknown as { value: string }).value;
  await userEvent.type(screen.getByTestId("composer-input"), "keep me");
  await fireEvent.keyDown(screen.getByTestId("composer-input"), { key: "Enter" });
  await new Promise((done) => setTimeout(done, 0));
  assertEquals(value(), "keep me");
  fail = false;
  await fireEvent.keyDown(screen.getByTestId("composer-input"), { key: "Enter" });
  await new Promise((done) => setTimeout(done, 0));
  assertEquals(value(), "");
  // Two messages in quick succession are two messages.
  await userEvent.type(screen.getByTestId("composer-input"), "one");
  await fireEvent.keyDown(screen.getByTestId("composer-input"), { key: "Enter" });
  await userEvent.type(screen.getByTestId("composer-input"), "two");
  await fireEvent.keyDown(screen.getByTestId("composer-input"), { key: "Enter" });
  await new Promise((done) => setTimeout(done, 0));
  assertEquals(sent.slice(-2), ["one", "two"]);
});

function view(path: PathState, queued: number, unread: number): ContactView {
  return {
    contact: {
      peerId: "b2".repeat(32),
      name: "Tomasz",
      identityKey: null,
      addedMs: 0,
      verified: "no",
      verifiedMs: null,
    },
    path,
    queued,
    unread,
    lastActivityMs: 0,
  };
}

Deno.test("ConversationRow: name, preview, waiting chip, unread count, presence dot", async () => {
  const screen = await render(
    <ConversationRow view={view("Offline", 3, 0)} preview="Safe flight." href="#/c/b2" current />,
  );
  const row = screen.getByTestId("row-b2b2b2b2");
  assertEquals(row.getAttribute("aria-current"), "page");
  assertEquals(screen.getByTestId("waiting-chip").textContent, "3 waiting");
  assertEquals(screen.queryByTestId("unread-badge"), null);
  assertEquals(row.outerHTML.includes("avatar__dot"), false);
  assertEquals(row.children[0].textContent, "T");

  await screen.rerender(
    <ConversationRow view={view("Direct", 0, 2)} preview="" href="#" current={false} />,
  );
  assertEquals(screen.queryByTestId("waiting-chip"), null);
  // The number for the eye, the words for a screen reader.
  assertEquals(screen.getByTestId("unread-badge").textContent, "22 new messages");
  assertEquals(screen.getByTestId("row-b2b2b2b2").outerHTML.includes("avatar__dot"), true);
});

Deno.test("QrCode: an image with a name, drawn from the code", async () => {
  const screen = await render(<QrCode text="a1b2c3" label="Your code" testId="qr" />);
  const qr = screen.getByTestId("qr");
  assertEquals(qr.getAttribute("role"), "img");
  assertEquals(qr.getAttribute("aria-label"), "Your code");
  // Version 1: 21 modules and a quiet zone of 4 on each side.
  assertEquals(qr.getAttribute("viewBox"), "0 0 29 29");
});

Deno.test("Panel: at most two actions", async () => {
  const action = (n: number) => ({ label: `Action ${n}`, testId: `a${n}`, onClick: () => {} });
  const screen = await render(
    <Panel tone="amber" title="Title" testId="panel" actions={[action(1), action(2), action(3)]}>
      Body
    </Panel>,
  );
  assertEquals(screen.getAllByRole("button").map((b) => b.textContent), ["Action 1", "Action 2"]);
  assertEquals(screen.getByTestId("panel").getAttribute("class"), "panel panel--amber");
});

Deno.test("codes: pairing code in fours, safety number as 12 groups of 5", async () => {
  assertEquals(groups("abcdefghij", 4), ["abcd", "efgh", "ij"]);
  const digits = "123456789012345678901234567890123456789012345678901234567890";
  const screen = await render(
    <div>
      <CodeBlock code="7K4MQ2ZD 9XTBH6RP" label="Pairing code" testId="code" />
      <SafetyNumber digits={digits} label="Safety number" testId="safety" />
    </div>,
  );
  assertEquals([...screen.getByTestId("code").children].map((c) => c.textContent), [
    "7K4M",
    "Q2ZD",
    "9XTB",
    "H6RP",
  ]);
  const safety = [...screen.getByTestId("safety").children].map((c) => c.textContent ?? "");
  assertEquals(safety.length, 12);
  assertEquals(safety.every((g) => /^\d{5}$/.test(g)), true);
});

Deno.test("helpers: initials and file sizes", () => {
  assertEquals(initial("  mira"), "M");
  assertEquals(initial(""), "?");
  assertEquals(initial("ñandú"), "Ñ");
  assertEquals(formatBytes(184_320, "en"), "184 kB");
  assertEquals(formatBytes(2_411_724, "en"), "2.4 MB");
  assertEquals(formatBytes(512, "en"), "512 byte");
});
