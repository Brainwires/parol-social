import { assertEquals } from "@std/assert";
import { fireEvent, render, userEvent } from "denext/testing";
import { Bubble, formatBytes, HeldBubble } from "../../src/components/Bubble.tsx";
import { Button, IconButton } from "../../src/components/Button.tsx";
import { CodeBlock, groups, SafetyNumber } from "../../src/components/Codes.tsx";
import { Composer } from "../../src/components/Composer.tsx";
import { ConversationRow, initial } from "../../src/components/ConversationRow.tsx";
import { Line } from "../../src/components/Line.tsx";
import { Panel } from "../../src/components/Panel.tsx";
import type { LineState } from "../../src/state/model.ts";

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
      <Bubble kind="received" body={{ kind: "text", text: "in" }} testId="a" />
      <Bubble kind="delivered" body={{ kind: "text", text: "out" }} tail="end" testId="b" />
      <Bubble kind="held" body={{ kind: "file", name: "a.pdf", bytes: 184_320 }} fill testId="c" />
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
      body={{ kind: "text", text: "wait" }}
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
  const screen = await render(<Composer name="Mira" away onSend={(text) => sent.push(text)} />);
  const field = screen.getByTestId("composer-field");
  assertEquals(field.hasAttribute("disabled"), false);
  assertEquals(field.getAttribute("placeholder"), "Mira is away. Your message will wait here.");
  await userEvent.type(field, "  hello  ");
  // Enter sends (the test DOM does not submit a form from its button; browsers do, see e2e).
  await fireEvent.keyDown(field, { key: "Enter" });
  assertEquals(sent, ["hello"]);

  await screen.rerender(<Composer name="Mira" away={false} onSend={() => {}} />);
  assertEquals(screen.getByTestId("composer-field").getAttribute("placeholder"), "Message Mira");
});

Deno.test("ConversationRow: name, preview, waiting chip, presence dot", async () => {
  const contact = {
    peerId: "b2".repeat(32),
    name: "Tomasz",
    kind: "person",
    path: "Offline",
  } as const;
  const screen = await render(
    <ConversationRow contact={contact} preview="Safe flight." waiting={3} href="#/c/b2" current />,
  );
  const row = screen.getByTestId("row-b2b2b2b2");
  assertEquals(row.getAttribute("aria-current"), "page");
  assertEquals(screen.getByTestId("waiting-chip").textContent, "3 waiting");
  assertEquals(row.outerHTML.includes("avatar__dot"), false);
  assertEquals(row.children[0].textContent, "T");

  await screen.rerender(
    <ConversationRow
      contact={{ ...contact, path: "Direct" }}
      preview=""
      waiting={0}
      href="#"
      current={false}
    />,
  );
  assertEquals(screen.queryByTestId("waiting-chip"), null);
  assertEquals(screen.getByTestId("row-b2b2b2b2").outerHTML.includes("avatar__dot"), true);
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
