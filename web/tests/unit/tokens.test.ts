import { assert, assertEquals } from "@std/assert";
import { type Tokens, tokensToCss } from "../../scripts/gen-tokens.ts";
import tokensJson from "../../src/design/tokens.json" with { type: "json" };

const tokens = tokensJson as unknown as Tokens;
type Theme = "light" | "dark";

/** WCAG 2.x relative luminance of a #RRGGBB colour. */
function luminance(hex: string): number {
  const channel = (i: number) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

function ratio(fg: string, bg: string, theme: Theme): number {
  return contrast(tokens.color[fg][theme], tokens.color[bg][theme]);
}

/** Every pair the components put text on: [text colour, ground]. WCAG 2.2 AA: 4.5:1. */
const TEXT_PAIRS: Array<[string, string]> = [
  ["ink", "paper"], // body text; text of a waiting bubble
  ["ink", "surface"], // fields, sheets, menus
  ["ink", "fog"], // received bubbles, avatars, codes, the selected row
  ["ink-2", "paper"], // captions, previews, section headers
  ["ink-2", "surface"],
  ["ink-2", "fog"], // preview on the selected row
  ["on-ink", "ink"], // delivered bubbles, primary buttons, toasts
  ["lamp", "paper"], // "Waiting on this device", the waiting chip
  ["lamp", "fog"], // the waiting chip on the selected row
  ["lamp", "surface"],
  ["flare", "paper"], // danger button, "Not sent"
  ["flare", "surface"],
  ["ink", "lamp-fill"], // amber panel
  ["ink", "flare-fill"], // red panel
  ["ink", "open-fill"], // an open state's ground
  ["on-video", "video-ground"], // the call screen's words
  ["flare-on-video", "video-ground"], // "End call"
  ["video-ground", "on-video"], // a call control that is switched on
];

/** State colours drawn as lines and dots next to their words. WCAG 1.4.11: 3:1. */
const GRAPHIC_PAIRS: Array<[string, string]> = [
  ["open", "paper"], // the open wire, the presence dot
  ["open", "fog"], // the presence dot on the selected row
  ["flare", "paper"], // the blocked wire
  ["flare", "flare-fill"], // the red panel's border
  ["ink-2", "paper"], // quiet button and field outlines
  ["ink-2", "surface"],
];

for (const theme of ["light", "dark"] as const) {
  Deno.test(`contrast (${theme}): text pairs meet WCAG AA 4.5:1`, () => {
    for (const [fg, bg] of TEXT_PAIRS) {
      const r = ratio(fg, bg, theme);
      assert(r >= 4.5, `${fg} on ${bg} (${theme}) is ${r.toFixed(2)}:1`);
    }
  });

  Deno.test(`contrast (${theme}): state lines and outlines meet 3:1`, () => {
    for (const [fg, bg] of GRAPHIC_PAIRS) {
      const r = ratio(fg, bg, theme);
      assert(r >= 3, `${fg} on ${bg} (${theme}) is ${r.toFixed(2)}:1`);
    }
  });
}

// lamp-line is the amber of waiting wires and dashed borders. In the dark theme it clears 3:1
// everywhere. In the light theme the decided value (#D9981E) does not (about 2.3:1 on paper),
// which is fine where it is used: every dashed border has words or a shape beside it.
Deno.test("contrast: lamp-line as a line", () => {
  for (const bg of ["paper", "surface", "lamp-fill"]) {
    assert(ratio("lamp-line", bg, "dark") >= 3, `lamp-line on ${bg} (dark)`);
  }
  const onPaper = ratio("lamp-line", "paper", "light");
  assert(onPaper > 2.2 && onPaper < 3, `lamp-line on paper (light) is ${onPaper.toFixed(2)}:1`);
});

// The focus ring depends on its colour alone, so it must clear 3:1 (WCAG 1.4.11) on every
// ground a control sits on: `lamp` in the light theme, `lamp-line` in the dark one.
Deno.test("contrast: the focus ring clears 3:1 on every ground, in both themes", () => {
  assertEquals(tokens.focus.color, { light: "lamp", dark: "lamp-line" });
  const grounds = ["paper", "surface", "fog", "lamp-fill", "flare-fill", "open-fill"];
  for (const theme of ["light", "dark"] as const) {
    for (const bg of grounds) {
      const value = ratio(tokens.focus.color[theme], bg, theme);
      assert(value >= 3, `focus ring on ${bg} (${theme}) is ${value.toFixed(2)}:1`);
    }
  }
  // The call screen's ground is the same in both themes: the ring there is lamp-line.
  assert(ratio("lamp-line", "video-ground", "light") >= 3);
  assert(ratio("lamp-line", "video-ground", "dark") >= 3);
});

Deno.test("contrast: open is never text on open-fill (4.37:1 in light)", () => {
  // The components put ink on open-fill; this pins why.
  assert(ratio("open", "open-fill", "light") < 4.5);
  assert(ratio("ink", "open-fill", "light") >= 4.5);
});

Deno.test("tokens.css is what gen-tokens.ts writes from tokens.json", async () => {
  const committed = await Deno.readTextFile(
    new URL("../../src/design/tokens.css", import.meta.url),
  );
  assertEquals(committed, tokensToCss(tokens), "run `denext task tokens`");
});

Deno.test("tokens: the decided values", () => {
  assertEquals(
    tokens.color.paper,
    { light: "#F3F5F4", dark: "#0F181D", use: "Page ground" } as never,
  );
  assertEquals(tokens.radius, { control: 10, bubble: 14, "bubble-tail": 4, panel: 12, full: 9999 });
  assertEquals(tokens.focus, {
    width: 3,
    offset: 2,
    color: { light: "lamp", dark: "lamp-line" },
  });
  assertEquals(tokens.target.min, 44);
  assertEquals(tokens.motion, { "fill-stagger": 350, "fill-duration": 450 });
});
