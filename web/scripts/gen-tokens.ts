// Writes src/design/tokens.css from src/design/tokens.json (the single source of the design
// tokens; the GPUI desktop app reads the same JSON). Run: `denext task tokens`.
// tests/unit/tokens.test.ts fails when the committed CSS is not what this produces.

interface ColorToken {
  light: string;
  dark: string;
}

export interface Tokens {
  color: Record<string, ColorToken>;
  font: { text: string[]; mono: string[]; weight: Record<string, number> };
  type: { ratio: number; size: Record<string, number>; line: Record<string, number> };
  space: Record<string, number>;
  radius: Record<string, number>;
  border: Record<string, number>;
  /** `color` names a colour token per theme: the ring must clear 3:1 on every ground. */
  focus: { width: number; offset: number; color: { light: string; dark: string } };
  target: { min: number };
  layout: Record<string, number>;
  motion: Record<string, number>;
}

const GENERIC = new Set(["system-ui", "sans-serif", "serif", "monospace", "ui-monospace"]);

function family(names: string[]): string {
  return names.map((n) => (GENERIC.has(n) ? n : `"${n}"`)).join(", ");
}

/** Font sizes follow the reader's browser setting: pixels become rem (16px = 1rem). */
function rem(px: number): string {
  return `${px / 16}rem`;
}

function block(selector: string, lines: string[], indent = "  "): string {
  return `${indent}${selector} {\n${lines.map((l) => `${indent}  ${l}`).join("\n")}\n${indent}}`;
}

export function tokensToCss(tokens: Tokens): string {
  const light = Object.entries(tokens.color).map(([name, c]) => `--${name}: ${c.light};`);
  const dark = [
    ...Object.entries(tokens.color).map(([name, c]) => `--${name}: ${c.dark};`),
    `--focus-color: var(--${tokens.focus.color.dark});`,
  ];
  const rest = [
    `--font-text: ${family(tokens.font.text)};`,
    `--font-mono: ${family(tokens.font.mono)};`,
    ...Object.entries(tokens.font.weight).map(([k, v]) => `--weight-${k}: ${v};`),
    ...Object.entries(tokens.type.size).map(([k, v]) => `--text-${k}: ${rem(v)};`),
    ...Object.entries(tokens.type.line).map(([k, v]) => `--line-${k}: ${v};`),
    ...Object.entries(tokens.space).map(([k, v]) => `--space-${k}: ${v}px;`),
    ...Object.entries(tokens.radius).map(([k, v]) => `--radius-${k}: ${v}px;`),
    ...Object.entries(tokens.border).map(([k, v]) => `--border-${k}: ${v}px;`),
    `--focus-width: ${tokens.focus.width}px;`,
    `--focus-offset: ${tokens.focus.offset}px;`,
    `--focus-color: var(--${tokens.focus.color.light});`,
    `--target-min: ${tokens.target.min}px;`,
    ...Object.entries(tokens.layout).map(([k, v]) => `--layout-${k}: ${v}px;`),
    ...Object.entries(tokens.motion).map(([k, v]) => `--motion-${k}: ${v}ms;`),
  ];
  return [
    "/* Generated from tokens.json by scripts/gen-tokens.ts. Do not edit. */",
    "@layer reset, tokens, base, components, screens;",
    "@layer tokens {",
    block(":root", ["color-scheme: light dark;", ...light, ...rest]),
    "  @media (prefers-color-scheme: dark) {",
    block(':root:not([data-theme="light"])', dark, "    "),
    "  }",
    block(':root[data-theme="light"]', ["color-scheme: light;"]),
    block(':root[data-theme="dark"]', ["color-scheme: dark;", ...dark]),
    "}",
    "",
  ].join("\n");
}

if (import.meta.main) {
  const dir = new URL("../src/design/", import.meta.url);
  const tokens = JSON.parse(await Deno.readTextFile(new URL("tokens.json", dir))) as Tokens;
  await Deno.writeTextFile(new URL("tokens.css", dir), tokensToCss(tokens));
  console.log("wrote src/design/tokens.css");
}
