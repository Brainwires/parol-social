// Line icons, drawn on a 24px grid with the current text colour. Decorative: the control
// that holds one carries the accessible name.

const PATHS = {
  phone:
    "M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2",
  video: "M3 7h11a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H3zM16 10.5l5-3v9l-5-3",
  back: "M15 5l-7 7 7 7",
  send: "M12 19V5M5 12l7-7 7 7",
  plus: "M12 5v14M5 12h14",
  close: "M6 6l12 12M18 6L6 18",
  file: "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5",
} as const;

export type IconName = keyof typeof PATHS;

/** Icons that point along the reading direction and flip in right-to-left layouts. */
const DIRECTIONAL: ReadonlySet<IconName> = new Set(["back"]);

export function Icon({ name }: { name: IconName }) {
  return (
    <svg
      className={DIRECTIONAL.has(name) ? "icon icon--directional" : "icon"}
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
