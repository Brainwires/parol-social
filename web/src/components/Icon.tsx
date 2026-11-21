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
  settings:
    "M4 7h9M17 7h3M4 17h3M11 17h9M13 4.5v5M17 4.5v5M13 4.5h4M13 9.5h4M7 14.5v5M11 14.5v5M7 14.5h4M7 19.5h4",
  mic:
    "M12 3a3 3 0 0 0-3 3v5a3 3 0 0 0 6 0V6a3 3 0 0 0-3-3M5.5 11a6.5 6.5 0 0 0 13 0M12 17.5V21M9 21h6",
  "mic-off":
    "M15 9.5V6a3 3 0 0 0-5.7-1.3M9 9v2a3 3 0 0 0 4.6 2.5M5.5 11a6.5 6.5 0 0 0 10.6 5M18.5 11a6.4 6.4 0 0 1-.6 2.7M12 17.5V21M9 21h6M4 4l16 16",
  "video-off":
    "M10.5 7H14a2 2 0 0 1 2 2v3.5M16 15a2 2 0 0 1-2 2H3V7h3M16 10.5l5-3v9l-2-1.2M4 4l16 16",
  flip: "M4 9a8 8 0 0 1 14-3.5L20 8M20 3.5V8h-4.5M20 15a8 8 0 0 1-14 3.5L4 16M4 20.5V16h4.5",
  speaker: "M4 9.5v5h3.5L12 18.5v-13L7.5 9.5zM15.5 9a4.5 4.5 0 0 1 0 6M18 6.5a8 8 0 0 1 0 11",
  hangup:
    "M3.5 14.5a13 13 0 0 1 17 0l-.6 2.6a1.5 1.5 0 0 1-1.8 1.1l-2.6-.7v-3a11 11 0 0 0-7 0v3l-2.6.7a1.5 1.5 0 0 1-1.8-1.1z",
  copy: "M9 9h10v11H9zM15 9V4H5v11h4",
  share: "M12 15V3.5M7.5 8L12 3.5 16.5 8M5 12.5V20h14v-7.5",
  scan: "M4 8.5V4h4.5M15.5 4H20v4.5M20 15.5V20h-4.5M8.5 20H4v-4.5M4 12h16",
  check: "M5 12.5l4.5 4.5L19 7.5",
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
