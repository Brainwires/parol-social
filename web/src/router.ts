// Routing lives in the URL hash, so the static host needs no rewrite rules and the document
// URL (which every asset URL is resolved against) never changes.
//   #/            the conversation list
//   #/c/<peerId>  a conversation
//   #/add         add a contact (your code, scan or paste theirs)
//   #/settings    settings
//
// Development and test builds only (src/main.dev.tsx): everything under #/lab runs on made-up
// state, without the engine.
//   #/lab         the state lab
//   #/lab/…       the same screens as above, on the lab's fake store
import { type ReadonlySignal, signal } from "denext/signals";

export type Route =
  | { name: "list" }
  | { name: "conversation"; peerId: string }
  | { name: "add" }
  | { name: "settings" }
  | { name: "lab" };

const LAB = "/lab";

/** True for a hash inside the lab's namespace (`#/lab` and everything under it). */
export function isLabHash(hash: string): boolean {
  const path = hash.replace(/^#/, "");
  return path === LAB || path.startsWith(LAB + "/");
}

export function parseRoute(hash: string): Route {
  let path = hash.replace(/^#/, "");
  if (path === LAB) return { name: "lab" };
  if (path.startsWith(LAB + "/")) path = path.slice(LAB.length);
  const conversation = /^\/c\/([0-9a-f]{1,64})$/i.exec(path);
  if (conversation) return { name: "conversation", peerId: conversation[1].toLowerCase() };
  if (path === "/add") return { name: "add" };
  if (path === "/settings") return { name: "settings" };
  return { name: "list" };
}

/** Set once at start when the page runs on the lab's fake store: links stay under #/lab. */
let prefix = "";

export function hrefOf(route: Route): string {
  switch (route.name) {
    case "conversation":
      return `#${prefix}/c/${route.peerId}`;
    case "add":
      return `#${prefix}/add`;
    case "settings":
      return `#${prefix}/settings`;
    case "lab":
      return `#${LAB}`;
    case "list":
      return `#${prefix}/`;
  }
}

const current = signal<Route>(
  parseRoute(typeof location === "undefined" ? "" : location.hash),
);

export const route: ReadonlySignal<Route> = current;

export interface RouterOptions {
  /** The page runs on the lab's fake store: every link stays inside #/lab. */
  lab?: boolean;
  /** Called when the hash crosses between the lab and the real app (the page reloads). */
  onBoundary?: () => void;
}

export function startRouter(options: RouterOptions = {}): void {
  prefix = options.lab ? LAB : "";
  current.value = parseRoute(location.hash);
  addEventListener("hashchange", () => {
    if (options.onBoundary && isLabHash(location.hash) !== (options.lab === true)) {
      options.onBoundary();
      return;
    }
    current.value = parseRoute(location.hash);
  });
}

export function navigate(to: Route): void {
  location.hash = hrefOf(to);
}
