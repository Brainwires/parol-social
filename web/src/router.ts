// Routing lives in the URL hash, so the static host needs no rewrite rules and the document
// URL (which every asset URL is resolved against) never changes.
//   #/            the conversation list
//   #/c/<peerId>  a conversation
//   #/lab         the state lab (development)
import { type ReadonlySignal, signal } from "denext/signals";

export type Route =
  | { name: "list" }
  | { name: "conversation"; peerId: string }
  | { name: "lab" };

export function parseRoute(hash: string): Route {
  const path = hash.replace(/^#/, "");
  const conversation = /^\/c\/([0-9a-f]{1,64})$/i.exec(path);
  if (conversation) return { name: "conversation", peerId: conversation[1].toLowerCase() };
  if (path === "/lab") return { name: "lab" };
  return { name: "list" };
}

export function hrefOf(route: Route): string {
  switch (route.name) {
    case "conversation":
      return `#/c/${route.peerId}`;
    case "lab":
      return "#/lab";
    case "list":
      return "#/";
  }
}

const current = signal<Route>(
  parseRoute(typeof location === "undefined" ? "" : location.hash),
);

export const route: ReadonlySignal<Route> = current;

export function startRouter(): void {
  addEventListener("hashchange", () => {
    current.value = parseRoute(location.hash);
  });
}

export function navigate(to: Route): void {
  location.hash = hrefOf(to);
}
