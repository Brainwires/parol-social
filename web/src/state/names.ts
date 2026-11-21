// A contact has no name until the person gives one (the engine stores an empty name), and
// the screens call it "New contact" until then. Naming happens on "Add a contact"; a contact
// that arrived while the person was elsewhere, or was left unnamed, is asked for in its
// conversation instead: once, without blocking anything.
import { signal } from "denext/signals";
import { t } from "../i18n/index.ts";
import type { Contact } from "./model.ts";

/** True until the person names this contact. */
export function isUnnamed(contact: Contact): boolean {
  return contact.name.trim() === "";
}

/** The name to show: the person's own, or "New contact" until they give one. */
export function shownName(contact: Contact): string {
  return isUnnamed(contact) ? t("contact.newName") : contact.name;
}

/** Contacts this device added itself (by scanning or pasting), during this visit. */
const addedHere = new Set<string>();
/** Conversations where the person put the naming prompt away ("Not now"), this visit. */
const dismissed = signal<ReadonlySet<string>>(new Set());

export function rememberAddedHere(peerId: string): void {
  addedHere.add(peerId);
}

/** Whether the contact was added from this device rather than by someone using its code. */
export function wasAddedHere(peerId: string): boolean {
  return addedHere.has(peerId);
}

/** Whether the conversation should ask for a name now. */
export function asksForName(contact: Contact): boolean {
  return isUnnamed(contact) && !dismissed.value.has(contact.peerId);
}

export function dismissNamePrompt(peerId: string): void {
  dismissed.value = new Set([...dismissed.value, peerId]);
}
