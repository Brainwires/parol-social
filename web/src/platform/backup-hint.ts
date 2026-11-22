// "Make a backup" is suggested once there is a contact to lose and no backup was made here.
// "Not now" puts the suggestion away on this device for good; Settings keeps the button.
import { type ReadonlySignal, signal } from "denext/signals";
import { readPref, writePref } from "./prefs.ts";

const dismissed = signal(readPref("backupHintDismissed") === "1");

export const backupHintDismissed: ReadonlySignal<boolean> = dismissed;

export function dismissBackupHint(): void {
  dismissed.value = true;
  writePref("backupHintDismissed", "1");
}
