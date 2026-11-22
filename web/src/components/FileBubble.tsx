// A file in the conversation. It has the one form every message has: outlined while it is
// still only on this device (a file we offer, until their device confirms it has all of it),
// filled once it is on theirs. A file they offer us is drawn as a received bubble. Under the
// name and the size, one status line says in words where the file is; a progress bar while
// it moves only repeats those words. Its actions sit under the bubble.
import { useId } from "denext";
import { locale, type MessageKey, t } from "../i18n/index.ts";
import { type TransferInfo, transferOver } from "../state/model.ts";
import { bubbleClass, type BubbleKind, formatBytes } from "./Bubble.tsx";
import { Icon } from "./Icon.tsx";

/** Outlined is here, filled is there; a file that will not get there is dotted. */
export function transferKind(transfer: TransferInfo): BubbleKind {
  const sent = transfer.direction === "Sent";
  if (transferOver(transfer)) {
    if (transfer.state.kind !== "Complete") return "stopped";
    return sent ? "delivered" : "received";
  }
  // Our offer, answer or cancel still waits on this device; a file we send is here until
  // their device has all of it.
  if (transfer.pending || sent) return "held";
  return "received";
}

/** The status line's message (its arguments: `name`, `done`, `total`). */
export function transferStatusKey(transfer: TransferInfo, filesPersist = true): MessageKey {
  const sent = transfer.direction === "Sent";
  const state = transfer.state;
  switch (state.kind) {
    case "Offered":
      if (transfer.pending) return "transfer.status.pending";
      return sent ? "transfer.status.offeredSent" : "transfer.status.offeredReceived";
    case "Waiting":
      return transfer.pending ? "transfer.status.pending" : "transfer.status.waiting";
    case "Active":
      return "transfer.progress";
    case "Complete":
      if (sent) return "transfer.status.sentComplete";
      if (!transfer.available) return "transfer.status.receivedGone";
      return filesPersist
        ? "transfer.status.receivedComplete"
        : "transfer.status.receivedUntilReload";
    case "Declined":
      return sent ? "transfer.status.theyDeclined" : "transfer.status.youDeclined";
    case "Cancelled": {
      const { byPeer, reason } = state;
      switch (reason) {
        case "User":
          return byPeer ? "transfer.status.theyCancelled" : "transfer.status.youCancelled";
        case "Unavailable":
          // A sending page keeps no handle on the file: a reload is what makes it unavailable.
          if (sent && !byPeer) return "transfer.status.reloaded";
          return byPeer ? "transfer.status.unavailableThere" : "transfer.status.unavailableHere";
        case "Integrity":
          return "transfer.status.integrity";
        case "Storage":
          return byPeer ? "transfer.status.storageThere" : "transfer.status.storageHere";
        case "Limit":
          return byPeer ? "transfer.status.limitThere" : "transfer.status.limitHere";
        case "Other":
          return "transfer.status.other";
      }
    }
  }
}

/** The status line in words: "12 MB of 48 MB", "On Mira's device", "You cancelled". */
export function transferStatus(
  transfer: TransferInfo,
  name: string,
  filesPersist = true,
  localeCode: string = locale.value,
): string {
  return t(transferStatusKey(transfer, filesPersist), {
    name,
    done: formatBytes(transfer.bytesDone, localeCode),
    total: formatBytes(transfer.size, localeCode),
  });
}

export type TransferAction = "accept" | "decline" | "cancel" | "save" | "remove";

/** What can be done with a transfer now, in the order the buttons appear. */
export function transferActions(transfer: TransferInfo): TransferAction[] {
  const received = transfer.direction === "Received";
  if (received && transfer.state.kind === "Offered") return ["accept", "decline"];
  if (!transferOver(transfer)) return ["cancel"];
  const actions: TransferAction[] = [];
  if (received && transfer.state.kind === "Complete" && transfer.available) actions.push("save");
  actions.push("remove");
  return actions;
}

const ACTION_WORDS: Record<TransferAction, MessageKey> = {
  accept: "transfer.accept",
  decline: "transfer.decline",
  cancel: "transfer.cancel",
  save: "transfer.save",
  remove: "transfer.remove",
};

export function FileBubble({ transfer, name, filesPersist = true, tail = null, onAction }: {
  transfer: TransferInfo;
  /** The contact's name, for the status line. */
  name: string;
  /** Received files survive a reload of this page. */
  filesPersist?: boolean;
  tail?: "start" | "end" | null;
  onAction: (action: TransferAction) => void;
}) {
  const nameId = useId();
  const kind = transferKind(transfer);
  const actions = transferActions(transfer);
  const active = transfer.state.kind === "Active";
  return (
    <div
      className={`transfer transfer--${transfer.direction === "Sent" ? "sent" : "received"}`}
      data-testid="transfer-bubble"
      data-transfer-id={transfer.id}
      data-direction={transfer.direction === "Sent" ? "sent" : "received"}
      data-state={transfer.state.kind.toLowerCase()}
      data-pending={transfer.pending ? "true" : "false"}
      data-kind={kind}
    >
      <div className={`${bubbleClass(kind, tail)} bubble--file`} data-kind={kind}>
        <span className="bubble__attachment">
          <Icon name="file" />
          <span className="transfer__body">
            {/* The engine made the name safe; it is still only ever text. */}
            <bdi className="transfer__name" id={nameId} data-testid="transfer-name">
              {transfer.name}
            </bdi>
            <span className="bubble__meta">{formatBytes(transfer.size, locale.value)}</span>
            {active && (
              <progress
                className="transfer__progress"
                max={Math.max(transfer.size, 1)}
                value={Math.min(transfer.bytesDone, transfer.size)}
                aria-label={t("transfer.progressLabel", { name: transfer.name })}
              />
            )}
            <span className="transfer__status" data-testid="transfer-status">
              {transferStatus(transfer, name, filesPersist)}
            </span>
          </span>
        </span>
      </div>
      {actions.length > 0 && (
        <div className="transfer__actions">
          {actions.map((action) => (
            <TransferButton
              key={action}
              action={action}
              describedBy={nameId}
              onClick={() => onAction(action)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function TransferButton({ action, describedBy, onClick }: {
  action: TransferAction;
  describedBy: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`btn btn--${action === "accept" ? "primary" : "quiet"} transfer__action`}
      // The visible word is the name; the file's name says which file it acts on.
      aria-describedby={describedBy}
      data-testid={`transfer-${action}`}
      onClick={onClick}
    >
      {t(ACTION_WORDS[action])}
    </button>
  );
}
