// The conversation screen. Its header holds the line: the one status of this conversation.
// Under the thread, a panel appears only when something needs the person (no direct path, a
// failed security check); the composer is always there.
import { useEffect, useId, useRef, useState } from "denext";
import { Bubble, HeldBubble } from "../components/Bubble.tsx";
import { IconButton } from "../components/Button.tsx";
import { Composer, type ComposerState } from "../components/Composer.tsx";
import { FileBubble, type TransferAction } from "../components/FileBubble.tsx";
import { Avatar } from "../components/ConversationRow.tsx";
import { Icon } from "../components/Icon.tsx";
import { Line } from "../components/Line.tsx";
import { Panel } from "../components/Panel.tsx";
import { Sheet } from "../components/Sheet.tsx";
import { showToast } from "../components/Toast.tsx";
import { type MessageKey, t } from "../i18n/index.ts";
import { hrefOf, navigate } from "../router.ts";
import { useStore } from "../state/context.ts";
import {
  type ContactView,
  isVerified,
  type LineState,
  lineState,
  type TransferInfo,
} from "../state/model.ts";
import { asksForName, shownName } from "../state/names.ts";
import { type AppStore, contactOf, messagesOf, transfersOf } from "../state/store.ts";
import { ContactDetailsSheet, RemoveContactSheet, VerifySheet } from "./ContactSheets.tsx";
import { errorText } from "./errors.ts";
import { NamePrompt } from "./NamePrompt.tsx";
import { type Caption, timelineCaption, timelineItems, useFillSequence } from "./thread.ts";

const CAPTION: Record<Caption, MessageKey> = {
  waiting: "caption.waiting",
  delivered: "caption.delivered",
  dropped: "caption.dropped",
};

/** Why calls are unavailable on this line, or null when they are available. */
function callBlocker(line: LineState): MessageKey | null {
  switch (line) {
    case "open":
      return null;
    case "self-offline":
      return "call.needsSelf";
    case "no-path":
    case "blocked":
      return "call.needsLine";
    case "waiting":
    case "connecting":
      return "call.needsOnline";
  }
}

/** What the composer's placeholder promises on this line. */
function composerState(line: LineState): ComposerState {
  if (line === "open") return "open";
  // "{name} is away" is only true while we wait for them to come online.
  return line === "waiting" ? "away" : "no-path";
}

/** Run what a file bubble's button asks for. */
export function runTransferAction(
  store: AppStore,
  transfer: TransferInfo,
  action: TransferAction,
): Promise<void> {
  switch (action) {
    case "accept":
      return store.acceptTransfer(transfer.id);
    case "decline":
      return store.declineTransfer(transfer.id);
    case "cancel":
      return store.cancelTransfer(transfer.id);
    case "save":
      return store.saveTransfer(transfer.id);
    case "remove":
      return store.removeTransfer(transfer.id);
  }
}

function Thread({ view, onEdit, onProblem }: {
  view: ContactView;
  onEdit: (id: number, text: string) => void;
  onProblem: (error: unknown) => void;
}) {
  const store = useStore();
  const { contact } = view;
  const messages = messagesOf(store, contact.peerId);
  const transfers = transfersOf(store, contact.peerId);
  const { stillOutlined, animated } = useFillSequence(messages);
  const items = timelineItems(messages, transfers, stillOutlined);
  const caption = timelineCaption(items);
  const scroller = useRef<HTMLDivElement>(null);

  // Keep the newest message in view.
  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [items.length]);

  if (items.length === 0) {
    return (
      <div className="thread thread--empty" ref={scroller}>
        <p className="thread__empty">
          {t("conversation.noMessages", { name: shownName(contact) })}
        </p>
      </div>
    );
  }

  return (
    <div className="thread" ref={scroller} data-testid="thread">
      <ol className="thread__list">
        {items.map(({ entry, kind, groupStart, groupEnd }, index) => {
          if (entry.type === "transfer") {
            const transfer = entry.transfer;
            const sent = transfer.direction === "Sent";
            return (
              <li
                key={`t:${transfer.id}`}
                className={`thread__item thread__item--${sent ? "sent" : "received"}${
                  groupStart ? " thread__item--group-start" : ""
                }`}
                data-testid="transfer-item"
                data-direction={sent ? "sent" : "received"}
              >
                <FileBubble
                  transfer={transfer}
                  name={shownName(contact)}
                  filesPersist={store.filesPersist.value}
                  tail={groupEnd ? (sent ? "end" : "start") : null}
                  onAction={(action) => {
                    runTransferAction(store, transfer, action).catch(onProblem);
                  }}
                />
              </li>
            );
          }
          const message = entry.message;
          const sent = message.direction === "Sent";
          const tail = groupEnd ? (sent ? "end" : "start") : null;
          const testId = `bubble-${message.id}`;
          // Only a message that is really still here has actions; one that is delivered and
          // merely waiting for its turn in the fill animation does not.
          const actionable = kind === "held" && message.state === "Queued";
          return (
            <li
              key={message.id}
              className={`thread__item thread__item--${sent ? "sent" : "received"}${
                groupStart ? " thread__item--group-start" : ""
              }`}
              data-testid="message-item"
              data-direction={sent ? "sent" : "received"}
            >
              {actionable
                ? (
                  <HeldBubble
                    content={message}
                    tail={tail}
                    testId={testId}
                    onTakeBack={() => {
                      store.takeBack(message.id).then(
                        () => showToast(t("toast.takenBack")),
                        onProblem,
                      );
                    }}
                    onEdit={message.attachment ? undefined : () => onEdit(message.id, message.text)}
                  />
                )
                : (
                  <Bubble
                    kind={kind}
                    content={message}
                    tail={tail}
                    fill={animated.has(message.id)}
                    testId={testId}
                  />
                )}
              {caption?.after === index && (
                <p
                  className={`thread__caption thread__caption--${caption.caption}`}
                  data-testid="thread-caption"
                  data-caption={caption.caption}
                >
                  {t(CAPTION[caption.caption], { name: shownName(contact) })}
                </p>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

type OpenSheet = "details" | "verify" | "remove" | "blocked" | null;

export function Conversation({ peerId, showBack = true }: { peerId: string; showBack?: boolean }) {
  const store = useStore();
  const view = contactOf(store, peerId);
  const [editing, setEditing] = useState<{ id: number; text: string } | null>(null);
  const [sheet, setSheet] = useState<OpenSheet>(null);
  const [callHint, setCallHint] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [preparing, setPreparing] = useState<string[]>([]);
  const [dropping, setDropping] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const offerRef = useRef<(files: readonly File[]) => void>(() => {});
  const hintId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const known = view !== undefined;
  const unread = view?.unread ?? 0;

  // Stack navigation: arriving on a conversation moves focus to its name, and asks for the
  // direct path now.
  useEffect(() => {
    heading.current?.focus();
    if (known) store.connect(peerId);
  }, [peerId, known]);

  // Dropping files on the conversation offers them, as the attach button does (the button is
  // the way that works for everyone; this is a shortcut for a pointer).
  useEffect(() => {
    const el = root.current;
    if (!el?.addEventListener) return;
    const carriesFiles = (event: DragEvent) => event.dataTransfer?.types.includes("Files") ?? false;
    const over = (event: DragEvent) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
      setDropping(true);
    };
    const leave = (event: DragEvent) => {
      const to = event.relatedTarget as Node | null;
      if (!to || !el.contains(to)) setDropping(false);
    };
    const drop = (event: DragEvent) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      setDropping(false);
      offerRef.current([...(event.dataTransfer?.files ?? [])]);
    };
    el.addEventListener("dragover", over);
    el.addEventListener("dragleave", leave);
    el.addEventListener("drop", drop);
    return () => {
      el.removeEventListener("dragover", over);
      el.removeEventListener("dragleave", leave);
      el.removeEventListener("drop", drop);
    };
  }, [known]);

  // What is on screen has been read, as long as the person can see it.
  useEffect(() => {
    const read = () => {
      if (unread > 0 && document.visibilityState === "visible") store.markRead(peerId);
    };
    read();
    document.addEventListener("visibilitychange", read);
    return () => document.removeEventListener("visibilitychange", read);
  }, [peerId, unread]);

  if (!view) {
    return (
      <div className="conversation conversation--placeholder" data-testid="conversation-missing">
        <p>{t("conversation.missing")}</p>
        <a className="btn btn--quiet" href={hrefOf({ name: "list" })} data-testid="missing-back">
          {t("action.back")}
        </a>
      </div>
    );
  }

  const { contact } = view;
  const name = shownName(contact);
  const line = lineState(view.path, store.selfOnline.value);
  const blocker = callBlocker(line);
  const fail = (error: unknown) => setProblem(errorText(error, { name }));

  // Each file is read for its hash before it is offered; meanwhile it is "Preparing …" and
  // the composer stays usable.
  const offer = (files: readonly File[]) => {
    for (const file of files) {
      setPreparing((now) => [...now, file.name]);
      store.offerFile(peerId, file).then(
        () => setProblem(null),
        fail,
      ).finally(() =>
        setPreparing((now) => {
          const at = now.indexOf(file.name);
          return at < 0 ? now : [...now.slice(0, at), ...now.slice(at + 1)];
        })
      );
    }
  };

  offerRef.current = offer;

  const callButton = (video: boolean) => (
    <IconButton
      icon={video ? "video" : "phone"}
      label={t(video ? "call.video" : "call.voice", { name })}
      testId={video ? "call-video" : "call-voice"}
      unavailable={blocker !== null}
      describedBy={blocker && callHint ? hintId : undefined}
      onFocus={() => setCallHint(blocker !== null)}
      onBlur={() => setCallHint(false)}
      onClick={() => {
        if (blocker) {
          setCallHint(true);
          return;
        }
        setProblem(null);
        store.startCall(peerId, video).catch(fail);
      }}
    />
  );

  return (
    <div
      className={dropping ? "conversation conversation--dropping" : "conversation"}
      data-testid="conversation"
      data-line={line}
      ref={root}
    >
      <header className="conversation__header">
        {showBack && (
          <a
            className="icon-btn conversation__back"
            href={hrefOf({ name: "list" })}
            aria-label={t("action.back")}
            data-testid="conversation-back"
          >
            <Icon name="back" />
          </a>
        )}
        <button
          type="button"
          className="conversation__avatar"
          aria-label={t("conversation.details", { name })}
          data-testid="conversation-details"
          onClick={() => setSheet("details")}
        >
          <Avatar name={name} />
        </button>
        <h1
          className="conversation__name"
          tabIndex={-1}
          ref={heading}
          data-testid="conversation-name"
        >
          <bdi>{name}</bdi>
        </h1>
        <Line state={line} name={name} />
        {callButton(false)}
        {callButton(true)}
      </header>
      {/* Floats under the call buttons, so showing the reason moves nothing. */}
      <p className="hint conversation__hint" id={hintId} role="status" data-testid="call-hint">
        {blocker && callHint ? t(blocker, { name }) : ""}
      </p>
      {asksForName(contact) && <NamePrompt key={peerId} peerId={peerId} />}
      {contact.restoredMs !== undefined && line !== "blocked" && (
        <p className="conversation__verify" role="note" data-testid="restored-note">
          {t("restored.note", { name })}
        </p>
      )}
      {!isVerified(contact) && (
        <div className="conversation__verify" data-testid="verify-prompt">
          <span>{t("verify.prompt")}</span>
          <button
            type="button"
            className="link-btn"
            data-testid="verify-open"
            onClick={() => setSheet("verify")}
          >
            {t("verify.open")}
          </button>
        </div>
      )}

      <Thread
        key={peerId}
        view={view}
        onEdit={(id, text) => setEditing({ id, text })}
        onProblem={fail}
      />

      {line === "no-path" && (
        <div className="conversation__panel">
          <Panel
            tone="amber"
            testId="panel-no-path"
            title={t("panel.noPath.title")}
            actions={[
              {
                label: t("action.tryAgain"),
                testId: "panel-try-again",
                primary: true,
                onClick: () => store.connect(peerId),
              },
              {
                label: t("action.useOwnRelay"),
                testId: "panel-own-relay",
                onClick: () => navigate({ name: "settings" }),
              },
            ]}
          >
            {t("panel.noPath.body")}
          </Panel>
        </div>
      )}
      {line === "blocked" && contact.restoredMs !== undefined && (
        // The contact came from a backup and the connection failed its check: the backup's
        // session is older than the one their device has. Trying again cannot help.
        <div className="conversation__panel">
          <Panel
            tone="red"
            testId="panel-restored"
            title={t("panel.restored.title", { name })}
            actions={[
              {
                label: t("details.remove"),
                testId: "panel-restored-remove",
                primary: true,
                onClick: () => setSheet("remove"),
              },
            ]}
          >
            {t("panel.restored.body", { name })}
          </Panel>
        </div>
      )}
      {line === "blocked" && contact.restoredMs === undefined && (
        <div className="conversation__panel">
          <Panel
            tone="red"
            testId="panel-blocked"
            title={t("panel.blocked.title")}
            actions={[
              {
                label: t("action.tryAgain"),
                testId: "panel-try-again",
                primary: true,
                onClick: () => store.connect(peerId),
              },
              {
                label: t("action.whatThisMeans"),
                testId: "panel-what-this-means",
                onClick: () => setSheet("blocked"),
              },
            ]}
          >
            {t("panel.blocked.body", { name })}
          </Panel>
        </div>
      )}

      {dropping && (
        <p className="conversation__drop" aria-hidden="true">
          {t("transfer.dropHint", { name })}
        </p>
      )}
      <p className="conversation__problem" role="alert" data-testid="conversation-problem">
        {problem ?? ""}
      </p>
      <Composer
        name={name}
        state={composerState(line)}
        editingText={editing?.text ?? null}
        onSend={async (text) => {
          try {
            await store.send(peerId, text);
            setProblem(null);
          } catch (error) {
            fail(error);
            throw error;
          }
        }}
        onSaveEdit={async (text) => {
          if (!editing) return;
          try {
            await store.edit(editing.id, text);
            setProblem(null);
            showToast(t("toast.edited"));
          } catch (error) {
            // It left this device while it was being edited: nothing to edit any more.
            fail(error);
          }
          setEditing(null);
        }}
        onCancelEdit={() => setEditing(null)}
        onAttach={offer}
        preparing={preparing}
      />

      {sheet === "details" && (
        <ContactDetailsSheet
          view={view}
          onClose={() => setSheet(null)}
          onVerify={() => setSheet("verify")}
          onRemove={() => setSheet("remove")}
        />
      )}
      {sheet === "verify" && (
        <VerifySheet
          view={view}
          onClose={() => setSheet(null)}
          onRemoved={() => navigate({ name: "add" })}
        />
      )}
      {sheet === "remove" && (
        <RemoveContactSheet
          view={view}
          onClose={() => setSheet(null)}
          onRemoved={() => navigate({ name: "list" })}
        />
      )}
      {sheet === "blocked" && (
        <Sheet
          title={t("sheet.blocked.title")}
          testId="sheet-blocked"
          onClose={() => setSheet(null)}
        >
          <p>{t("sheet.blocked.body1")}</p>
          <p>{t("sheet.blocked.body2")}</p>
          <p>{t("sheet.blocked.body3")}</p>
        </Sheet>
      )}
    </div>
  );
}

/** Wide layout, nothing chosen yet. */
export function ConversationPlaceholder() {
  return (
    <div className="conversation conversation--placeholder" data-testid="conversation-placeholder">
      <h1 className="conversation__placeholder-title">{t("conversation.choose")}</h1>
      <p>{t("conversation.chooseBody")}</p>
    </div>
  );
}
