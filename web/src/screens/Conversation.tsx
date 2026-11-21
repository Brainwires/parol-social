// The conversation screen. Its header holds the line: the one status of this conversation.
// Under the thread, a panel appears only when something needs the person (no direct path, a
// failed security check); the composer is always there.
import { useEffect, useId, useRef, useState } from "denext";
import { Bubble, HeldBubble } from "../components/Bubble.tsx";
import { Button, IconButton } from "../components/Button.tsx";
import { Composer } from "../components/Composer.tsx";
import { Avatar } from "../components/ConversationRow.tsx";
import { Icon } from "../components/Icon.tsx";
import { Line } from "../components/Line.tsx";
import { Panel } from "../components/Panel.tsx";
import { Sheet } from "../components/Sheet.tsx";
import { showToast } from "../components/Toast.tsx";
import { type MessageKey, t } from "../i18n/index.ts";
import { hrefOf } from "../router.ts";
import { useStore } from "../state/context.ts";
import { type CallMedia, type Contact, type LineState, lineState } from "../state/model.ts";
import { messagesOf } from "../state/store.ts";
import { type Caption, captionOf, threadItems, useFillSequence } from "./thread.ts";

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

function Thread(
  { contact, onEdit }: { contact: Contact; onEdit: (id: number, text: string) => void },
) {
  const store = useStore();
  const messages = messagesOf(store, contact.peerId);
  const { stillOutlined, animated } = useFillSequence(messages);
  const items = threadItems(messages, stillOutlined);
  const caption = captionOf(items);
  const scroller = useRef<HTMLDivElement>(null);

  // Keep the newest message in view.
  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length]);

  if (items.length === 0) {
    return (
      <div className="thread thread--empty" ref={scroller}>
        <p className="thread__empty">{t("conversation.noMessages", { name: contact.name })}</p>
      </div>
    );
  }

  return (
    <div className="thread" ref={scroller} data-testid="thread">
      <ol className="thread__list">
        {items.map(({ message, kind, groupStart, groupEnd }, index) => {
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
            >
              {actionable
                ? (
                  <HeldBubble
                    body={message.body}
                    tail={tail}
                    testId={testId}
                    onTakeBack={() => {
                      store.takeBack(contact.peerId, message.id);
                      showToast(t("toast.takenBack"));
                    }}
                    onEdit={message.body.kind === "text"
                      ? () =>
                        onEdit(message.id, message.body.kind === "text" ? message.body.text : "")
                      : undefined}
                  />
                )
                : (
                  <Bubble
                    kind={kind}
                    body={message.body}
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
                  {t(CAPTION[caption.caption], { name: contact.name })}
                </p>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export function Conversation({ peerId, showBack = true }: { peerId: string; showBack?: boolean }) {
  const store = useStore();
  const contact = store.contacts.value.find((c) => c.peerId === peerId);
  const [editing, setEditing] = useState<{ id: number; text: string } | null>(null);
  const [sheet, setSheet] = useState<"relay" | "blocked" | null>(null);
  const [callHint, setCallHint] = useState(false);
  const hintId = useId();
  const heading = useRef<HTMLHeadingElement>(null);

  // Stack navigation: arriving on a conversation moves focus to its name.
  useEffect(() => {
    heading.current?.focus();
  }, [peerId]);

  if (!contact) {
    return (
      <div className="conversation conversation--placeholder" data-testid="conversation-missing">
        <p>{t("conversation.missing")}</p>
        <a className="btn btn--quiet" href={hrefOf({ name: "list" })} data-testid="missing-back">
          {t("action.back")}
        </a>
      </div>
    );
  }

  const name = contact.name;
  const line = lineState(contact.path, store.selfOnline.value);
  const blocker = callBlocker(line);
  const call = store.call.value?.peerId === peerId ? store.call.value : null;

  const callButton = (media: CallMedia) => (
    <IconButton
      icon={media === "video" ? "video" : "phone"}
      label={t(media === "video" ? "call.video" : "call.voice", { name })}
      testId={`call-${media}`}
      unavailable={blocker !== null}
      describedBy={blocker && callHint ? hintId : undefined}
      onFocus={() => setCallHint(blocker !== null)}
      onBlur={() => setCallHint(false)}
      onClick={() => {
        if (blocker) setCallHint(true);
        else store.startCall(peerId, media);
      }}
    />
  );

  return (
    <div className="conversation" data-testid="conversation" data-line={line}>
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
        <Avatar contact={contact} />
        <h1
          className="conversation__name"
          tabIndex={-1}
          ref={heading}
          data-testid="conversation-name"
        >
          <bdi>{name}</bdi>
        </h1>
        <Line state={line} name={name} />
        {callButton("voice")}
        {callButton("video")}
      </header>
      {/* Floats under the call buttons, so showing the reason moves nothing. */}
      <p className="hint conversation__hint" id={hintId} role="status" data-testid="call-hint">
        {blocker && callHint ? t(blocker, { name }) : ""}
      </p>
      {call && (
        <div className="conversation__call" data-testid="call-strip">
          <span>{t("call.outgoing", { name })}</span>
          <Button variant="danger" testId="call-end" onClick={() => store.endCall()}>
            {t("call.end")}
          </Button>
        </div>
      )}

      <Thread key={peerId} contact={contact} onEdit={(id, text) => setEditing({ id, text })} />

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
                onClick: () => store.retryPath(peerId),
              },
              {
                label: t("action.useOwnRelay"),
                testId: "panel-own-relay",
                onClick: () => setSheet("relay"),
              },
            ]}
          >
            {t("panel.noPath.body")}
          </Panel>
        </div>
      )}
      {line === "blocked" && (
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
                onClick: () => store.retryPath(peerId),
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

      <Composer
        name={name}
        away={line !== "open"}
        editingText={editing?.text ?? null}
        onSend={(text) => store.send(peerId, text)}
        onSaveEdit={(text) => {
          if (editing) store.edit(peerId, editing.id, text);
          setEditing(null);
          showToast(t("toast.edited"));
        }}
        onCancelEdit={() => setEditing(null)}
      />

      {sheet === "relay" && (
        <Sheet
          title={t("sheet.relay.title")}
          testId="sheet-relay"
          onClose={() => setSheet(null)}
        >
          <p>{t("sheet.relay.body")}</p>
        </Sheet>
      )}
      {sheet === "blocked" && (
        <Sheet
          title={t("sheet.blocked.title")}
          testId="sheet-blocked"
          onClose={() => setSheet(null)}
        >
          <p>{t("sheet.blocked.body1")}</p>
          <p>{t("sheet.blocked.body2")}</p>
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
