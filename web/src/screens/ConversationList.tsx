// The conversation list: who is online now first, then who is away, each by last activity.
// A row carries an amber "{n} waiting" chip while messages for that contact are still on this
// device, and a count of what arrived and has not been read.
import { ConversationRow, SectionHeader } from "../components/ConversationRow.tsx";
import { Icon } from "../components/Icon.tsx";
import { Line } from "../components/Line.tsx";
import { Panel } from "../components/Panel.tsx";
import { UpdateNotice } from "../components/UpdateNotice.tsx";
import { t } from "../i18n/index.ts";
import { dismissInstall, install, installAvailable } from "../platform/install.ts";
import { updateReady } from "../platform/service-worker.ts";
import { hrefOf, navigate, type Route } from "../router.ts";
import { useStore } from "../state/context.ts";
import { type ChatMessage, type ContactView, isOnline, sortContacts } from "../state/model.ts";
import { messagesOf } from "../state/store.ts";

export function previewOf(last: ChatMessage | undefined): string {
  if (!last) return t("list.preview.none");
  const attachment = last.attachment;
  const text = !attachment
    ? last.text
    : attachment.kind === "file"
    ? t("list.preview.file", { name: attachment.name })
    : t(attachment.media === "video" ? "message.videoInvite" : "message.voiceInvite");
  return last.direction === "Sent" ? t("list.preview.you", { text }) : text;
}

/** What the app has to say on its own: storage failed, or the person's relay server did. */
function NoticePanel() {
  const store = useStore();
  const notice = store.notice.value;
  if (!notice) return null;
  if (notice.code === "TurnUnusable") {
    return (
      <div className="list__notice">
        <Panel
          tone="amber"
          testId="notice-turn"
          title={t("notice.turn.title")}
          actions={[
            {
              label: t("action.openSettings"),
              testId: "notice-settings",
              primary: true,
              onClick: () => {
                store.dismissNotice();
                navigate({ name: "settings" });
              },
            },
            { label: t("action.dismiss"), testId: "notice-dismiss", onClick: store.dismissNotice },
          ]}
        >
          {t("notice.turn.body")}
        </Panel>
      </div>
    );
  }
  return (
    <div className="list__notice">
      <Panel
        tone="red"
        testId="notice-storage"
        title={t("notice.storage.title")}
        actions={[
          { label: t("action.dismiss"), testId: "notice-dismiss", onClick: store.dismissNotice },
        ]}
      >
        {t("notice.storage.body")}
      </Panel>
    </div>
  );
}

export function ConversationList({ current }: { current: Route }) {
  const store = useStore();
  const contacts = sortContacts(store.contacts.value);
  const online = contacts.filter((c) => isOnline(c.path));
  const away = contacts.filter((c) => !isOnline(c.path));
  const selfOnline = store.selfOnline.value;

  const row = (view: ContactView) => {
    const peerId = view.contact.peerId;
    const messages = messagesOf(store, peerId);
    return (
      <li key={peerId} data-testid="contact-item" data-peer-id={peerId}>
        <ConversationRow
          view={view}
          preview={previewOf(messages[messages.length - 1])}
          href={hrefOf({ name: "conversation", peerId })}
          current={current.name === "conversation" && current.peerId === peerId}
        />
      </li>
    );
  };

  return (
    <div className="list" data-testid="conversation-list">
      <header className="list__header">
        <h1 className="list__title" tabIndex={-1} data-testid="list-title">{t("list.title")}</h1>
        <div className="list__actions">
          {contacts.length > 0 && (
            <a
              className="icon-btn icon-btn--filled"
              href={hrefOf({ name: "add" })}
              aria-label={t("list.addContact")}
              title={t("list.addContact")}
              aria-current={current.name === "add" ? "page" : undefined}
              data-testid="add-contact"
            >
              <Icon name="plus" />
            </a>
          )}
          <a
            className="icon-btn"
            href={hrefOf({ name: "settings" })}
            aria-label={t("list.settings")}
            title={t("list.settings")}
            aria-current={current.name === "settings" ? "page" : undefined}
            data-testid="open-settings"
          >
            <Icon name="settings" />
          </a>
        </div>
      </header>
      {!selfOnline && (
        <div className="list__line">
          <Line state="self-offline" name="" testId="list-line" />
        </div>
      )}
      <NoticePanel />
      {updateReady.value && (
        <div className="list__notice">
          <UpdateNotice />
        </div>
      )}
      <nav className="list__scroll" aria-label={t("list.title")}>
        {contacts.length === 0 && (
          <div className="list__empty" data-testid="list-empty">
            <h2 className="list__empty-title">{t("list.empty.title")}</h2>
            <p>{t("list.empty.body")}</p>
            <a
              className="btn btn--primary"
              href={hrefOf({ name: "add" })}
              data-testid="add-contact"
            >
              {t("list.addContact")}
            </a>
          </div>
        )}
        {online.length > 0 && (
          <section>
            <SectionHeader>{t("list.online")}</SectionHeader>
            <ul data-testid="section-online">{online.map(row)}</ul>
          </section>
        )}
        {away.length > 0 && (
          <section>
            <SectionHeader>{t("list.away")}</SectionHeader>
            <ul data-testid="section-away">{away.map(row)}</ul>
          </section>
        )}
      </nav>
      {installAvailable.value && contacts.length > 0 && (
        <footer className="list__footer" data-testid="install-hint">
          <p className="list__hint">{t("install.hint")}</p>
          <div className="list__hint-actions">
            <button
              type="button"
              className="btn btn--quiet"
              data-testid="install-action"
              onClick={() =>
                void install()}
            >
              {t("install.action")}
            </button>
            <button
              type="button"
              className="btn btn--quiet"
              data-testid="install-later"
              onClick={dismissInstall}
            >
              {t("install.later")}
            </button>
          </div>
        </footer>
      )}
    </div>
  );
}
