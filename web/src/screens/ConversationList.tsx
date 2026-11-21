// One list for people and groups: who is online now first, then who is away. A row carries
// an amber "{n} waiting" chip while messages for that contact are still on this device.
import { useState } from "denext";
import { Button } from "../components/Button.tsx";
import { CodeBlock } from "../components/Codes.tsx";
import { ConversationRow, SectionHeader } from "../components/ConversationRow.tsx";
import { Line } from "../components/Line.tsx";
import { Panel } from "../components/Panel.tsx";
import { Sheet } from "../components/Sheet.tsx";
import { showToast } from "../components/Toast.tsx";
import { t } from "../i18n/index.ts";
import { applyUpdate, updateReady } from "../platform/service-worker.ts";
import { wasmStatus } from "../platform/wasm.ts";
import { hrefOf, navigate, type Route } from "../router.ts";
import { useStore } from "../state/context.ts";
import { type ChatMessage, type Contact, isOnline } from "../state/model.ts";
import { messagesOf, waitingCount } from "../state/store.ts";

/** A stand-in until pairing is ported: the real code comes from this device's identity. */
const FAKE_OWN_CODE = "7K4MQ2ZD9XTBH6RP";

export function previewOf(last: ChatMessage | undefined): string {
  if (!last) return t("list.preview.none");
  const text = last.body.kind === "text"
    ? last.body.text
    : last.body.kind === "file"
    ? t("list.preview.file", { name: last.body.name })
    : t(last.body.media === "video" ? "message.videoInvite" : "message.voiceInvite");
  return last.direction === "Sent" ? t("list.preview.you", { text }) : text;
}

function AddContactSheet({ onClose }: { onClose: () => void }) {
  const store = useStore();
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [problem, setProblem] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(FAKE_OWN_CODE);
      showToast(t("toast.codeCopied"));
    } catch {
      showToast(t("sheet.add.copyFailed"));
    }
  };

  const submit = (event: { preventDefault(): void }) => {
    event.preventDefault();
    if (!name.trim() || !code.trim()) {
      setProblem(true);
      return;
    }
    const contact = store.addContact(name.trim(), code.trim());
    onClose();
    showToast(t("toast.contactAdded", { name: contact.name }));
    navigate({ name: "conversation", peerId: contact.peerId });
  };

  return (
    <Sheet title={t("sheet.add.title")} testId="sheet-add" onClose={onClose}>
      <div className="field">
        <span className="field__label">{t("sheet.add.yourCode")}</span>
        <CodeBlock code={FAKE_OWN_CODE} label={t("code.label")} testId="own-code" />
        <span className="field__help">{t("sheet.add.yourCodeHelp")}</span>
      </div>
      <Button testId="own-code-copy" onClick={copy}>{t("sheet.add.copy")}</Button>
      <form className="sheet__form" onSubmit={submit} noValidate>
        <label className="field">
          <span className="field__label">{t("sheet.add.theirName")}</span>
          <input
            className="field__input"
            value={name}
            autoComplete="off"
            data-testid="add-name"
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">{t("sheet.add.theirCode")}</span>
          <input
            className="field__input field__input--code"
            value={code}
            autoComplete="off"
            autoCapitalize="characters"
            spellcheck={false}
            dir="ltr"
            data-testid="add-code"
            onInput={(e) => setCode(e.currentTarget.value)}
          />
        </label>
        <p className="field__problem" role="alert" data-testid="add-problem">
          {problem ? t("sheet.add.needBoth") : ""}
        </p>
        <Button variant="primary" type="submit" testId="add-submit" block>
          {t("sheet.add.submit")}
        </Button>
      </form>
    </Sheet>
  );
}

/** Reserved height in every state, so the list does not move when encryption is ready. */
function DeviceStatus() {
  const status = wasmStatus.value;
  let text: string;
  if (status.state === "ready") text = `${t("device.ready")} · ${status.version}`;
  else if (status.state === "failed") text = t("device.failed");
  else {
    const percent = status.state === "loading" && status.total > 0
      ? Math.floor((status.loaded / status.total) * 100)
      : 0;
    text = t("device.loading", { percent });
  }
  return (
    <p
      className={`device-status device-status--${status.state}`}
      role="status"
      data-testid="device-status"
      data-state={status.state}
    >
      {text}
    </p>
  );
}

export function ConversationList({ current }: { current: Route }) {
  const store = useStore();
  const [adding, setAdding] = useState(false);
  const contacts = store.contacts.value;
  const online = contacts.filter((c) => isOnline(c.path));
  const away = contacts.filter((c) => !isOnline(c.path));
  const selfOnline = store.selfOnline.value;

  const row = (contact: Contact) => {
    const messages = messagesOf(store, contact.peerId);
    return (
      <li key={contact.peerId}>
        <ConversationRow
          contact={contact}
          preview={previewOf(messages[messages.length - 1])}
          waiting={waitingCount(messages)}
          href={hrefOf({ name: "conversation", peerId: contact.peerId })}
          current={current.name === "conversation" && current.peerId === contact.peerId}
        />
      </li>
    );
  };

  return (
    <div className="list" data-testid="conversation-list">
      <header className="list__header">
        <h1 className="list__title">{t("list.title")}</h1>
        {contacts.length > 0 && (
          <Button
            variant="primary"
            testId="add-contact"
            onClick={() => setAdding(true)}
          >
            {t("list.addContact")}
          </Button>
        )}
      </header>
      {!selfOnline && (
        <div className="list__line">
          <Line state="self-offline" name="" testId="list-line" />
        </div>
      )}
      {updateReady.value && (
        <div className="list__notice">
          <Panel
            tone="plain"
            testId="update-ready"
            title={t("update.title")}
            actions={[{
              label: t("update.reload"),
              testId: "update-reload",
              primary: true,
              onClick: applyUpdate,
            }]}
          >
            {t("update.body")}
          </Panel>
        </div>
      )}
      <nav className="list__scroll" aria-label={t("list.title")}>
        {contacts.length === 0 && (
          <div className="list__empty" data-testid="list-empty">
            <h2 className="list__empty-title">{t("list.empty.title")}</h2>
            <p>{t("list.empty.body")}</p>
            <Button variant="primary" testId="add-contact" onClick={() => setAdding(true)}>
              {t("list.addContact")}
            </Button>
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
      <footer className="list__footer">
        <DeviceStatus />
      </footer>
      {adding && <AddContactSheet onClose={() => setAdding(false)} />}
    </div>
  );
}
