// The state lab (#/lab): every component in every state, with controls to flip the fake
// store. A development page: it ships with the app but nothing links to it, and its own
// labels are not translated. The stories themselves render through the catalogue, so the
// locale and direction controls exercise them.
import { type ReactNode, useEffect, useState } from "denext";
import { Bubble, type BubbleKind } from "../components/Bubble.tsx";
import { Button, IconButton } from "../components/Button.tsx";
import { CodeBlock, SafetyNumber } from "../components/Codes.tsx";
import { Composer } from "../components/Composer.tsx";
import { ConversationRow, SectionHeader } from "../components/ConversationRow.tsx";
import { Line } from "../components/Line.tsx";
import { Panel } from "../components/Panel.tsx";
import { Sheet } from "../components/Sheet.tsx";
import { showToast } from "../components/Toast.tsx";
import { direction, locale, LOCALES, setDirectionOverride, setLocale, t } from "../i18n/index.ts";
import { setTheme, type ThemeChoice, themeChoice } from "../platform/theme.ts";
import { loadWasm, wasmStatus } from "../platform/wasm.ts";
import { hrefOf } from "../router.ts";
import { useStore } from "../state/context.ts";
import { FAKE_PEERS } from "../state/fake.ts";
import type { LineState, PathState } from "../state/model.ts";
import type { FakeControls } from "../state/store.ts";
import { Conversation } from "./Conversation.tsx";

const LINE_STATES: LineState[] = [
  "open",
  "waiting",
  "connecting",
  "no-path",
  "blocked",
  "self-offline",
];
const PATH_STATES: PathState[] = [
  "Unknown",
  "Offline",
  "Connecting",
  "Direct",
  "NoDirectPath",
  "BindingFailed",
];
const THEMES: ThemeChoice[] = ["system", "light", "dark"];
const NAME = "Tomasz";

function Choice<T extends string>({ label, values, value, onChoose, testId }: {
  label: string;
  values: readonly T[];
  value: T;
  onChoose: (value: T) => void;
  testId: string;
}) {
  return (
    <div className="lab__choice" role="group" aria-label={label}>
      <span className="lab__choice-label">{label}</span>
      {values.map((v) => (
        <button
          key={v}
          type="button"
          className={v === value ? "btn btn--primary" : "btn btn--quiet"}
          aria-pressed={v === value ? "true" : "false"}
          data-testid={`${testId}-${v}`}
          onClick={() => onChoose(v)}
        >
          {v}
        </button>
      ))}
    </div>
  );
}

function Story({ title, id, children }: { title: string; id: string; children: ReactNode }) {
  return (
    <section className="lab__story" data-testid={`story-${id}`} aria-labelledby={`story-${id}`}>
      <h2 className="lab__story-title" id={`story-${id}`}>{title}</h2>
      <div className="lab__story-body">{children}</div>
    </section>
  );
}

/** The wasm proof: two fresh identities and their safety number, computed by the Rust core. */
function WasmProof() {
  const status = wasmStatus.value;
  const [digits, setDigits] = useState<string | null>(null);
  const api = status.state === "ready" ? status.api : null;

  useEffect(() => {
    if (api) setDigits(api.safety_number(api.generate_identity(), api.generate_identity()));
  }, [api]);

  return (
    <div className="lab__wasm" data-testid="wasm-proof" data-state={status.state}>
      <p data-testid="wasm-status">
        {status.state === "ready"
          ? `parolnet-wasm ${status.version}: safety number of two new identities`
          : status.state === "failed"
          ? `wasm failed: ${status.reason}`
          : status.state === "loading"
          ? `loading wasm ${status.loaded} / ${status.total} bytes`
          : "wasm not started"}
      </p>
      {/* Placeholder digits keep the block's size, so nothing moves when wasm is ready. */}
      <SafetyNumber
        digits={digits ?? "0".repeat(60)}
        label={t("safety.label")}
        testId={digits ? "wasm-result" : "wasm-result-pending"}
      />
      {status.state === "failed" && (
        <Button
          testId="wasm-retry"
          onClick={() => void loadWasm().catch(() => {})}
        >
          {t("action.tryAgain")}
        </Button>
      )}
    </div>
  );
}

const SAMPLE_BUBBLES: Array<[BubbleKind, string]> = [
  ["received", "Are you still coming on Saturday?"],
  ["delivered", "Yes. I can bring the projector."],
  ["held", "The keys are with the neighbour at number 4."],
  ["dropped", "This one could not be kept."],
];

export function Lab({ controls }: { controls: FakeControls }) {
  const store = useStore();
  const [peer, setPeer] = useState<string>(FAKE_PEERS.tomasz);
  const [sheet, setSheet] = useState(false);
  const contacts = store.contacts.value;
  const contact = contacts.find((c) => c.peerId === peer) ?? contacts[0];
  const selfOnline = store.selfOnline.value;

  return (
    <main className="lab" data-testid="lab">
      <header className="lab__header">
        <h1 className="lab__title">State lab</h1>
        <p className="lab__note">
          Development page. Every state of the design, on fake data.{" "}
          <a href={hrefOf({ name: "list" })} data-testid="lab-to-app">Open the app</a>
        </p>
      </header>

      <section className="lab__controls" aria-label="Controls" data-testid="lab-controls">
        <Choice
          label="Theme"
          values={THEMES}
          value={themeChoice.value}
          onChoose={setTheme}
          testId="lab-theme"
        />
        <Choice
          label="Direction"
          values={["ltr", "rtl"] as const}
          value={direction.value}
          onChoose={setDirectionOverride}
          testId="lab-dir"
        />
        <Choice
          label="Locale"
          values={LOCALES}
          value={locale.value as (typeof LOCALES)[number]}
          onChoose={(code) => {
            setDirectionOverride(null);
            void setLocale(code);
          }}
          testId="lab-locale"
        />
        {contact && (
          <>
            <label className="lab__choice">
              <span className="lab__choice-label">Contact</span>
              <select
                className="field__input"
                value={contact.peerId}
                data-testid="lab-contact"
                onChange={(e) => setPeer(e.currentTarget.value)}
              >
                {contacts.map((c) => <option key={c.peerId} value={c.peerId}>{c.name}</option>)}
              </select>
            </label>
            <div className="lab__choice" role="group" aria-label="Presence">
              <span className="lab__choice-label">Presence</span>
              <Button
                testId="lab-online"
                onClick={() => controls.setPath(contact.peerId, "Direct")}
              >
                Comes online
              </Button>
              <Button testId="lab-away" onClick={() => controls.setPath(contact.peerId, "Offline")}>
                Goes away
              </Button>
            </div>
            <Choice
              label="Path"
              values={PATH_STATES}
              value={contact.path}
              onChoose={(path) => controls.setPath(contact.peerId, path)}
              testId="lab-path"
            />
          </>
        )}
        <Choice
          label="This device"
          values={["online", "offline"] as const}
          value={selfOnline ? "online" : "offline"}
          onChoose={(v) => controls.setSelfOnline(v === "online")}
          testId="lab-self"
        />
        <div className="lab__choice">
          <Button testId="lab-reset" onClick={() => controls.reset()}>Reset fake data</Button>
          <Button testId="lab-clear" onClick={() => controls.clear()}>Remove all contacts</Button>
        </div>
      </section>

      <div className="lab__grid">
        {contact && (
          <Story title="Conversation (live, follows the controls)" id="conversation">
            <div className="lab__frame">
              <Conversation peerId={contact.peerId} showBack={false} />
            </div>
          </Story>
        )}

        <Story title="The line" id="line">
          {LINE_STATES.map((state) => (
            <Line key={state} state={state} name={NAME} testId={`lab-line-${state}`} />
          ))}
        </Story>

        <Story title="Bubbles" id="bubbles">
          <ol className="thread__list lab__thread">
            {SAMPLE_BUBBLES.map(([kind, text]) => (
              <li
                key={kind}
                className={`thread__item thread__item--${
                  kind === "received" ? "received" : "sent"
                }`}
              >
                <Bubble
                  kind={kind}
                  body={{ kind: "text", text }}
                  tail={kind === "received" ? "start" : "end"}
                  testId={`lab-bubble-${kind}`}
                />
                {kind === "delivered" && (
                  <p className="thread__caption">{t("caption.delivered", { name: NAME })}</p>
                )}
                {kind === "held" && (
                  <p className="thread__caption thread__caption--waiting">{t("caption.waiting")}</p>
                )}
                {kind === "dropped" && (
                  <p className="thread__caption thread__caption--dropped">{t("caption.dropped")}</p>
                )}
              </li>
            ))}
            <li className="thread__item thread__item--sent">
              <Bubble
                kind="held"
                body={{ kind: "file", name: "harbour.jpg", bytes: 2_411_724 }}
                testId="lab-bubble-file"
              />
            </li>
            <li className="thread__item thread__item--received">
              <Bubble
                kind="received"
                body={{ kind: "call", media: "video" }}
                testId="lab-bubble-call"
              />
            </li>
          </ol>
        </Story>

        <Story title="Buttons" id="buttons">
          <div className="lab__row">
            <Button variant="primary" testId="lab-btn-primary">{t("list.addContact")}</Button>
            <Button variant="quiet" testId="lab-btn-quiet">{t("action.tryAgain")}</Button>
            <Button variant="danger" testId="lab-btn-danger">{t("call.end")}</Button>
          </div>
          <div className="lab__row">
            <IconButton
              icon="phone"
              label={t("call.voice", { name: NAME })}
              testId="lab-icon-phone"
            />
            <IconButton
              icon="video"
              label={t("call.video", { name: NAME })}
              testId="lab-icon-video"
              unavailable
            />
            <IconButton icon="send" label={t("composer.send")} testId="lab-icon-send" filled />
          </div>
        </Story>

        <Story title="Panels" id="panels">
          <Panel
            tone="amber"
            testId="lab-panel-amber"
            title={t("panel.noPath.title")}
            actions={[
              {
                label: t("action.tryAgain"),
                testId: "lab-panel-amber-1",
                primary: true,
                onClick: () => {},
              },
              { label: t("action.useOwnRelay"), testId: "lab-panel-amber-2", onClick: () => {} },
            ]}
          >
            {t("panel.noPath.body")}
          </Panel>
          <Panel
            tone="red"
            testId="lab-panel-red"
            title={t("panel.blocked.title")}
            actions={[
              {
                label: t("action.tryAgain"),
                testId: "lab-panel-red-1",
                primary: true,
                onClick: () => {},
              },
              { label: t("action.whatThisMeans"), testId: "lab-panel-red-2", onClick: () => {} },
            ]}
          >
            {t("panel.blocked.body", { name: NAME })}
          </Panel>
          <Panel
            tone="plain"
            testId="lab-panel-plain"
            title={t("update.title")}
            actions={[{
              label: t("update.reload"),
              testId: "lab-panel-plain-1",
              primary: true,
              onClick: () => {},
            }]}
          >
            {t("update.body")}
          </Panel>
        </Story>

        <Story title="Conversation rows" id="rows">
          <SectionHeader>{t("list.online")}</SectionHeader>
          <ConversationRow
            contact={{ peerId: "a1".repeat(32), name: "Mira", kind: "person", path: "Direct" }}
            preview="Got it, thank you."
            waiting={0}
            href="#/lab"
            current={false}
          />
          <ConversationRow
            contact={{
              peerId: "c3".repeat(32),
              name: "Reading group",
              kind: "group",
              path: "Direct",
            }}
            preview="Chapter six for Thursday."
            waiting={0}
            href="#/lab"
            current
          />
          <SectionHeader>{t("list.away")}</SectionHeader>
          <ConversationRow
            contact={{ peerId: "b2".repeat(32), name: NAME, kind: "person", path: "Offline" }}
            preview="Call me when you are back online, there is a lot to tell you about."
            waiting={3}
            href="#/lab"
            current={false}
          />
        </Story>

        <Story title="Composer" id="composer">
          <Composer name={NAME} away={false} onSend={() => {}} />
          <Composer name={NAME} away onSend={() => {}} />
        </Story>

        <Story title="Codes" id="codes">
          <CodeBlock code="7K4MQ2ZD9XTBH6RP" label={t("code.label")} testId="lab-code" />
          <WasmProof />
        </Story>

        <Story title="Sheet and toast" id="overlays">
          <div className="lab__row">
            <Button testId="lab-open-sheet" onClick={() => setSheet(true)}>Open a sheet</Button>
            <Button testId="lab-show-toast" onClick={() => showToast(t("toast.takenBack"))}>
              Show a toast
            </Button>
          </div>
          {sheet && (
            <Sheet
              title={t("sheet.blocked.title")}
              testId="lab-sheet"
              onClose={() => setSheet(false)}
            >
              <p>{t("sheet.blocked.body1")}</p>
              <p>{t("sheet.blocked.body2")}</p>
              <Button variant="primary" testId="lab-sheet-done" onClick={() => setSheet(false)}>
                {t("action.close")}
              </Button>
            </Sheet>
          )}
        </Story>
      </div>
    </main>
  );
}
