// Settings: five plain groups. You, Connection, Calls and devices, Appearance and language,
// About.
import { type ReactNode, useEffect, useId, useState } from "denext";
import { Button } from "../components/Button.tsx";
import { Screen } from "../components/Screen.tsx";
import { Sheet } from "../components/Sheet.tsx";
import { showToast } from "../components/Toast.tsx";
import { chooseLocale, LANGUAGES, locale, type MessageKey, t } from "../i18n/index.ts";
import { assetUrl } from "../platform/base.ts";
import {
  canChooseSpeaker,
  chooseDevice,
  type DeviceChoice,
  deviceChoice,
  type DeviceList,
  listDevices,
} from "../platform/devices.ts";
import { notificationsSupported, notifyEnabled, setNotify } from "../platform/notify.ts";
import { defaultRelayUrl, isRelayUrl, savedRelayUrl, saveRelayUrl } from "../platform/relay-url.ts";
import { setTheme, type ThemeChoice, themeChoice } from "../platform/theme.ts";
import { wasmStatus } from "../platform/wasm.ts";
import { hrefOf } from "../router.ts";
import { useStore } from "../state/context.ts";
import type { RelayState } from "../state/model.ts";
import { errorText } from "./errors.ts";
import { BackupSetting, LockSetting, RestoreSetting } from "./Protection.tsx";

function Group(
  { title, testId, children }: { title: string; testId: string; children: ReactNode },
) {
  const id = useId();
  return (
    <section className="settings__group" aria-labelledby={id} data-testid={testId}>
      <h2 className="settings__group-title" id={id}>{title}</h2>
      {children}
    </section>
  );
}

/** An on/off setting: a button with the switch role, its label beside it. */
function Switch({ label, help, on, onChange, testId }: {
  label: string;
  help?: string;
  on: boolean;
  onChange: (on: boolean) => void;
  testId: string;
}) {
  const helpId = useId();
  return (
    <div className="switch">
      <button
        type="button"
        role="switch"
        className="switch__control"
        aria-checked={on ? "true" : "false"}
        aria-describedby={help ? helpId : undefined}
        data-testid={testId}
        onClick={() => onChange(!on)}
      >
        <span className="switch__track" aria-hidden="true">
          <span className="switch__thumb" />
        </span>
        <span className="switch__label">{label}</span>
      </button>
      {help && <p className="field__help" id={helpId}>{help}</p>}
    </div>
  );
}

const STATUS: Record<RelayState["kind"], MessageKey> = {
  Registered: "settings.status.registered",
  Connecting: "settings.status.connecting",
  Disconnected: "settings.status.disconnected",
};

function You() {
  const store = useStore();
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState("");
  const word = t("settings.wipe.word");
  const ready = typed.trim().toLocaleLowerCase() === word.toLocaleLowerCase();

  return (
    <Group title={t("settings.you")} testId="settings-you">
      <div className="settings__item">
        <h3 className="settings__item-title">{t("settings.you.code")}</h3>
        <p className="field__help">{t("settings.you.codeBody")}</p>
        <a className="btn btn--quiet" href={hrefOf({ name: "add" })} data-testid="settings-code">
          {t("settings.you.showCode")}
        </a>
      </div>
      <LockSetting />
      <BackupSetting />
      <RestoreSetting />
      <div className="settings__item">
        <h3 className="settings__item-title">{t("settings.wipe")}</h3>
        <p className="field__help">{t("settings.wipe.body")}</p>
        <Button variant="danger" testId="settings-wipe" onClick={() => setConfirming(true)}>
          {t("settings.wipe")}
        </Button>
      </div>
      {confirming && (
        <Sheet
          title={t("settings.wipe")}
          testId="sheet-wipe"
          onClose={() => {
            setConfirming(false);
            setTyped("");
          }}
        >
          <p>{t("settings.wipe.body")}</p>
          <form
            className="sheet__form"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              if (ready) void store.wipe();
            }}
          >
            <label className="field">
              <span className="field__label">{t("settings.wipe.label", { word })}</span>
              <input
                className="field__input"
                value={typed}
                autoComplete="off"
                autoCapitalize="off"
                spellcheck={false}
                data-testid="wipe-input"
                onInput={(event) => setTyped(event.currentTarget.value)}
              />
            </label>
            <Button type="submit" variant="danger" testId="wipe-confirm" disabled={!ready}>
              {t("settings.wipe.confirm")}
            </Button>
          </form>
        </Sheet>
      )}
    </Group>
  );
}

function OwnRelayServer() {
  const store = useStore();
  const saved = store.turn.value;
  const [uri, setUri] = useState(saved?.uri ?? "");
  const [username, setUsername] = useState(saved?.username ?? "");
  const [password, setPassword] = useState("");
  const [only, setOnly] = useState(saved?.relayOnly ?? false);
  const [problem, setProblem] = useState<string | null>(null);
  const ids = { uri: useId(), username: useId(), password: useId() };

  const save = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    try {
      await store.setTurn({ uri, username, password, relayOnly: only });
      setPassword("");
      setProblem(null);
      showToast(t("toast.turnSaved"));
    } catch {
      setProblem(t("settings.turn.invalid"));
    }
  };

  const remove = async () => {
    try {
      await store.setTurn(null);
      setUri("");
      setUsername("");
      setPassword("");
      setOnly(false);
      setProblem(null);
      showToast(t("toast.turnRemoved"));
    } catch (error) {
      setProblem(errorText(error, {}, "settings.turn.removeFailed"));
    }
  };

  return (
    <form className="settings__item" onSubmit={save} noValidate data-testid="settings-turn">
      <h3 className="settings__item-title">{t("settings.turn.title")}</h3>
      <p className="field__help">{t("settings.turn.body")}</p>
      <div className="field">
        <label className="field__label" htmlFor={ids.uri}>{t("settings.turn.address")}</label>
        <input
          id={ids.uri}
          className="field__input"
          value={uri}
          placeholder="turn:turn.example.org:3478"
          autoComplete="off"
          autoCapitalize="off"
          spellcheck={false}
          dir="ltr"
          data-testid="turn-uri"
          onInput={(event) => setUri(event.currentTarget.value)}
        />
      </div>
      <div className="field">
        <label className="field__label" htmlFor={ids.username}>
          {t("settings.turn.username")}
        </label>
        <input
          id={ids.username}
          className="field__input"
          value={username}
          autoComplete="off"
          autoCapitalize="off"
          spellcheck={false}
          dir="ltr"
          data-testid="turn-username"
          onInput={(event) => setUsername(event.currentTarget.value)}
        />
      </div>
      <div className="field">
        <label className="field__label" htmlFor={ids.password}>
          {t("settings.turn.password")}
        </label>
        {/* Never filled from what is saved: a saved password is not shown back. */}
        <input
          id={ids.password}
          className="field__input"
          type="password"
          value={password}
          autoComplete="new-password"
          dir="ltr"
          data-testid="turn-password"
          onInput={(event) => setPassword(event.currentTarget.value)}
        />
        {saved && <span className="field__help">{t("settings.turn.passwordSaved")}</span>}
      </div>
      <Switch
        label={t("settings.turn.only")}
        help={t("settings.turn.onlyHelp")}
        on={only}
        onChange={setOnly}
        testId="turn-only"
      />
      <p className="field__problem" role="alert" data-testid="turn-problem">{problem ?? ""}</p>
      <div className="settings__actions">
        <Button type="submit" variant="primary" testId="turn-save">{t("action.save")}</Button>
        {saved && <Button testId="turn-remove" onClick={remove}>{t("action.remove")}</Button>}
      </div>
    </form>
  );
}

function RelayAddress() {
  const [value, setValue] = useState(savedRelayUrl() ?? "");
  const [problem, setProblem] = useState<string | null>(null);
  const id = useId();

  const save = (event: { preventDefault(): void }) => {
    event.preventDefault();
    const next = value.trim();
    if (next !== "" && !isRelayUrl(next)) {
      setProblem(t("settings.relay.invalid"));
      return;
    }
    saveRelayUrl(next === "" ? null : next);
    // The engine takes its relay at start.
    location.reload();
  };

  return (
    <details className="settings__advanced" data-testid="settings-advanced">
      <summary className="settings__summary">{t("settings.advanced")}</summary>
      <form className="settings__item" onSubmit={save} noValidate>
        <div className="field">
          <label className="field__label" htmlFor={id}>{t("settings.relay.address")}</label>
          <input
            id={id}
            className="field__input"
            value={value}
            placeholder={defaultRelayUrl()}
            autoComplete="off"
            autoCapitalize="off"
            spellcheck={false}
            dir="ltr"
            data-testid="relay-url"
            onInput={(event) => setValue(event.currentTarget.value)}
          />
          <span className="field__help">
            {t("settings.relay.help", { url: defaultRelayUrl() })}
          </span>
        </div>
        <p className="field__problem" role="alert" data-testid="relay-problem">{problem ?? ""}</p>
        <Button type="submit" testId="relay-save">{t("settings.relay.save")}</Button>
      </form>
    </details>
  );
}

function Connection() {
  const store = useStore();
  const relay = store.relay.value;
  return (
    <Group title={t("settings.connection")} testId="settings-connection">
      <p role="status" data-testid="settings-status" data-state={relay.kind}>
        {t(STATUS[relay.kind])}
      </p>
      <OwnRelayServer />
      <RelayAddress />
    </Group>
  );
}

function DeviceSelect({ kind, label, devices }: {
  kind: keyof DeviceChoice;
  label: string;
  devices: MediaDeviceInfo[];
}) {
  const id = useId();
  const chosen = deviceChoice.value[kind];
  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>{label}</label>
      <select
        id={id}
        className="field__input"
        value={devices.some((device) => device.deviceId === chosen) ? chosen : ""}
        data-testid={`device-${kind}`}
        onChange={(event) => chooseDevice(kind, event.currentTarget.value)}
      >
        <option value="">{t("settings.devices.default")}</option>
        {devices.filter((device) => device.deviceId !== "" && device.deviceId !== "default").map((
          device,
          index,
        ) => (
          <option key={device.deviceId} value={device.deviceId}>
            {device.label || t("settings.devices.unnamed", { n: index + 1 })}
          </option>
        ))}
      </select>
    </div>
  );
}

function Devices() {
  const [devices, setDevices] = useState<DeviceList>({
    microphones: [],
    cameras: [],
    speakers: [],
  });
  const [blocked, setBlocked] = useState(false);
  const notify = notifyEnabled.value;

  const refresh = () => void listDevices().then(setDevices);
  useEffect(() => {
    refresh();
    const media = navigator.mediaDevices;
    media?.addEventListener?.("devicechange", refresh);
    return () => media?.removeEventListener?.("devicechange", refresh);
  }, []);

  const unnamed = [...devices.microphones, ...devices.cameras].some((device) => !device.label);
  // Names are hidden until capture was allowed once: ask, then let go of the devices.
  const showNames = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
      for (const track of stream.getTracks()) track.stop();
    } catch {
      // Not allowed: the lists keep their numbered entries.
    }
    refresh();
  };

  return (
    <Group title={t("settings.devices")} testId="settings-devices">
      <DeviceSelect kind="camera" label={t("settings.devices.camera")} devices={devices.cameras} />
      <DeviceSelect
        kind="microphone"
        label={t("settings.devices.microphone")}
        devices={devices.microphones}
      />
      {canChooseSpeaker()
        ? (
          <DeviceSelect
            kind="speaker"
            label={t("settings.devices.speaker")}
            devices={devices.speakers}
          />
        )
        : <p className="field__help">{t("settings.devices.speakerFixed")}</p>}
      {unnamed && (
        <div className="settings__item">
          <p className="field__help">{t("settings.devices.namesHelp")}</p>
          <Button testId="device-names" onClick={() => void showNames()}>
            {t("settings.devices.names")}
          </Button>
        </div>
      )}
      {notificationsSupported() && (
        <div className="settings__item">
          <Switch
            label={t("settings.notify")}
            help={t("settings.notify.help")}
            on={notify}
            testId="settings-notify"
            onChange={(on) => void setNotify(on).then((enabled) => setBlocked(on && !enabled))}
          />
          <p className="field__problem" role="alert" data-testid="notify-problem">
            {blocked ? t("settings.notify.blocked") : ""}
          </p>
        </div>
      )}
    </Group>
  );
}

const THEMES: Array<[ThemeChoice, MessageKey]> = [
  ["system", "settings.theme.system"],
  ["light", "settings.theme.light"],
  ["dark", "settings.theme.dark"],
];

function Appearance() {
  const theme = themeChoice.value;
  const languageId = useId();
  const themeId = useId();
  return (
    <Group title={t("settings.appearance")} testId="settings-appearance">
      <div className="field">
        <span className="field__label" id={themeId}>{t("settings.theme")}</span>
        <div className="segmented" role="group" aria-labelledby={themeId}>
          {THEMES.map(([value, label]) => (
            <button
              key={value}
              type="button"
              className="segmented__option"
              aria-pressed={theme === value ? "true" : "false"}
              data-testid={`theme-${value}`}
              onClick={() => setTheme(value)}
            >
              {t(label)}
            </button>
          ))}
        </div>
      </div>
      <div className="field">
        <label className="field__label" htmlFor={languageId}>{t("settings.language")}</label>
        <select
          id={languageId}
          className="field__input"
          value={locale.value}
          data-testid="settings-language"
          onChange={(event) => void chooseLocale(event.currentTarget.value)}
        >
          {LANGUAGES.map((language) => (
            <option key={language.code} value={language.code} lang={language.code}>
              {language.name}
            </option>
          ))}
        </select>
      </div>
    </Group>
  );
}

function About() {
  const status = wasmStatus.value;
  return (
    <Group title={t("settings.about")} testId="settings-about">
      <p>{t("settings.about.body")}</p>
      <p data-testid="settings-version">
        {t("settings.version")}{" "}
        <span dir="ltr">{status.state === "ready" ? status.version : ""}</span>
      </p>
      <p>
        <a
          className="link"
          href={assetUrl("licences.txt")}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="settings-licences"
        >
          {t("settings.licences")}
        </a>
      </p>
    </Group>
  );
}

export function Settings() {
  return (
    <Screen title={t("settings.title")} testId="settings-screen">
      <div className="settings">
        <You />
        <Connection />
        <Devices />
        <Appearance />
        <About />
      </div>
    </Screen>
  );
}
