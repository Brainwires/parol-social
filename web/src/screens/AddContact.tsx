// Add a contact: one screen for both directions. This device's code as a picture to scan and
// as text; and two ways to take theirs, the camera or a paste. Then the two devices reach
// each other and both show a verification code, which the two people compare (PNP-003 §5.5);
// only then is the contact added, and given a name. A scanned code means the two devices
// were together, so that contact is verified in person; so is one whose verification code
// both confirmed.
import { useEffect, useId, useRef, useState } from "denext";
import { Button } from "../components/Button.tsx";
import { CodeBlock } from "../components/Codes.tsx";
import { Icon } from "../components/Icon.tsx";
import { Panel } from "../components/Panel.tsx";
import { QrCode } from "../components/QrCode.tsx";
import { Screen } from "../components/Screen.tsx";
import { showToast } from "../components/Toast.tsx";
import { requestPersistentStorage } from "../engine/browser.ts";
import { type MessageKey, t } from "../i18n/index.ts";
import { keepStorage } from "../platform/install.ts";
import { type ScanFailure, type Scanner, startScanner } from "../qr/scan.ts";
import { hrefOf, navigate } from "../router.ts";
import { useStore } from "../state/context.ts";
import { rememberAddedHere } from "../state/names.ts";
import { contactOf } from "../state/store.ts";
import { errorText, PAIRING_FAILED } from "./errors.ts";
import { SasPanel } from "./SasCheck.tsx";

type How = "scan" | "paste" | "theirs";
type Mode = "code" | "scan" | "paste";

const MINUTE = 60_000;

const NAMING_BODY: Record<How, MessageKey> = {
  scan: "name.bodyScan",
  paste: "name.bodyPaste",
  theirs: "name.bodyTheyAdded",
};

const SCAN_FAILURE: Record<ScanFailure, MessageKey> = {
  "denied": "scan.denied",
  "no-camera": "scan.noCamera",
  "failed": "scan.failed",
};

/** This device's code, as a picture and as text, with how long it is good for. */
function OwnCode() {
  const store = useStore();
  const pairing = store.pairing.value;
  const [now, setNow] = useState(() => Date.now());
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const making = useRef(false);

  // A code is made when there is none: on arrival (leaving the screen closed the last one),
  // after a reload, when one expires, and after one was used.
  useEffect(() => {
    if (pairing || making.current) return;
    making.current = true;
    store.createPairingCode().then(
      () => setFailed(false),
      () => setFailed(true),
    ).finally(() => {
      making.current = false;
      setNow(Date.now());
    });
  }, [pairing, attempt]);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 15_000);
    return () => clearInterval(timer);
  }, []);

  if (!pairing) {
    return (
      <div className="pairing__own" data-testid="pairing-own" data-state="making">
        <p role="status">{failed ? t("add.makeFailed") : t("add.making")}</p>
        {failed && (
          <Button testId="pairing-retry" onClick={() => setAttempt(attempt + 1)}>
            {t("action.tryAgain")}
          </Button>
        )}
      </div>
    );
  }

  const minutes = Math.max(1, Math.ceil((pairing.expiresAtMs - now) / MINUTE));
  // As text the code goes without blanks (`text`); the picture holds the code itself.
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(pairing.text);
      showToast(t("toast.codeCopied"));
    } catch {
      showToast(t("add.copyFailed"));
    }
  };
  const share = async () => {
    try {
      await navigator.share({ text: pairing.text });
    } catch {
      // The person closed the share sheet.
    }
  };

  return (
    <div className="pairing__own" data-testid="pairing-own" data-state="ready">
      <h2 className="pairing__label">{t("add.yourCode")}</h2>
      <QrCode text={pairing.code} label={t("add.qrLabel")} testId="pairing-qr" />
      <p className="pairing__expiry" data-testid="pairing-expiry">
        {t("add.expiry", { minutes })}
      </p>
      <div className="pairing__actions">
        <Button testId="pairing-copy" icon="copy" onClick={copy}>{t("add.copy")}</Button>
        {typeof navigator.share === "function" && (
          <Button testId="pairing-share" icon="share" onClick={share}>{t("add.share")}</Button>
        )}
      </div>
      <CodeAsText code={pairing.text} />
      <p className="pairing__help" data-testid="pairing-help">{t("add.help")}</p>
    </div>
  );
}

/**
 * The code as text, behind a disclosure: a real code is a few hundred characters, and shown
 * open it pushes everything else off a phone's screen. It stays in the page while closed, so
 * Copy and Share (and anything reading it) never need it open.
 */
function CodeAsText({ code }: { code: string }) {
  const [open, setOpen] = useState(false);
  const region = useId();
  return (
    <div className="pairing__text">
      <button
        type="button"
        className="link-btn pairing__disclosure"
        aria-expanded={open}
        aria-controls={region}
        data-testid="pairing-code-toggle"
        onClick={() => setOpen(!open)}
      >
        <Icon name="chevron" />
        {t("add.showText")}
      </button>
      <div id={region} className="pairing__text-region" hidden={!open}>
        <CodeBlock code={code} label={t("code.label")} testId="pairing-code" small selectable />
      </div>
    </div>
  );
}

type Pair = (code: string, via: "scan" | "paste") => Promise<void>;

function ScanTheirs({ pair, onStop }: { pair: Pair; onStop: () => void }) {
  const video = useRef<HTMLVideoElement>(null);
  const [state, setState] = useState<"starting" | "scanning" | ScanFailure>("starting");
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    const element = video.current;
    if (!element) return;
    let scanner: Scanner | null = null;
    let left = false;
    let pairing = false;
    let refused = "";

    const onText = async (text: string) => {
      // The same picture is read many times a second: try each text once.
      if (pairing || text === refused) return;
      pairing = true;
      try {
        await pair(text, "scan");
        // Read: the camera is not needed any more.
        scanner?.stop();
      } catch (error) {
        refused = text;
        if (!left) setProblem(errorText(error, {}, "scan.notCode"));
      } finally {
        pairing = false;
      }
    };

    startScanner(element, (text) => void onText(text)).then(
      (started) => {
        scanner = started;
        // The person left while the camera was starting: release it at once.
        if (left) started.stop();
        else setState("scanning");
      },
      (failure: ScanFailure) => {
        if (!left) setState(failure);
      },
    );
    return () => {
      left = true;
      scanner?.stop();
    };
  }, []);

  const failed = state !== "starting" && state !== "scanning";
  return (
    <div className="pairing__scan" data-testid="pairing-scan" data-state={state}>
      <h2 className="pairing__label">{t("scan.title")}</h2>
      {
        /* Muted and inline, so phones play it without a tap and without going full screen.
          It shows nothing until the camera starts. */
      }
      <video
        ref={video}
        className="pairing__video"
        muted
        playsInline
        aria-label={t("scan.title")}
        hidden={failed}
        data-testid="pairing-video"
      />
      <p role="status" data-testid="pairing-scan-status">
        {failed
          ? t(SCAN_FAILURE[state])
          : state === "starting"
          ? t("scan.starting")
          : t("scan.help")}
      </p>
      <p className="field__problem" role="alert" data-testid="pairing-scan-problem">
        {problem ?? ""}
      </p>
      <Button testId="pairing-scan-stop" onClick={onStop}>{t("scan.stop")}</Button>
    </div>
  );
}

function PasteTheirs({ pair, onCancel }: { pair: Pair; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const field = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    field.current?.focus();
  }, []);

  const submit = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    if (busy) return;
    if (!code.trim()) {
      setProblem(t("paste.empty"));
      return;
    }
    setBusy(true);
    try {
      await pair(code, "paste");
    } catch (error) {
      setProblem(errorText(error, {}, "pair.failed"));
      setBusy(false);
    }
  };

  return (
    <form className="pairing__paste" onSubmit={submit} noValidate data-testid="pairing-paste">
      <h2 className="pairing__label">{t("paste.title")}</h2>
      <label className="field">
        <span className="field__label">{t("paste.label")}</span>
        <textarea
          ref={field}
          className="field__input field__input--code field__input--area"
          rows={4}
          value={code}
          autoComplete="off"
          autoCapitalize="off"
          spellcheck={false}
          dir="ltr"
          data-testid="pairing-code-input"
          onInput={(event) => setCode(event.currentTarget.value)}
        />
      </label>
      <p className="field__problem" role="alert" data-testid="pairing-problem">{problem ?? ""}</p>
      <div className="pairing__actions">
        <Button type="submit" variant="primary" testId="pairing-code-submit" disabled={busy}>
          {t("paste.submit")}
        </Button>
        <Button testId="pairing-paste-cancel" onClick={onCancel}>{t("action.cancel")}</Button>
      </div>
    </form>
  );
}

/** Why the last try to add a contact came to nothing, until it is dismissed. */
function PairingProblem() {
  const store = useStore();
  const notice = store.notice.value;
  if (notice?.code !== "Pairing") return null;
  const reason = notice.pairing ?? "Failed";
  return (
    <Panel
      tone={reason === "SasRejected" || reason === "SasMismatch" ? "red" : "amber"}
      testId="pairing-failed"
      title={t("notice.pairing.title")}
      actions={[
        {
          label: t("action.dismiss"),
          testId: "pairing-failed-dismiss",
          onClick: store.dismissNotice,
        },
      ]}
    >
      {t(PAIRING_FAILED[reason])}
    </Panel>
  );
}

/** The two devices are reaching each other: nothing to do but wait, or stop. */
function Connecting({ peerId }: { peerId: string }) {
  const store = useStore();
  return (
    <div className="pairing__own" data-testid="pairing-connecting">
      <p role="status">{t("pairing.waiting")}</p>
      <Button
        testId="pairing-stop"
        onClick={() => void store.stopPairing(peerId).catch(() => {})}
      >
        {t("pairing.stop")}
      </Button>
    </div>
  );
}

function NameContact({ peerId, how }: { peerId: string; how: How }) {
  const store = useStore();
  const [name, setName] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const field = useRef<HTMLInputElement>(null);

  useEffect(() => {
    field.current?.focus();
  }, []);

  const submit = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    const chosen = name.trim();
    if (!chosen) {
      setProblem(t("name.empty"));
      return;
    }
    try {
      await store.rename(peerId, chosen);
    } catch (error) {
      setProblem(errorText(error));
      return;
    }
    // The identity now matters to someone else: ask the browser to keep this device's
    // storage. Once, and here, because Firefox answers with a prompt.
    void keepStorage(requestPersistentStorage);
    showToast(t("toast.contactAdded", { name: chosen }));
    navigate({ name: "conversation", peerId });
  };

  // Both confirmed the verification code: that is worth more than how the code travelled.
  const verified = how !== "scan" && contactOf(store, peerId)?.contact.sasVerified === true;
  return (
    <form className="pairing__name" onSubmit={submit} noValidate data-testid="pairing-name">
      <p data-testid="pairing-name-body" data-how={how} data-sas={verified ? "true" : "false"}>
        {t(verified ? "name.bodyVerified" : NAMING_BODY[how])}
      </p>
      <label className="field">
        <span className="field__label">{t("name.label")}</span>
        <input
          ref={field}
          className="field__input"
          value={name}
          autoComplete="off"
          maxLength={80}
          data-testid="contact-name-input"
          onInput={(event) => setName(event.currentTarget.value)}
        />
        <span className="field__help">{t("name.hint")}</span>
      </label>
      <p className="field__problem" role="alert" data-testid="contact-name-problem">
        {problem ?? ""}
      </p>
      <Button type="submit" variant="primary" testId="contact-name-submit">
        {t("name.done")}
      </Button>
    </form>
  );
}

export function AddContact() {
  const store = useStore();
  const [mode, setMode] = useState<Mode>("code");
  // A code works only while its owner is looking at it: leaving the screen closes it, and
  // coming back makes a fresh one.
  useEffect(() => () => void store.cancelPairing().catch(() => {}), []);
  const [added, setAdded] = useState<{ peerId: string; how: How } | null>(null);
  // A pairing that came to nothing leaves the person at their own code, with the reason
  // above it (and the camera off: the code it was looking at is spent).
  const failed = store.notice.value?.code === "Pairing";
  useEffect(() => {
    if (failed) setMode("code");
  }, [failed]);
  // Who was already a contact when this screen opened: anyone new after that used our code.
  const known = useRef<Set<string> | null>(null);
  const contacts = store.contacts.value;
  known.current ??= new Set(contacts.map((view) => view.contact.peerId));

  // The contact appears in the store before `pair` resolves: remember how it is being added.
  const adding = useRef<How | null>(null);
  const pair: Pair = async (code, via) => {
    adding.current = via;
    // A new try: what the last one came to is no longer the news.
    if (store.notice.value?.code === "Pairing") store.dismissNotice();
    try {
      const contact = await store.pair(code, via);
      rememberAddedHere(contact.peerId);
      setAdded({ peerId: contact.peerId, how: via });
    } finally {
      adding.current = null;
    }
  };

  const newcomer = contacts.find((view) => !known.current!.has(view.contact.peerId));
  const naming = added ??
    (newcomer ? { peerId: newcomer.contact.peerId, how: adding.current ?? "theirs" } : null);

  // The verification code comes first, whoever it is with: nothing else can be done about a
  // contact that is being added until it was compared.
  const sas = store.sas.value;
  if (sas) {
    return (
      <Screen title={t("sas.title")} testId="add-screen" focusKey={`sas-${sas.peerId}`}>
        <div className="pairing">
          <SasPanel key={sas.peerId} sas={sas} />
        </div>
      </Screen>
    );
  }

  const beingAdded = naming ? contactOf(store, naming.peerId) : undefined;
  if (naming && beingAdded?.contact.pairing !== undefined) {
    return (
      <Screen title={t("pairing.waitTitle")} testId="add-screen" focusKey="connecting">
        <div className="pairing">
          <Connecting peerId={naming.peerId} />
        </div>
      </Screen>
    );
  }

  if (naming && beingAdded) {
    return (
      <Screen title={t("name.title")} testId="add-screen" focusKey="name" focusTitle={false}>
        <NameContact key={naming.peerId} peerId={naming.peerId} how={naming.how} />
      </Screen>
    );
  }

  return (
    <Screen
      title={t("add.title")}
      testId="add-screen"
      focusKey={mode}
      focusTitle={mode !== "paste"}
    >
      <div className="pairing">
        <PairingProblem />
        {mode === "code" && <OwnCode />}
        {mode === "scan" && <ScanTheirs pair={pair} onStop={() => setMode("code")} />}
        {mode === "paste" && <PasteTheirs pair={pair} onCancel={() => setMode("code")} />}
        {mode === "code" && (
          <div className="pairing__theirs">
            <Button
              variant="primary"
              testId="pairing-scan-open"
              icon="scan"
              onClick={() => setMode("scan")}
            >
              {t("add.scan")}
            </Button>
            <Button testId="pairing-paste-open" onClick={() => setMode("paste")}>
              {t("add.paste")}
            </Button>
          </div>
        )}
        <p className="pairing__ip" data-testid="pairing-ip">
          {t("add.ip")}{" "}
          <a className="link" href={hrefOf({ name: "settings" })} data-testid="pairing-hide-ip">
            {t("add.hideIp")}
          </a>
        </p>
      </div>
    </Screen>
  );
}
