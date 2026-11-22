// The passphrase lock and the backup: the unlock screen's form, the three settings under
// "You" (lock, back up, restore) and the sheet that restores a backup, which the first-run
// screen opens too.
import { useEffect, useId, useRef, useState } from "denext";
import { Button } from "../components/Button.tsx";
import { Sheet } from "../components/Sheet.tsx";
import { showToast } from "../components/Toast.tsx";
import { BACKUP_EXTENSION, BackupError } from "../engine/backup.ts";
import { MIN_PASSPHRASE, VaultError } from "../engine/vault.ts";
import { locale, type MessageKey, t } from "../i18n/index.ts";
import { useStore } from "../state/context.ts";
import type { BackupFile } from "../state/store.ts";

/**
 * Stretching a passphrase keeps the page busy for a moment: let "Working" be painted first.
 */
export function afterPaint(): Promise<void> {
  return new Promise((done) => requestAnimationFrame(() => setTimeout(done, 0)));
}

const BACKUP_WORDS: Record<BackupError["code"], MessageKey> = {
  NotABackup: "restore.error.notBackup",
  Newer: "restore.error.newer",
  WrongPassphrase: "restore.error.wrong",
  Invalid: "restore.error.invalid",
  Weak: "lock.tooShort",
  Empty: "backup.failed",
};

/** What went wrong with a passphrase or a backup file, in plain words. */
export function protectionError(error: unknown, fallback: MessageKey): string {
  if (error instanceof VaultError) {
    if (error.code === "WrongPassphrase") return t("lock.wrong");
    if (error.code === "Weak") return t("lock.tooShort");
    if (error.code === "TooSoon") {
      return t("lock.wait", { seconds: secondsUntil(error.retryAtMs) });
    }
  }
  if (error instanceof BackupError) return t(BACKUP_WORDS[error.code]);
  return t(fallback);
}

function secondsUntil(ms: number): number {
  return Math.max(1, Math.ceil((ms - Date.now()) / 1000));
}

/** Seconds left until `retryAtMs` (0: none), counting down. */
export function useCountdown(retryAtMs: number): number {
  const left = () => (retryAtMs > Date.now() ? secondsUntil(retryAtMs) : 0);
  const [seconds, setSeconds] = useState(left);
  useEffect(() => {
    setSeconds(left());
    if (retryAtMs <= Date.now()) return;
    const timer = setInterval(() => {
      const now = left();
      setSeconds(now);
      if (now === 0) clearInterval(timer);
    }, 500);
    return () => clearInterval(timer);
  }, [retryAtMs]);
  return seconds;
}

function PassphraseField({ label, value, onInput, testId, fresh = false, help, focus = false }: {
  label: string;
  value: string;
  onInput: (value: string) => void;
  testId: string;
  /** A passphrase being chosen (not one being entered). */
  fresh?: boolean;
  help?: string;
  focus?: boolean;
}) {
  const id = useId();
  const helpId = useId();
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (focus) input.current?.focus();
  }, []);
  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>{label}</label>
      <input
        id={id}
        ref={input}
        className="field__input"
        type="password"
        value={value}
        autoComplete={fresh ? "new-password" : "current-password"}
        autoCapitalize="off"
        spellcheck={false}
        aria-describedby={help ? helpId : undefined}
        data-testid={testId}
        onInput={(event) => onInput(event.currentTarget.value)}
      />
      {help && <span className="field__help" id={helpId}>{help}</span>}
    </div>
  );
}

/** A new passphrase, typed twice. `check` returns what is wrong with the pair, if anything. */
function useNewPassphrase() {
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const check = (): string | null => {
    if ([...first.normalize("NFKC")].length < MIN_PASSPHRASE) return t("lock.tooShort");
    if (first !== second) return t("lock.mismatch");
    return null;
  };
  return { first, second, setFirst, setSecond, check };
}

function NewPassphraseFields({ fields, label, prefix }: {
  fields: ReturnType<typeof useNewPassphrase>;
  label: string;
  prefix: string;
}) {
  return (
    <>
      <PassphraseField
        label={label}
        value={fields.first}
        onInput={fields.setFirst}
        testId={`${prefix}-new`}
        fresh
        help={t("lock.hint", { n: MIN_PASSPHRASE })}
      />
      <PassphraseField
        label={t("lock.again")}
        value={fields.second}
        onInput={fields.setSecond}
        testId={`${prefix}-again`}
        fresh
      />
    </>
  );
}

// ── Unlock ───────────────────────────────────────────────────────

/** The form of the unlock screen (src/screens/Start.tsx puts it on the page). */
export function UnlockForm({ retryAtMs }: { retryAtMs: number }) {
  const store = useStore();
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [wrong, setWrong] = useState(false);
  const waiting = useCountdown(retryAtMs);

  const submit = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    if (busy || waiting > 0 || passphrase === "") return;
    setBusy(true);
    setWrong(false);
    await afterPaint();
    try {
      await store.unlock(passphrase);
    } catch {
      setWrong(true);
      setPassphrase("");
    }
    setBusy(false);
  };

  const problem = waiting > 0 ? t("lock.wait", { seconds: waiting }) : wrong ? t("lock.wrong") : "";
  return (
    <form className="start__form" onSubmit={submit} noValidate data-testid="unlock-form">
      <PassphraseField
        label={t("unlock.label")}
        value={passphrase}
        onInput={setPassphrase}
        testId="unlock-passphrase"
        focus
      />
      <p className="field__problem" role="alert" data-testid="unlock-problem">{problem}</p>
      <p className="field__help" role="status" data-testid="unlock-working">
        {busy ? t("unlock.working") : ""}
      </p>
      <Button
        type="submit"
        variant="primary"
        testId="unlock-submit"
        disabled={busy || waiting > 0}
      >
        {t("unlock.submit")}
      </Button>
    </form>
  );
}

/** "Type the word to confirm", then delete everything: the same words as in Settings. */
export function ForgetSheet({ onClose }: { onClose: () => void }) {
  const store = useStore();
  const [typed, setTyped] = useState("");
  const word = t("settings.wipe.word");
  const ready = typed.trim().toLocaleLowerCase() === word.toLocaleLowerCase();
  return (
    <Sheet title={t("settings.wipe")} testId="sheet-forget" onClose={onClose}>
      <p>{t("unlock.forgot.body")}</p>
      <form
        className="sheet__form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) void store.forget();
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
            data-testid="forget-input"
            onInput={(event) => setTyped(event.currentTarget.value)}
          />
        </label>
        <Button type="submit" variant="danger" testId="forget-confirm" disabled={!ready}>
          {t("settings.wipe.confirm")}
        </Button>
      </form>
    </Sheet>
  );
}

// ── The lock, in Settings ────────────────────────────────────────

type LockSheet = "set" | "change" | "remove";

function LockSheetForm({ kind, onClose }: { kind: LockSheet; onClose: () => void }) {
  const store = useStore();
  const [current, setCurrent] = useState("");
  const fields = useNewPassphrase();
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState("");

  const submit = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    if (busy) return;
    const wrong = kind === "remove" ? null : fields.check();
    if (wrong) {
      setProblem(wrong);
      return;
    }
    setBusy(true);
    setProblem("");
    await afterPaint();
    try {
      if (kind === "set") await store.setPassphrase(fields.first);
      else if (kind === "change") await store.changePassphrase(current, fields.first);
      else await store.removePassphrase(current);
      showToast(t(
        kind === "set"
          ? "toast.lockSet"
          : kind === "change"
          ? "toast.lockChanged"
          : "toast.lockRemoved",
      ));
      onClose();
    } catch (error) {
      setProblem(protectionError(error, "lock.failed"));
      setBusy(false);
    }
  };

  const title = t(
    kind === "set"
      ? "settings.lock.set"
      : kind === "change"
      ? "settings.lock.change"
      : "settings.lock.remove",
  );
  return (
    <Sheet title={title} testId={`sheet-lock-${kind}`} onClose={onClose}>
      <form className="sheet__form" onSubmit={submit} noValidate>
        {kind === "remove" && <p>{t("settings.lock.removeBody")}</p>}
        {kind !== "set" && (
          <PassphraseField
            label={t("lock.current")}
            value={current}
            onInput={setCurrent}
            testId="lock-current"
          />
        )}
        {kind !== "remove" && (
          <>
            <NewPassphraseFields fields={fields} label={t("lock.new")} prefix="lock" />
            <p className="field__help" data-testid="lock-forgotten">{t("lock.forgotten")}</p>
          </>
        )}
        <p className="field__problem" role="alert" data-testid="lock-problem">{problem}</p>
        <p className="field__help" role="status">{busy ? t("lock.working") : ""}</p>
        <Button
          type="submit"
          variant={kind === "remove" ? "danger" : "primary"}
          testId="lock-submit"
          disabled={busy}
        >
          {title}
        </Button>
      </form>
    </Sheet>
  );
}

export function LockSetting() {
  const store = useStore();
  const [sheet, setSheet] = useState<LockSheet | null>(null);
  const on = store.passphraseSet.value;
  return (
    <div className="settings__item" data-testid="settings-lock" data-on={on ? "true" : "false"}>
      <h3 className="settings__item-title">{t("settings.lock.title")}</h3>
      <p className="field__help">{t("settings.lock.body")}</p>
      {on && <p data-testid="settings-lock-on">{t("settings.lock.on")}</p>}
      <div className="settings__actions">
        {on
          ? (
            <>
              <Button testId="lock-now" onClick={store.lock}>{t("settings.lock.now")}</Button>
              <Button
                testId="lock-change"
                onClick={() => setSheet("change")}
              >
                {t("settings.lock.change")}
              </Button>
              <Button
                testId="lock-remove"
                onClick={() =>
                  setSheet("remove")}
              >
                {t("settings.lock.remove")}
              </Button>
            </>
          )
          : (
            <Button
              testId="lock-set"
              onClick={() => setSheet("set")}
            >
              {t("settings.lock.set")}
            </Button>
          )}
      </div>
      {sheet && (
        <LockSheetForm
          kind={sheet}
          onClose={() => setSheet(null)}
        />
      )}
    </div>
  );
}

// ── Backup ───────────────────────────────────────────────────────

/** "parolnet-backup-2026-11-21.pnbackup", by this device's calendar. */
export function backupFileName(madeMs: number): string {
  const date = new Date(madeMs);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `parolnet-backup-${date.getFullYear()}-${pad(date.getMonth() + 1)}-${
    pad(date.getDate())
  }${BACKUP_EXTENSION}`;
}

export function BackupSheet({ onClose }: { onClose: () => void }) {
  const store = useStore();
  const fields = useNewPassphrase();
  const [history, setHistory] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState("");
  const [made, setMade] = useState<{ file: BackupFile; url: string } | null>(null);
  const historyHelp = useId();

  // The file lives in this page's memory behind the link; let it go with the sheet.
  useEffect(() => () => {
    if (made) URL.revokeObjectURL(made.url);
  }, [made]);

  const submit = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    if (busy) return;
    const wrong = fields.check();
    if (wrong) {
      setProblem(wrong);
      return;
    }
    setBusy(true);
    setProblem("");
    await afterPaint();
    try {
      const file = await store.makeBackup(fields.first, { history });
      const blob = new Blob([file.bytes as Uint8Array<ArrayBuffer>], {
        type: "application/octet-stream",
      });
      setMade({ file, url: URL.createObjectURL(blob) });
    } catch (error) {
      setProblem(protectionError(error, "backup.failed"));
    }
    setBusy(false);
  };

  return (
    <Sheet title={t("settings.backup.title")} testId="sheet-backup" onClose={onClose}>
      {made
        ? (
          <div className="sheet__form">
            <p role="status" data-testid="backup-ready">{t("backup.ready")}</p>
            {/* A link the person presses: the browser saves the file as a download. */}
            <a
              className="btn btn--primary"
              href={made.url}
              download={backupFileName(made.file.madeMs)}
              data-testid="backup-save"
            >
              {t("backup.save")}
            </a>
            <p className="field__help">{t("backup.forgotten")}</p>
            <p className="field__help">{t("backup.twoDevices")}</p>
          </div>
        )
        : (
          <form className="sheet__form" onSubmit={submit} noValidate>
            <p>{t("settings.backup.body")}</p>
            <NewPassphraseFields fields={fields} label={t("backup.passphrase")} prefix="backup" />
            <p className="field__help">{t("backup.forgotten")}</p>
            <div className="field">
              <label className="check">
                <input
                  type="checkbox"
                  className="check__box"
                  checked={history}
                  aria-describedby={historyHelp}
                  data-testid="backup-history"
                  onChange={(event) => setHistory(event.currentTarget.checked)}
                />
                <span>{t("backup.history")}</span>
              </label>
              <span className="field__help" id={historyHelp}>{t("backup.historyHelp")}</span>
            </div>
            <p className="field__problem" role="alert" data-testid="backup-problem">{problem}</p>
            <p className="field__help" role="status">{busy ? t("lock.working") : ""}</p>
            <Button type="submit" variant="primary" testId="backup-make" disabled={busy}>
              {t("backup.make")}
            </Button>
          </form>
        )}
    </Sheet>
  );
}

export function BackupSetting() {
  const store = useStore();
  const [open, setOpen] = useState(false);
  const last = store.lastBackupMs.value;
  return (
    <div className="settings__item" data-testid="settings-backup">
      <h3 className="settings__item-title">{t("settings.backup.title")}</h3>
      <p className="field__help">{t("settings.backup.body")}</p>
      <p data-testid="backup-last" data-made={last === null ? "never" : String(last)}>
        {last === null ? t("settings.backup.never") : t("settings.backup.last", {
          date: new Intl.DateTimeFormat(locale.value, { dateStyle: "long" }).format(last),
        })}
      </p>
      <Button testId="backup-open" onClick={() => setOpen(true)}>
        {t("settings.backup.title")}
      </Button>
      {open && <BackupSheet onClose={() => setOpen(false)} />}
    </div>
  );
}

// ── Restore ──────────────────────────────────────────────────────

/**
 * Choose a backup file and type its passphrase. `replaces`: this device has an identity that
 * the backup will replace, so a word must be typed first.
 */
export function RestoreSheet({ replaces, onClose }: { replaces: boolean; onClose: () => void }) {
  const store = useStore();
  const [file, setFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState("");
  const fileId = useId();
  const word = t("restore.word");
  const confirmed = !replaces || typed.trim().toLocaleLowerCase() === word.toLocaleLowerCase();

  const submit = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    if (busy || !confirmed) return;
    if (!file) {
      setProblem(t("restore.error.noFile"));
      return;
    }
    setBusy(true);
    setProblem("");
    await afterPaint();
    try {
      // On success the app starts over from the backup: this sheet goes with the page.
      await store.restore(new Uint8Array(await file.arrayBuffer()), passphrase);
    } catch (error) {
      setProblem(protectionError(error, "restore.failed"));
      setBusy(false);
    }
  };

  return (
    <Sheet title={t("restore.title")} testId="sheet-restore" onClose={onClose}>
      <form className="sheet__form" onSubmit={submit} noValidate>
        {replaces && <p data-testid="restore-replaces">{t("restore.replace")}</p>}
        <div className="field">
          <label className="field__label" htmlFor={fileId}>{t("restore.file")}</label>
          <input
            id={fileId}
            className="field__file"
            type="file"
            accept={`${BACKUP_EXTENSION},application/octet-stream`}
            data-testid="restore-file"
            onChange={(event) => setFile(event.currentTarget.files?.[0] ?? null)}
          />
        </div>
        <PassphraseField
          label={t("restore.passphrase")}
          value={passphrase}
          onInput={setPassphrase}
          testId="restore-passphrase"
        />
        <p className="field__help">{t("restore.sessions")}</p>
        <p className="field__help">{t("backup.twoDevices")}</p>
        {replaces && (
          <label className="field">
            <span className="field__label">{t("restore.confirmLabel", { word })}</span>
            <input
              className="field__input"
              value={typed}
              autoComplete="off"
              autoCapitalize="off"
              spellcheck={false}
              data-testid="restore-confirm-input"
              onInput={(event) => setTyped(event.currentTarget.value)}
            />
          </label>
        )}
        <p className="field__problem" role="alert" data-testid="restore-problem">{problem}</p>
        <p className="field__help" role="status">{busy ? t("lock.working") : ""}</p>
        <Button
          type="submit"
          variant={replaces ? "danger" : "primary"}
          testId="restore-submit"
          disabled={busy || !confirmed}
        >
          {t("restore.submit")}
        </Button>
      </form>
    </Sheet>
  );
}

export function RestoreSetting() {
  const [open, setOpen] = useState(false);
  return (
    <div className="settings__item" data-testid="settings-restore">
      <h3 className="settings__item-title">{t("restore.title")}</h3>
      <p className="field__help">{t("settings.restore.body")}</p>
      <Button testId="restore-open" onClick={() => setOpen(true)}>{t("restore.title")}</Button>
      {open && <RestoreSheet replaces onClose={() => setOpen(false)} />}
    </div>
  );
}
