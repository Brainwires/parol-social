// The screens before (and instead of) the app: loading, first run, "open in another tab",
// and "could not start".
import { useEffect, useRef, useState } from "denext";
import { Button } from "../components/Button.tsx";
import { UpdateNotice } from "../components/UpdateNotice.tsx";
import { t } from "../i18n/index.ts";
import { wasmStatus } from "../platform/wasm.ts";
import { navigate } from "../router.ts";
import { useStore } from "../state/context.ts";
import { ForgetSheet, RestoreSheet, UnlockForm } from "./Protection.tsx";

/** Reserved height, so nothing moves when encryption is ready. */
export function Loading() {
  const status = wasmStatus.value;
  const percent = status.state === "ready"
    ? 100
    : status.state === "loading" && status.total > 0
    ? Math.floor((status.loaded / status.total) * 100)
    : 0;
  return (
    <main className="start" data-testid="loading">
      <h1 className="start__name">ParolNet</h1>
      <p className="start__status" role="status" data-testid="loading-status">
        {t("boot.loading", { percent })}
      </p>
    </main>
  );
}

export function FirstRun() {
  const store = useStore();
  const [starting, setStarting] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, []);

  const start = async () => {
    if (starting) return;
    setStarting(true);
    // Straight to adding a contact: there is nothing else to do with no one to talk to.
    navigate({ name: "add" });
    await store.begin();
    setStarting(false);
  };

  return (
    <main className="start" data-testid="first-run">
      <h1 className="start__name" tabIndex={-1} ref={heading}>ParolNet</h1>
      <p className="start__lead">{t("firstRun.lead")}</p>
      <p className="start__body">{t("firstRun.body")}</p>
      <Button variant="primary" testId="first-run-start" disabled={starting} onClick={start}>
        {t("firstRun.start")}
      </Button>
      <Button testId="first-run-restore" onClick={() => setRestoring(true)}>
        {t("firstRun.restore")}
      </Button>
      {restoring && <RestoreSheet replaces={false} onClose={() => setRestoring(false)} />}
      <UpdateNotice />
    </main>
  );
}

/** What is on this device is locked with a passphrase: ask for it. */
export function Locked({ retryAtMs }: { retryAtMs: number }) {
  const [forgetting, setForgetting] = useState(false);
  return (
    <main className="start" data-testid="locked">
      <h1 className="start__title">{t("unlock.title")}</h1>
      <UnlockForm retryAtMs={retryAtMs} />
      <Button testId="unlock-forgot" onClick={() => setForgetting(true)}>
        {t("unlock.forgot")}
      </Button>
      {forgetting && <ForgetSheet onClose={() => setForgetting(false)} />}
      <UpdateNotice />
    </main>
  );
}

export function OtherTab({ moved }: { moved: boolean }) {
  const store = useStore();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, [moved]);
  return (
    <main className="start" data-testid="other-tab" data-moved={moved ? "true" : "false"}>
      <h1 className="start__title" tabIndex={-1} ref={heading}>
        {t(moved ? "otherTab.movedTitle" : "otherTab.title")}
      </h1>
      <p className="start__body">{t(moved ? "otherTab.movedBody" : "otherTab.body")}</p>
      <Button variant="primary" testId="other-tab-use-here" onClick={store.takeOver}>
        {t("otherTab.useHere")}
      </Button>
      <UpdateNotice />
    </main>
  );
}

export function StartFailed({ reason }: { reason: "core" | "storage" }) {
  return (
    <main className="start" data-testid="start-failed" data-reason={reason}>
      <h1 className="start__title">
        {t(reason === "core" ? "boot.failed.core.title" : "boot.failed.storage.title")}
      </h1>
      <p className="start__body" role="alert">
        {t(reason === "core" ? "boot.failed.core.body" : "boot.failed.storage.body")}
      </p>
      <Button variant="primary" testId="start-retry" onClick={() => location.reload()}>
        {t("action.tryAgain")}
      </Button>
    </main>
  );
}
