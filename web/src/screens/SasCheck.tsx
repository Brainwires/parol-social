// The verification code of a contact that is being added (the Short Authentication String of
// PNP-003 §5.5). Both devices show the same code unless someone sits between them, so the two
// people compare it, by voice or in person, and each says whether it matches. The contact is
// added once both said yes; "They don't match" drops it.
import { useState } from "denext";
import { Button } from "../components/Button.tsx";
import { Screen } from "../components/Screen.tsx";
import { t } from "../i18n/index.ts";
import { useStore } from "../state/context.ts";
import type { SasCheck as Sas } from "../state/model.ts";
import { errorText } from "./errors.ts";

/** The six digits in two groups of three. */
export function sasSpaced(digits: string): string {
  return digits.length === 6 ? `${digits.slice(0, 3)} ${digits.slice(3)}` : digits;
}

export function SasPanel({ sas }: { sas: Sas }) {
  const store = useStore();
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  const answer = async (matches: boolean) => {
    if (busy) return;
    setBusy(true);
    setProblem(null);
    try {
      await (matches ? store.confirmSas(sas.peerId) : store.rejectSas(sas.peerId));
    } catch (error) {
      setProblem(errorText(error, {}, "pair.failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="sas" data-testid="sas" data-confirmed={sas.confirmed ? "true" : "false"}>
      <p data-testid="sas-body">{t("sas.body")}</p>
      {/* Codes run left to right in every language. */}
      <p
        className="sas__digits"
        role="group"
        aria-label={t("sas.digitsLabel")}
        dir="ltr"
        data-testid="sas-digits"
        data-digits={sas.digits}
      >
        {sasSpaced(sas.digits)}
      </p>
      <p
        className="sas__emoji"
        role="group"
        aria-label={t("sas.emojiLabel")}
        dir="ltr"
        data-testid="sas-emoji"
      >
        {[...sas.emoji].map((picture, i) => <span key={i}>{picture}</span>)}
      </p>
      {sas.confirmed ? <p role="status" data-testid="sas-waiting">{t("sas.waiting")}</p> : (
        <>
          <p className="sas__warning" data-testid="sas-warning">{t("sas.warning")}</p>
          <div className="pairing__actions">
            <Button
              variant="primary"
              testId="sas-match"
              disabled={busy}
              onClick={() => void answer(true)}
            >
              {t("sas.match")}
            </Button>
            <Button
              variant="danger"
              testId="sas-no-match"
              disabled={busy}
              onClick={() => void answer(false)}
            >
              {t("sas.noMatch")}
            </Button>
          </div>
        </>
      )}
      <p className="field__problem" role="alert" data-testid="sas-problem">{problem ?? ""}</p>
    </div>
  );
}

/** The code as a screen of its own, wherever the person is when it has to be compared. */
export function SasScreen({ sas }: { sas: Sas }) {
  return (
    <Screen title={t("sas.title")} testId="sas-screen" focusKey={sas.peerId}>
      <div className="pairing">
        <SasPanel key={sas.peerId} sas={sas} />
      </div>
    </Screen>
  );
}
