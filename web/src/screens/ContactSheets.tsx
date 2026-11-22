// The sheets a conversation opens about its contact: details (name, verification, removal),
// comparing safety numbers, and the confirmation before a contact is removed.
import { useState } from "denext";
import { Button } from "../components/Button.tsx";
import { SafetyNumber } from "../components/Codes.tsx";
import { Sheet } from "../components/Sheet.tsx";
import { showToast } from "../components/Toast.tsx";
import { type MessageKey, t } from "../i18n/index.ts";
import { useStore } from "../state/context.ts";
import type { ContactView, Verification } from "../state/model.ts";
import { shownName } from "../state/names.ts";
import { errorText } from "./errors.ts";

const VERIFIED: Record<Verification, MessageKey> = {
  "in-person": "details.verifiedInPerson",
  "compared": "details.verifiedCompared",
  "no": "details.notVerified",
};

export function ContactDetailsSheet({ view, onClose, onVerify, onRemove }: {
  view: ContactView;
  onClose: () => void;
  onVerify: () => void;
  onRemove: () => void;
}) {
  const store = useStore();
  const { contact } = view;
  const [name, setName] = useState(contact.name);
  const [problem, setProblem] = useState<string | null>(null);

  const save = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    const next = name.trim();
    if (!next) {
      setProblem(t("name.empty"));
      return;
    }
    try {
      await store.rename(contact.peerId, next);
      showToast(t("toast.renamed"));
      onClose();
    } catch (error) {
      setProblem(errorText(error));
    }
  };

  return (
    <Sheet title={t("details.title")} testId="sheet-details" onClose={onClose}>
      <form className="sheet__form" onSubmit={save} noValidate>
        <label className="field">
          <span className="field__label">{t("name.label")}</span>
          <input
            className="field__input"
            value={name}
            autoComplete="off"
            maxLength={80}
            data-testid="details-name"
            onInput={(event) => setName(event.currentTarget.value)}
          />
          <span className="field__help">{t("name.hint")}</span>
        </label>
        <p className="field__problem" role="alert" data-testid="details-problem">
          {problem ?? ""}
        </p>
        <Button type="submit" variant="primary" testId="details-save">
          {t("details.saveName")}
        </Button>
      </form>
      <div className="sheet__section">
        <p
          data-testid="details-verified"
          data-verified={contact.verified}
          data-sas={contact.sasVerified ? "true" : "false"}
        >
          {t(
            contact.verified === "no" && contact.sasVerified
              ? "details.verifiedSas"
              : VERIFIED[contact.verified],
          )}
        </p>
        <Button testId="details-verify" onClick={onVerify}>{t("verify.open")}</Button>
      </div>
      <div className="sheet__section">
        <Button variant="danger" testId="details-remove" onClick={onRemove}>
          {t("details.remove")}
        </Button>
      </div>
    </Sheet>
  );
}

export function VerifySheet({ view, onClose, onRemoved }: {
  view: ContactView;
  onClose: () => void;
  /** The contact was removed after a mismatch: go and add them again. */
  onRemoved: () => void;
}) {
  const store = useStore();
  const { contact } = view;
  const name = shownName(contact);
  const [mismatch, setMismatch] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const digits = store.safetyNumber(contact.peerId);

  const match = async () => {
    try {
      await store.setCompared(contact.peerId, true);
      showToast(t("verify.done", { name }));
      onClose();
    } catch (error) {
      setProblem(errorText(error));
    }
  };

  const noMatch = async () => {
    // Whatever was recorded before, these numbers were just seen to differ.
    try {
      await store.setCompared(contact.peerId, false);
    } catch { /* the explanation matters more than the record */ }
    setMismatch(true);
  };

  const remove = async () => {
    try {
      await store.removeContact(contact.peerId);
      showToast(t("toast.contactRemoved", { name }));
      onRemoved();
    } catch (error) {
      setProblem(errorText(error));
    }
  };

  if (mismatch) {
    return (
      <Sheet title={t("verify.mismatch.title")} testId="sheet-verify" onClose={onClose}>
        <p data-testid="verify-mismatch">{t("verify.mismatch.body", { name })}</p>
        <p className="field__problem" role="alert">{problem ?? ""}</p>
        <div className="sheet__actions">
          <Button variant="danger" testId="verify-remove" onClick={remove}>
            {t("verify.mismatch.remove")}
          </Button>
          <Button testId="verify-back" onClick={() => setMismatch(false)}>
            {t("verify.mismatch.back")}
          </Button>
        </div>
      </Sheet>
    );
  }

  return (
    <Sheet title={t("verify.title")} testId="sheet-verify" onClose={onClose}>
      <p>{t("verify.body", { name })}</p>
      {digits
        ? <SafetyNumber digits={digits} label={t("safety.label")} testId="safety-number" />
        : <p role="alert" data-testid="verify-unavailable">{t("verify.unavailable")}</p>}
      <p className="field__problem" role="alert">{problem ?? ""}</p>
      {digits && (
        <div className="sheet__actions">
          <Button variant="primary" testId="verify-match" onClick={match}>
            {t("verify.match")}
          </Button>
          <Button testId="verify-no-match" onClick={noMatch}>{t("verify.noMatch")}</Button>
        </div>
      )}
    </Sheet>
  );
}

export function RemoveContactSheet({ view, onClose, onRemoved }: {
  view: ContactView;
  onClose: () => void;
  onRemoved: () => void;
}) {
  const store = useStore();
  const name = shownName(view.contact);
  const [problem, setProblem] = useState<string | null>(null);

  const remove = async () => {
    try {
      await store.removeContact(view.contact.peerId);
      showToast(t("toast.contactRemoved", { name }));
      onRemoved();
    } catch (error) {
      setProblem(errorText(error));
    }
  };

  return (
    <Sheet title={t("remove.title", { name })} testId="sheet-remove" onClose={onClose}>
      <p>{t("remove.body", { name })}</p>
      <p className="field__problem" role="alert">{problem ?? ""}</p>
      <div className="sheet__actions">
        <Button variant="danger" testId="remove-confirm" onClick={remove}>
          {t("remove.confirm")}
        </Button>
        <Button testId="remove-cancel" onClick={onClose}>{t("action.cancel")}</Button>
      </div>
    </Sheet>
  );
}
