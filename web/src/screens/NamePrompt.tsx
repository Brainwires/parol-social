// A contact without a name, in its conversation: usually someone who used this device's code
// while the person was on another screen. One line asks for a name; it blocks nothing, takes
// no focus, and "Not now" puts it away for this visit (the row keeps saying "New contact").
import { useState } from "denext";
import { Button } from "../components/Button.tsx";
import { showToast } from "../components/Toast.tsx";
import { requestPersistentStorage } from "../engine/browser.ts";
import { t } from "../i18n/index.ts";
import { keepStorage } from "../platform/install.ts";
import { useStore } from "../state/context.ts";
import { dismissNamePrompt, wasAddedHere } from "../state/names.ts";
import { errorText } from "./errors.ts";

export function NamePrompt({ peerId }: { peerId: string }) {
  const store = useStore();
  const [name, setName] = useState("");
  const [problem, setProblem] = useState<string | null>(null);

  const save = async (event: { preventDefault(): void }) => {
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
    // As on "Add a contact": the identity now matters to someone else.
    void keepStorage(requestPersistentStorage);
    showToast(t("toast.contactAdded", { name: chosen }));
  };

  return (
    <form
      className="conversation__name-prompt"
      onSubmit={save}
      noValidate
      data-testid="name-prompt"
    >
      <p className="conversation__name-prompt-text" data-testid="name-prompt-text">
        {t(wasAddedHere(peerId) ? "name.promptAdded" : "name.promptTheirs")}
      </p>
      <div className="conversation__name-prompt-row">
        <label className="field conversation__name-prompt-field">
          <span className="field__label">{t("name.label")}</span>
          <input
            className="field__input"
            value={name}
            autoComplete="off"
            maxLength={80}
            data-testid="name-prompt-input"
            onInput={(event) => setName(event.currentTarget.value)}
          />
        </label>
        <Button type="submit" variant="primary" testId="name-prompt-save">
          {t("action.save")}
        </Button>
        <button
          type="button"
          className="link-btn"
          data-testid="name-prompt-later"
          onClick={() => dismissNamePrompt(peerId)}
        >
          {t("name.later")}
        </button>
      </div>
      <p className="field__help">{t("name.hint")}</p>
      <p className="field__problem" role="alert" data-testid="name-prompt-problem">
        {problem ?? ""}
      </p>
    </form>
  );
}
