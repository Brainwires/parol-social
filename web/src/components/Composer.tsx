// The composer is never disabled because the contact is away: what is written waits on this
// device, and the placeholder says so.
import { useEffect, useLayoutEffect, useRef, useState } from "denext";
import { t } from "../i18n/index.ts";
import { Button, IconButton } from "./Button.tsx";

export type ComposerState =
  /** The line is open: what is written goes at once. */
  | "open"
  /** The contact is away (or this device is offline): what is written waits here. */
  | "away"
  /** The contact is online but there is no path to them: it waits for one. */
  | "no-path";

const PLACEHOLDER = {
  "open": "composer.placeholder",
  "away": "composer.placeholderAway",
  "no-path": "composer.placeholderNoPath",
} as const;

export function Composer(
  { name, state, editingText = null, onSend, onSaveEdit, onCancelEdit, onAttach, preparing = [] }: {
    name: string;
    state: ComposerState;
    /** The text of the waiting message being edited, or null when writing a new one. */
    editingText?: string | null;
    /** May reject: the text then stays in the field and the caller says why. */
    onSend: (text: string) => Promise<void> | void;
    onSaveEdit?: (text: string) => Promise<void> | void;
    onCancelEdit?: () => void;
    /** The person chose files to send. Without it there is no attach button. */
    onAttach?: (files: File[]) => void;
    /** Names of the files being read before they are offered: "Preparing {name}…". */
    preparing?: readonly string[];
  },
) {
  const [text, setText] = useState("");
  const field = useRef<HTMLTextAreaElement>(null);
  const picker = useRef<HTMLInputElement>(null);
  const editing = editingText !== null;

  useEffect(() => {
    if (editingText === null) return;
    setText(editingText);
    field.current?.focus();
  }, [editingText]);

  // Firefox and Safari have no `field-sizing: content` yet: size the field to its text, or
  // to its placeholder while it is empty, through the CSSOM (the CSP allows no style
  // attribute in markup, and this is not one).
  useLayoutEffect(() => {
    const el = field.current;
    if (!el?.style || typeof CSS === "undefined" || CSS.supports("field-sizing", "content")) return;
    const fit = () => {
      const empty = el.value === "";
      if (empty) el.value = el.placeholder;
      el.style.height = "auto";
      el.style.height = `${el.scrollHeight + el.offsetHeight - el.clientHeight}px`;
      if (empty) el.value = "";
    };
    fit();
    addEventListener("resize", fit);
    return () => removeEventListener("resize", fit);
  }, [text, name, state]);

  // The field empties at once, so what is typed next is a new message. If the message could
  // not be sent it comes back, unless something else has been written meanwhile.
  const submit = async () => {
    const value = text.trim();
    if (!value) return;
    setText("");
    try {
      await (editing ? onSaveEdit?.(value) : onSend(value));
    } catch {
      setText((now) => (now === "" ? value : now));
    }
  };

  const cancel = () => {
    setText("");
    onCancelEdit?.();
  };

  return (
    <form
      className="composer"
      data-testid="composer"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      {editing && (
        <div className="composer__editing">
          <span>{t("composer.editing")}</span>
          <Button testId="composer-cancel-edit" onClick={cancel}>{t("composer.cancelEdit")}</Button>
        </div>
      )}
      {preparing.map((file, index) => (
        <p
          key={`${index}:${file}`}
          className="composer__preparing"
          role="status"
          data-testid="composer-preparing"
        >
          {t("composer.preparing", { name: file })}
        </p>
      ))}
      <div className="composer__row">
        {onAttach && (
          <>
            <IconButton
              icon="attach"
              label={t("composer.attach")}
              testId="composer-attach"
              onClick={() => picker.current?.click()}
            />
            {/* Always in the page, so it can be given files directly; the button opens it. */}
            <input
              ref={picker}
              type="file"
              multiple
              hidden
              tabIndex={-1}
              aria-hidden="true"
              data-testid="composer-file"
              onChange={(event) => {
                const input = event.currentTarget;
                const files = [...(input.files ?? [])];
                // Choosing the same file again is a new choice.
                input.value = "";
                if (files.length > 0) onAttach(files);
              }}
            />
          </>
        )}
        <textarea
          ref={field}
          className="composer__field"
          rows={1}
          // What is typed takes the direction of its own script; the placeholder keeps the
          // interface's.
          dir={text ? "auto" : undefined}
          value={text}
          aria-label={t("composer.label", { name })}
          placeholder={t(PLACEHOLDER[state], { name })}
          data-testid="composer-input"
          onInput={(event) => setText(event.currentTarget.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
              event.preventDefault();
              void submit();
            } else if (event.key === "Escape" && editing) {
              cancel();
            }
          }}
        />
        <IconButton
          icon="send"
          label={editing ? t("composer.save") : t("composer.send")}
          testId="composer-send"
          type="submit"
          filled
        />
      </div>
    </form>
  );
}
