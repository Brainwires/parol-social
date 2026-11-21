// The composer is never disabled because the contact is away: what is written waits on this
// device, and the placeholder says so.
import { useEffect, useLayoutEffect, useRef, useState } from "denext";
import { t } from "../i18n/index.ts";
import { Button, IconButton } from "./Button.tsx";

export function Composer({ name, away, editingText = null, onSend, onSaveEdit, onCancelEdit }: {
  name: string;
  /** The line is not open: a message written now waits here. */
  away: boolean;
  /** The text of the waiting message being edited, or null when writing a new one. */
  editingText?: string | null;
  onSend: (text: string) => void;
  onSaveEdit?: (text: string) => void;
  onCancelEdit?: () => void;
}) {
  const [text, setText] = useState("");
  const field = useRef<HTMLTextAreaElement>(null);
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
  }, [text, name, away]);

  const submit = () => {
    const value = text.trim();
    if (!value) return;
    if (editing) onSaveEdit?.(value);
    else onSend(value);
    setText("");
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
        submit();
      }}
    >
      {editing && (
        <div className="composer__editing">
          <span>{t("composer.editing")}</span>
          <Button testId="composer-cancel-edit" onClick={cancel}>{t("composer.cancelEdit")}</Button>
        </div>
      )}
      <div className="composer__row">
        <textarea
          ref={field}
          className="composer__field"
          rows={1}
          // What is typed takes the direction of its own script; the placeholder keeps the
          // interface's.
          dir={text ? "auto" : undefined}
          value={text}
          aria-label={t("composer.label", { name })}
          placeholder={t(away ? "composer.placeholderAway" : "composer.placeholder", { name })}
          data-testid="composer-field"
          onInput={(event) => setText(event.currentTarget.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
              event.preventDefault();
              submit();
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
