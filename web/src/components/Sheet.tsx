// A modal dialog on the native <dialog>: the browser traps focus inside it, closes it on
// Escape, makes the rest of the page inert and gives focus back to what opened it.
import { type ReactNode, useEffect, useId, useRef } from "denext";
import { t } from "../i18n/index.ts";
import { IconButton } from "./Button.tsx";

export function Sheet({ title, onClose, children, testId }: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  testId: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  // Closing the dialog on unmount fires its `close` event a moment later; by then another
  // sheet may be open, and that event must not close it.
  const gone = useRef(false);

  useEffect(() => {
    const dialog = ref.current;
    gone.current = false;
    if (!dialog || dialog.open || typeof dialog.showModal !== "function") return;
    dialog.showModal();
    return () => {
      gone.current = true;
      if (dialog.open) dialog.close();
    };
  }, []);

  return (
    <dialog
      ref={ref}
      className="sheet"
      aria-labelledby={titleId}
      data-testid={testId}
      onClose={() => {
        if (!gone.current) onClose();
      }}
      onClick={(event: { target: EventTarget | null }) => {
        // A click on the backdrop lands on the dialog element itself.
        if (event.target === ref.current) onClose();
      }}
    >
      <div className="sheet__header">
        <h2 className="sheet__title" id={titleId}>{title}</h2>
        <IconButton
          icon="close"
          label={t("action.close")}
          testId={`${testId}-close`}
          onClick={onClose}
        />
      </div>
      <div className="sheet__body">{children}</div>
    </dialog>
  );
}
