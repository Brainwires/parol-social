// A message. Its form says where it is: outlined (dashed) while it is still on this device,
// filled once it is on theirs. Text, files and call invitations share the form.
import { useEffect, useId, useRef, useState } from "denext";
import { locale, t } from "../i18n/index.ts";
import type { MessageBody } from "../state/model.ts";
import { Icon } from "./Icon.tsx";

export type BubbleKind = "received" | "delivered" | "held" | "dropped";

/** "184 kB", "2.4 MB": decimal units, formatted for the locale. */
export function formatBytes(bytes: number, localeCode: string): string {
  const units = ["byte", "kilobyte", "megabyte", "gigabyte"] as const;
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  return new Intl.NumberFormat(localeCode, {
    style: "unit",
    unit: units[unit],
    unitDisplay: "short",
    maximumFractionDigits: value < 10 && unit > 0 ? 1 : 0,
  }).format(value);
}

function Body({ body }: { body: MessageBody }) {
  // The text is the writer's: its direction follows its own script, not the interface's.
  if (body.kind === "text") return <span className="bubble__text" dir="auto">{body.text}</span>;
  if (body.kind === "file") {
    return (
      <span className="bubble__attachment">
        <Icon name="file" />
        <span>
          <bdi>{body.name}</bdi>
          <span className="bubble__meta">
            {t("message.fileSize", { size: formatBytes(body.bytes, locale.value) })}
          </span>
        </span>
      </span>
    );
  }
  return (
    <span className="bubble__attachment">
      <Icon name={body.media === "video" ? "video" : "phone"} />
      <span>{t(body.media === "video" ? "message.videoInvite" : "message.voiceInvite")}</span>
    </span>
  );
}

function className(kind: BubbleKind, tail: "start" | "end" | null): string {
  return `bubble bubble--${kind}${tail ? ` bubble--tail-${tail}` : ""}`;
}

export function Bubble({ kind, body, tail = null, fill = false, testId }: {
  kind: BubbleKind;
  body: MessageBody;
  /** The corner that points at the sender, on the last bubble of a group. */
  tail?: "start" | "end" | null;
  /** This bubble takes part in the fill animation (it was waiting when the line opened). */
  fill?: boolean;
  testId: string;
}) {
  return (
    <div
      className={className(kind, tail)}
      data-fill={fill ? "" : undefined}
      data-testid={testId}
      data-kind={kind}
    >
      <Body body={body} />
    </div>
  );
}

/**
 * A waiting message is a button: it opens a menu with "Take back" and "Edit" (edit only for
 * text). Arrow keys move in the menu, Escape closes it and returns to the bubble.
 */
export function HeldBubble({ body, tail = null, onTakeBack, onEdit, testId }: {
  body: MessageBody;
  tail?: "start" | "end" | null;
  onTakeBack: () => void;
  onEdit?: () => void;
  testId: string;
}) {
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const takeBack = useRef<HTMLButtonElement>(null);
  const edit = useRef<HTMLButtonElement>(null);
  const hintId = useId();

  useEffect(() => {
    if (!open) return;
    takeBack.current?.focus();
    const outside = (event: Event) => {
      if (!anchor.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", outside);
    return () => document.removeEventListener("pointerdown", outside);
  }, [open]);

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) button.current?.focus();
  };

  const onMenuKey = (event: { key: string; preventDefault(): void }) => {
    if (event.key === "Escape") {
      event.preventDefault();
      close(true);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      // Two items at most: either arrow moves to the other one.
      event.preventDefault();
      const other = document.activeElement === takeBack.current ? edit.current : takeBack.current;
      (other ?? takeBack.current)?.focus();
    } else if (event.key === "Tab") {
      setOpen(false);
    }
  };

  const choose = (action: () => void) => () => {
    close(false);
    action();
  };

  return (
    <div className="thread__anchor" ref={anchor}>
      <button
        type="button"
        ref={button}
        className={className("held", tail)}
        aria-haspopup="menu"
        aria-expanded={open ? "true" : "false"}
        aria-describedby={hintId}
        data-testid={testId}
        data-kind="held"
        onClick={() => setOpen(!open)}
      >
        <Body body={body} />
      </button>
      <span className="visually-hidden" id={hintId}>{t("message.heldHint")}</span>
      {open && (
        <div className="menu" role="menu" onKeyDown={onMenuKey} data-testid={`${testId}-menu`}>
          <button
            type="button"
            role="menuitem"
            ref={takeBack}
            className="menu__item"
            data-testid={`${testId}-take-back`}
            onClick={choose(onTakeBack)}
          >
            {t("message.takeBack")}
          </button>
          {onEdit && (
            <button
              type="button"
              role="menuitem"
              ref={edit}
              className="menu__item"
              data-testid={`${testId}-edit`}
              onClick={choose(onEdit)}
            >
              {t("message.edit")}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
