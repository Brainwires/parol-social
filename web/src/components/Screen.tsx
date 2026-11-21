// A full screen beside (or, on a phone, on top of) the list: a header with a way back and a
// title that takes focus on arrival, then a scrolling body.
import { type ReactNode, useEffect, useRef } from "denext";
import { t } from "../i18n/index.ts";
import { hrefOf } from "../router.ts";
import { Icon } from "./Icon.tsx";

export function Screen({ title, testId, focusKey, focusTitle = true, children }: {
  title: string;
  testId: string;
  /** Focus returns to the title whenever this changes (a new step of the same screen). */
  focusKey?: string;
  /** False for a step that puts focus in a field of its own. */
  focusTitle?: boolean;
  children: ReactNode;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (focusTitle) heading.current?.focus();
  }, [focusKey]);

  return (
    <div className="screen" data-testid={testId}>
      <header className="screen__header">
        <a
          className="icon-btn conversation__back"
          href={hrefOf({ name: "list" })}
          aria-label={t("action.back")}
          data-testid={`${testId}-back`}
        >
          <Icon name="back" />
        </a>
        <h1 className="screen__title" tabIndex={-1} ref={heading} data-testid={`${testId}-title`}>
          {title}
        </h1>
      </header>
      <div className="screen__body">
        <div className="screen__content">{children}</div>
      </div>
    </div>
  );
}
