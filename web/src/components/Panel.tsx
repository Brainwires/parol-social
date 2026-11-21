import { type ReactNode, useId } from "denext";

export interface PanelAction {
  label: string;
  testId: string;
  onClick: () => void;
  primary?: boolean;
}

/**
 * Says what happened and why, and offers the one or two things that fix it. Amber for waiting
 * or held, red for blocked for safety; plain (ink outline) for a notice that is neither.
 */
export function Panel({ tone, title, children, actions = [], testId }: {
  tone: "amber" | "red" | "plain";
  title: string;
  children?: ReactNode;
  /** At most two. */
  actions?: readonly PanelAction[];
  testId: string;
}) {
  const titleId = useId();
  return (
    <section className={`panel panel--${tone}`} aria-labelledby={titleId} data-testid={testId}>
      <h2 className="panel__title" id={titleId}>{title}</h2>
      {children && <p className="panel__body">{children}</p>}
      {actions.length > 0 && (
        <div className="panel__actions">
          {actions.slice(0, 2).map((action) => (
            <button
              key={action.testId}
              type="button"
              className={action.primary ? "btn btn--primary" : "btn btn--quiet"}
              data-testid={action.testId}
              onClick={action.onClick}
            >
              {action.label}
            </button>
          ))}
        </div>
      )}
    </section>
  );
}
