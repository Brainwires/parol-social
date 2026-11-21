// The line: the one status of a conversation, in words, with a glyph of two ends and a wire.
// The near end (inline start) is this device, the far end is theirs. Each state has its own
// line style as well as its own colour and words, so it never depends on colour alone.
import { type MessageKey, t } from "../i18n/index.ts";
import type { LineState } from "../state/model.ts";

const TEXT: Record<LineState, MessageKey> = {
  "open": "line.open",
  "waiting": "line.waiting",
  "connecting": "line.connecting",
  "no-path": "line.noPath",
  "blocked": "line.blocked",
  "self-offline": "line.selfOffline",
};

export function lineText(state: LineState, name: string): string {
  return t(TEXT[state], { name });
}

export function Line({ state, name, testId = "line" }: {
  state: LineState;
  /** The contact's name, for the states that name them. */
  name: string;
  testId?: string;
}) {
  return (
    <div
      className={`line line--${state}`}
      role="status"
      aria-live="polite"
      data-testid={testId}
      data-state={state}
    >
      <span className="line__glyph" aria-hidden="true">
        <span className="line__end line__end--near" />
        <span className="line__wire" />
        {state === "no-path" && <span className="line__gap" />}
        {state === "no-path" && <span className="line__wire" />}
        <span className="line__end line__end--far" />
      </span>
      <span className="line__text">{lineText(state, name)}</span>
    </div>
  );
}
