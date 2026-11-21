// What the app says on its own to assistive technology (a message or a call arrived): one
// polite live region, rendered once at the root. See src/platform/notify.ts.
import { announcement } from "../platform/notify.ts";

export function Announcer() {
  const current = announcement.value;
  return (
    <div className="visually-hidden" role="status" aria-live="polite" data-testid="announcer">
      {current && <span key={current.id}>{current.text}</span>}
    </div>
  );
}
