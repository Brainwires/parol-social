// A toast only confirms something the person just did ("Message taken back"). Anything the
// app has to report on its own goes on the line or in a panel, never here.
import { signal } from "denext/signals";

const TOAST_MS = 4000;
const current = signal<{ id: number; text: string } | null>(null);
let timer: ReturnType<typeof setTimeout> | undefined;
let nextId = 0;

export function showToast(text: string): void {
  clearTimeout(timer);
  const id = ++nextId;
  current.value = { id, text };
  timer = setTimeout(() => {
    if (current.value?.id === id) current.value = null;
  }, TOAST_MS);
}

/** Render once, at the root. A polite live region, so the confirmation is also spoken. */
export function ToastHost() {
  const toast = current.value;
  return (
    <div className="toast-host" role="status" aria-live="polite" data-testid="toast-host">
      {toast && <div className="toast" key={toast.id} data-testid="toast">{toast.text}</div>}
    </div>
  );
}
