// The ringing sound: a tone made here with Web Audio, so no sound file ships. It plays only
// once the person has interacted with the page (browsers refuse audio before that, and a
// page should not make noise unasked).
type Kind = "incoming" | "outgoing";

/** Seconds: [tone, silence] pairs of one cycle. */
const PATTERN: Record<Kind, { hz: number; cycle: number[] }> = {
  incoming: { hz: 520, cycle: [0.35, 0.2, 0.35, 1.6] },
  outgoing: { hz: 425, cycle: [1, 3] },
};

let stopCurrent: (() => void) | null = null;

function interacted(): boolean {
  const activation = (navigator as { userActivation?: { hasBeenActive: boolean } }).userActivation;
  // Without the API (Firefox before 120) assume not: silence is the safe side.
  return activation?.hasBeenActive === true;
}

export function startRinging(kind: Kind): void {
  stopRinging();
  if (typeof AudioContext === "undefined" || !interacted()) return;
  let context: AudioContext;
  try {
    context = new AudioContext();
  } catch {
    return;
  }
  const gain = context.createGain();
  gain.gain.value = 0;
  gain.connect(context.destination);
  const tone = context.createOscillator();
  tone.type = "sine";
  tone.frequency.value = PATTERN[kind].hz;
  tone.connect(gain);
  tone.start();

  const { cycle } = PATTERN[kind];
  const length = cycle.reduce((sum, part) => sum + part, 0);
  // Schedule a few cycles ahead, again and again, until stopped.
  let next = context.currentTime + 0.05;
  const schedule = () => {
    while (next < context.currentTime + 2 * length) {
      let at = next;
      for (let i = 0; i < cycle.length; i += 2) {
        gain.gain.setValueAtTime(0, at);
        gain.gain.linearRampToValueAtTime(0.12, at + 0.02);
        gain.gain.setValueAtTime(0.12, at + cycle[i] - 0.02);
        gain.gain.linearRampToValueAtTime(0, at + cycle[i]);
        at += cycle[i] + cycle[i + 1];
      }
      next += length;
    }
  };
  schedule();
  const timer = setInterval(schedule, 1000);
  stopCurrent = () => {
    clearInterval(timer);
    try {
      tone.stop();
    } catch { /* already stopped */ }
    void context.close().catch(() => {});
  };
}

export function stopRinging(): void {
  stopCurrent?.();
  stopCurrent = null;
}
