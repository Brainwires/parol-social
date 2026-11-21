// Re-probing contacts the relay called offline (PNP-001-SHOULD-019). A port of
// crates/parolnet-app/src/reconnect.rs; times are milliseconds.
//
// The relay pushes presence only between mutual watchers and keeps at most 256 watched ids.
// A contact who does not watch us back (yet), one beyond that limit, or one whose push we
// missed is only known to be offline from the `peer_offline` answer to an offer. That verdict
// goes stale silently, so it is soft: the contact is offered to again with exponential
// backoff and jitter, whether or not messages wait for it. An offline verdict from a presence
// push is not handled here: the relay will say when it changes.
//
// Every probe is an `rtc_offer`, which the relay meters, so all probes draw on one token
// bucket sized well under the relay's caps. Pure scheduling: the caller passes time and jitter.

/** Jitter added to every delay: up to this share of it. */
const JITTER = 0.25;

export interface ReconnectConfig {
  /** The delay before the first probe after a `peer_offline` answer. */
  firstProbeMs: number;
  /** The longest delay between probes of a contact the user is waiting for. */
  maxProbeActiveMs: number;
  /** The longest delay between probes of any other contact. */
  maxProbeIdleMs: number;
  /** Probes that may go out in a burst (the token bucket's size). */
  probeBurst: number;
  /** One more probe is allowed per this interval. */
  probeRefillMs: number;
}

export const DEFAULT_RECONNECT: ReconnectConfig = {
  firstProbeMs: 15_000,
  maxProbeActiveMs: 5 * 60_000,
  maxProbeIdleMs: 15 * 60_000,
  probeBurst: 12,
  probeRefillMs: 60_000,
};

/**
 * The delay before probe number `probesSent` (0 for the first): `firstProbeMs` doubled each
 * time up to the cap for the contact's kind, plus `jitter` (0..1) of a quarter.
 */
export function probeDelay(
  cfg: ReconnectConfig,
  probesSent: number,
  active: boolean,
  jitter: number,
): number {
  const cap = Math.max(
    active ? cfg.maxProbeActiveMs : cfg.maxProbeIdleMs,
    cfg.firstProbeMs,
  );
  const base = Math.min(cfg.firstProbeMs * 2 ** Math.min(probesSent, 20), cap);
  return base + base * JITTER * Math.min(Math.max(jitter, 0), 1);
}

class Budget {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillMs: number;
  private last: number;

  constructor(cfg: ReconnectConfig, now: number) {
    this.capacity = Math.max(cfg.probeBurst, 1);
    this.tokens = this.capacity;
    this.refillMs = Math.max(cfg.probeRefillMs, 1);
    this.last = now;
  }

  private fill(now: number): void {
    const gained = Math.max(now - this.last, 0) / this.refillMs;
    this.tokens = Math.min(this.tokens + gained, this.capacity);
    this.last = now;
  }

  tryTake(now: number): boolean {
    this.fill(now);
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  /** When a token will be there (now, if one is). */
  availableAt(now: number): number {
    this.fill(now);
    return this.tokens >= 1 ? now : now + this.refillMs * (1 - this.tokens);
  }
}

interface Entry {
  /** The last `peer_offline` answer or probe. */
  last: number;
  /** Probes sent since the backoff started. */
  probes: number;
  /** This round's jitter, 0..1. */
  jitter: number;
}

/** Which soft-offline contacts to probe, and when. */
export class ProbeSchedule {
  private readonly entries = new Map<string, Entry>();
  private readonly budget: Budget;

  constructor(private readonly cfg: ReconnectConfig, now: number) {
    this.budget = new Budget(cfg, now);
  }

  /**
   * The relay answered an offer to `peer` with `peer_offline`: start its backoff, or (the
   * answer to a probe) count the next delay from now.
   */
  noteOffline(peer: string, now: number, jitter: number): void {
    const e = this.entries.get(peer);
    if (e) e.last = now;
    else this.entries.set(peer, { last: now, probes: 0, jitter });
  }

  /** The user asked for `peer` now: its backoff starts over (the caller offers at once). */
  restart(peer: string, now: number): void {
    const e = this.entries.get(peer);
    if (e) {
      e.last = now;
      e.probes = 0;
    }
  }

  /** `peer` is no longer soft-offline (a presence push, an offer or answer from it, ...). */
  clear(peer: string): void {
    this.entries.delete(peer);
  }

  isScheduled(peer: string): boolean {
    return this.entries.has(peer);
  }

  get size(): number {
    return this.entries.size;
  }

  private dueAt(e: Entry, active: boolean): number {
    return e.last + probeDelay(this.cfg, e.probes, active, e.jitter);
  }

  /**
   * The contacts to probe now, at most as many as the budget allows: those the user waits
   * for first, then the longest overdue. `ready` says a contact can be offered to (no attempt
   * is under way); `jitter` draws 0..1 for the next round of each one taken.
   */
  takeDue(
    now: number,
    active: (peer: string) => boolean,
    ready: (peer: string) => boolean,
    jitter: () => number,
  ): string[] {
    const due: { idle: boolean; at: number; peer: string }[] = [];
    for (const [peer, e] of this.entries) {
      const isActive = active(peer);
      const at = this.dueAt(e, isActive);
      if (at <= now && ready(peer)) due.push({ idle: !isActive, at, peer });
    }
    due.sort((a, b) =>
      Number(a.idle) - Number(b.idle) || a.at - b.at ||
      (a.peer < b.peer ? -1 : 1)
    );
    const taken: string[] = [];
    for (const d of due) {
      if (!this.budget.tryTake(now)) break;
      const e = this.entries.get(d.peer);
      if (e) {
        e.last = now;
        e.probes += 1;
        e.jitter = jitter();
      }
      taken.push(d.peer);
    }
    return taken;
  }

  /**
   * When `takeDue` next has something to return: the earliest due time of a ready contact,
   * not before the budget has a token. `null` with nothing to probe.
   */
  nextWake(
    now: number,
    active: (peer: string) => boolean,
    ready: (peer: string) => boolean,
  ): number | null {
    let earliest: number | null = null;
    for (const [peer, e] of this.entries) {
      if (!ready(peer)) continue;
      const at = this.dueAt(e, active(peer));
      if (earliest === null || at < earliest) earliest = at;
    }
    if (earliest === null) return null;
    return Math.max(earliest, this.budget.availableAt(now));
  }
}
