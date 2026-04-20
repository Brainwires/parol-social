// ParolNet PWA — Utility Functions

import { t } from './i18n.js';

// ── Safe Math Parser (replaces eval/new Function) ──────────
export function safeEval(expr) {
    const sanitized = expr.replace(/[^0-9+\-*/().]/g, '');
    if (!sanitized) return NaN;

    let pos = 0;

    function parseExpression() {
        let result = parseTerm();
        while (pos < sanitized.length && (sanitized[pos] === '+' || sanitized[pos] === '-')) {
            const op = sanitized[pos++];
            const term = parseTerm();
            result = op === '+' ? result + term : result - term;
        }
        return result;
    }

    function parseTerm() {
        let result = parseFactor();
        while (pos < sanitized.length && (sanitized[pos] === '*' || sanitized[pos] === '/')) {
            const op = sanitized[pos++];
            const factor = parseFactor();
            result = op === '*' ? result * factor : result / factor;
        }
        return result;
    }

    function parseFactor() {
        if (sanitized[pos] === '(') {
            pos++;
            const result = parseExpression();
            pos++;
            return result;
        }
        let negative = false;
        if (sanitized[pos] === '-') {
            negative = true;
            pos++;
        }
        let numStr = '';
        while (pos < sanitized.length && (sanitized[pos] >= '0' && sanitized[pos] <= '9' || sanitized[pos] === '.')) {
            numStr += sanitized[pos++];
        }
        const num = parseFloat(numStr);
        return negative ? -num : num;
    }

    try {
        const result = parseExpression();
        return isFinite(result) ? result : NaN;
    } catch {
        return NaN;
    }
}

// ── Platform Detection ──────────────────────────────────────
export function detectPlatform() {
    const ua = navigator.userAgent;
    if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
    if (/Android/.test(ua)) return 'android';
    if (/Windows/.test(ua)) return 'windows';
    if (/Mac/.test(ua)) return 'macos';
    return 'default';
}

// ── Toast Notifications ─────────────────────────────────────
//
// Three call shapes, all backwards-compatible:
//   showToast('msg')                       → info, auto-hide 3s
//   showToast('msg', 2000)                 → info, auto-hide 2s
//   showToast('msg', { level, persistent, duration })
//
// Every toast is tap-to-dismiss. Error toasts (level: 'error') default
// to persistent:true so the user MUST acknowledge them — matches the
// "loud failures" rule.
//
// Queue behaviour:
//   - 0 toasts: container hidden.
//   - 1 toast: plain bar, tap dismisses.
//   - 2+ toasts: carousel panel (prev / counter / next / clear-all).
//     Tap body dismisses current and advances; arrows cycle
//     non-destructively. The panel gets a `toast-carousel-active`
//     class so CSS can make it much larger than the single-toast bar.
// Auto-hide timers only run while a toast is the currently-visible
// entry; otherwise a 3-second info toast buried behind four errors
// would expire before the user ever saw it. In carousel mode the
// visible toast's timer still runs and auto-advances on expiry.
//
// Persistent-flag semantics:
//   - Alone (queue length 1): persistent toasts have NO auto-hide
//     timer — they stay until the user taps to dismiss. This keeps
//     errors "loud" when shown individually.
//   - In carousel (queue length ≥ 2): EVERY toast, including
//     persistent ones, gets an auto-dismiss timer so the carousel
//     drains itself. Persistent toasts use CAROUSEL_PERSISTENT_DURATION
//     (8s) instead of their stored duration; non-persistent toasts use
//     their own duration. If the queue drops back to 1 and the
//     remaining toast is persistent, its carousel timer is cancelled
//     and it reverts to stay-until-tapped behaviour.
const TOAST_STYLE_BASE = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);z-index:9999;max-width:80%;min-width:240px;display:none;font-size:14px;text-align:center;border-radius:8px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,0.4);';
const TOAST_BODY_STYLE_BASE = 'padding:12px 24px;cursor:pointer;';
const TOAST_BODY_STYLE_INFO = 'background:#333;color:#fff;';
const TOAST_BODY_STYLE_ERROR = 'background:#b3261e;color:#fff;';
const TOAST_CONTROLS_STYLE = 'display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 10px;background:rgba(0,0,0,0.35);color:#fff;font-size:13px;';
const TOAST_BTN_STYLE = 'background:transparent;border:none;color:inherit;font:inherit;padding:4px 10px;cursor:pointer;border-radius:4px;min-width:32px;';
const TOAST_COUNTER_STYLE = 'flex:1;text-align:center;opacity:0.85;';
// Auto-dismiss duration applied to persistent toasts when they are
// shown as part of a ≥2-entry carousel. Long enough for the user to
// read a loud error, short enough that the carousel empties itself.
const CAROUSEL_PERSISTENT_DURATION = 8000;

// Module-level queue state.
const toastQueue = []; // [{ id, message, level, persistent, duration, timerId }]
let toastCurrentIndex = 0;
let toastNextId = 1;
let toastDom = null; // { container, body, controls, prevBtn, nextBtn, counter, clearBtn }
let toastVisibleId = null; // id of the toast currently on-screen; used to
                            // decide whether renderToast should reset the
                            // timer (identity change) or leave it running
                            // (re-render of the same toast due to a push).
let toastVisibleInCarousel = false; // whether the visible entry was
                                    // last rendered with queue.length ≥ 2.
                                    // If this flips for the same visible
                                    // id, persistent toasts need their
                                    // carousel-timer started or cancelled.

function ensureToastDom() {
    if (toastDom) return toastDom;

    const container = document.createElement('div');
    container.id = 'toast';
    container.style.cssText = TOAST_STYLE_BASE;

    const body = document.createElement('div');
    body.className = 'toast-body';
    body.style.cssText = TOAST_BODY_STYLE_BASE + TOAST_BODY_STYLE_INFO;
    body.addEventListener('click', () => dismissCurrent());

    const controls = document.createElement('div');
    controls.className = 'toast-controls';
    controls.style.cssText = TOAST_CONTROLS_STYLE;
    controls.style.display = 'none';

    const prevBtn = document.createElement('button');
    prevBtn.type = 'button';
    prevBtn.className = 'toast-prev';
    prevBtn.textContent = '\u2039';
    prevBtn.style.cssText = TOAST_BTN_STYLE;
    prevBtn.setAttribute('aria-label', t('toast.carouselPrev'));
    prevBtn.addEventListener('click', (e) => { e.stopPropagation(); cycleToast(-1); });

    const counter = document.createElement('span');
    counter.className = 'toast-counter';
    counter.style.cssText = TOAST_COUNTER_STYLE;

    const nextBtn = document.createElement('button');
    nextBtn.type = 'button';
    nextBtn.className = 'toast-next';
    nextBtn.textContent = '\u203A';
    nextBtn.style.cssText = TOAST_BTN_STYLE;
    nextBtn.setAttribute('aria-label', t('toast.carouselNext'));
    nextBtn.addEventListener('click', (e) => { e.stopPropagation(); cycleToast(1); });

    const clearBtn = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.className = 'toast-clear-all';
    clearBtn.style.cssText = TOAST_BTN_STYLE + 'margin-left:8px;';
    clearBtn.textContent = t('toast.clearAll');
    clearBtn.setAttribute('aria-label', t('toast.clearAll'));
    clearBtn.addEventListener('click', (e) => { e.stopPropagation(); clearAllToasts(); });

    controls.appendChild(prevBtn);
    controls.appendChild(counter);
    controls.appendChild(nextBtn);
    controls.appendChild(clearBtn);

    container.appendChild(body);
    container.appendChild(controls);
    document.body.appendChild(container);

    toastDom = { container, body, controls, prevBtn, nextBtn, counter, clearBtn };
    return toastDom;
}

function clearEntryTimer(entry) {
    if (entry && entry.timerId) {
        clearTimeout(entry.timerId);
        entry.timerId = null;
    }
}

// Returns the auto-dismiss duration (in ms) that the visible entry
// SHOULD have given the current queue state, or null if the entry
// should have no timer (single persistent toast).
function desiredTimerMsForCurrent() {
    const entry = toastQueue[toastCurrentIndex];
    if (!entry) return null;
    if (entry.persistent) {
        // Persistent-alone → stay-until-tapped. Persistent-in-carousel →
        // auto-advance on a fixed, generous countdown.
        return toastQueue.length >= 2 ? CAROUSEL_PERSISTENT_DURATION : null;
    }
    return entry.duration;
}

function startTimerForCurrent() {
    const entry = toastQueue[toastCurrentIndex];
    if (!entry) return;
    // Always clear any pending timer on the current entry before starting
    // a new one; this prevents stacked timers when called multiple times
    // for the same visible toast.
    clearEntryTimer(entry);
    const ms = desiredTimerMsForCurrent();
    if (ms == null) return;
    const myId = entry.id;
    entry.timerId = setTimeout(() => {
        // Look up by id rather than trusting toastCurrentIndex — the queue
        // may have been mutated (another toast dismissed, cleared, etc).
        // If the toast still exists AND is still the one on screen, dismiss
        // it; the resulting renderToast will start a timer for whatever
        // slides into view next, or close the viewer if the queue is empty.
        const cur = toastQueue[toastCurrentIndex];
        if (cur && cur.id === myId) {
            dismissCurrent();
        } else {
            // Entry was removed out-of-band; scrub the dangling timerId on
            // whatever object it may still live on (no-op if GC'd).
            const stillThere = toastQueue.find((e) => e.id === myId);
            if (stillThere) stillThere.timerId = null;
        }
    }, ms);
}

// Idempotent: inspect the visible entry + queue state and decide
// whether its timer needs to start, stop, or be left alone. Called
// from every renderToast so that crossovers (queue growing to 2,
// shrinking to 1, visible identity changing) always leave the timer
// in a consistent state.
function reconcileTimerForCurrent() {
    const entry = toastQueue[toastCurrentIndex];
    if (!entry) return;
    const inCarousel = toastQueue.length >= 2;
    const identityChanged = entry.id !== toastVisibleId;
    const carouselModeFlipped = inCarousel !== toastVisibleInCarousel;
    toastVisibleId = entry.id;
    toastVisibleInCarousel = inCarousel;

    const desired = desiredTimerMsForCurrent();
    if (desired == null) {
        // Persistent + alone → must have NO timer. Cancel any that was
        // started earlier (e.g. entry was in carousel mode, other toast
        // dismissed, now it's alone again).
        clearEntryTimer(entry);
        return;
    }
    if (identityChanged) {
        // Visible entry just changed — start a fresh timer for it.
        startTimerForCurrent();
        return;
    }
    if (carouselModeFlipped && entry.persistent) {
        // Same persistent entry, but 1↔2 crossover just flipped its
        // desired duration between "no timer" and CAROUSEL_PERSISTENT_
        // DURATION. Restart so the new duration takes effect. (Non-
        // persistent toasts use the same duration in either mode, so
        // we leave their mid-countdown timer alone — that's what keeps
        // "a second toast doesn't reset the visible toast's deadline"
        // working for the info-on-info case.)
        startTimerForCurrent();
        return;
    }
    if (!entry.timerId) {
        // Same entry, same carousel state, but no timer running (e.g.
        // resumed after cycleToast cleared it). Start fresh.
        startTimerForCurrent();
    }
    // Otherwise: timer is mid-countdown for the SAME entry in the SAME
    // effective mode — leave it alone. A newly-arrived toast must not
    // push the visible toast's deadline forward.
}

function renderToast() {
    const dom = ensureToastDom();
    if (toastQueue.length === 0) {
        dom.container.style.display = 'none';
        dom.controls.style.display = 'none';
        if (dom.container.classList) dom.container.classList.remove('toast-carousel-active');
        toastVisibleId = null;
        toastVisibleInCarousel = false;
        return;
    }
    if (toastCurrentIndex >= toastQueue.length) toastCurrentIndex = toastQueue.length - 1;
    if (toastCurrentIndex < 0) toastCurrentIndex = 0;

    const entry = toastQueue[toastCurrentIndex];
    dom.body.style.cssText = TOAST_BODY_STYLE_BASE + (entry.level === 'error' ? TOAST_BODY_STYLE_ERROR : TOAST_BODY_STYLE_INFO);
    dom.body.textContent = entry.message;
    dom.container.style.display = 'block';

    if (toastQueue.length >= 2) {
        // Flag the viewer as a carousel so styles.css can enlarge it to
        // fill ≥1/3 of the viewport and lay out the prev/next/counter/
        // clear-all controls with room to breathe.
        if (dom.container.classList) dom.container.classList.add('toast-carousel-active');
        dom.controls.style.display = 'flex';
        dom.counter.textContent = t('toast.carouselCounter', {
            current: String(toastCurrentIndex + 1),
            total: String(toastQueue.length),
        });
        // Re-apply translatable labels on each render so language
        // changes mid-session take effect on already-built controls.
        dom.prevBtn.setAttribute('aria-label', t('toast.carouselPrev'));
        dom.nextBtn.setAttribute('aria-label', t('toast.carouselNext'));
        dom.clearBtn.textContent = t('toast.clearAll');
        dom.clearBtn.setAttribute('aria-label', t('toast.clearAll'));
    } else {
        if (dom.container.classList) dom.container.classList.remove('toast-carousel-active');
        dom.controls.style.display = 'none';
    }

    // Reconcile the visible entry's auto-dismiss timer against current
    // state. Handles all of:
    //   - identity change (initial render / cycle / auto-advance)
    //   - 1↔2 crossover for the SAME entry (persistent-alone ↔ in-carousel)
    //   - timer-missing-for-no-reason (restart)
    // Critically: does NOT restart a mid-countdown timer for the SAME
    // entry in the SAME mode, so a new toast pushed into the queue
    // cannot extend the visible toast's deadline.
    reconcileTimerForCurrent();
}

function cycleToast(delta) {
    if (toastQueue.length < 2) return;
    // Pause timer on the outgoing toast so its countdown resets when it
    // next becomes current — otherwise a half-expired info toast would
    // vanish shortly after the user cycled back to it.
    clearEntryTimer(toastQueue[toastCurrentIndex]);
    const n = toastQueue.length;
    toastCurrentIndex = ((toastCurrentIndex + delta) % n + n) % n;
    renderToast();
}

function dismissCurrent() {
    if (toastQueue.length === 0) return;
    const removed = toastQueue.splice(toastCurrentIndex, 1)[0];
    clearEntryTimer(removed);
    if (toastCurrentIndex >= toastQueue.length) {
        toastCurrentIndex = Math.max(0, toastQueue.length - 1);
    }
    renderToast();
}

function clearAllToasts() {
    for (const entry of toastQueue) clearEntryTimer(entry);
    toastQueue.length = 0;
    toastCurrentIndex = 0;
    toastVisibleId = null;
    toastVisibleInCarousel = false;
    renderToast();
}

export function showToast(message, opts) {
    // Back-compat: legacy numeric second arg is duration.
    let level = 'info';
    let persistent = false;
    let duration;
    if (typeof opts === 'number') {
        duration = opts;
    } else if (opts && typeof opts === 'object') {
        if (opts.level === 'error') level = 'error';
        if (typeof opts.duration === 'number') duration = opts.duration;
        if (typeof opts.persistent === 'boolean') persistent = opts.persistent;
        else if (level === 'error') persistent = true; // errors default to persistent
    }
    if (duration === undefined) duration = 3000;

    toastQueue.push({
        id: toastNextId++,
        message: String(message),
        level,
        persistent,
        duration,
        timerId: null,
    });
    renderToast();
}

export function showErrorToast(message) {
    return showToast(message, { level: 'error', persistent: true });
}

// ── HTML/Attribute Escaping ─────────────────────────────────
export function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

export function escapeAttr(text) {
    return text.replace(/&/g, '&amp;').replace(/'/g, '&#39;').replace(/"/g, '&quot;');
}

// ── Formatters ──────────────────────────────────────────────
export function formatTime(ts) {
    const d = new Date(ts);
    const now = new Date();
    if (d.toDateString() === now.toDateString()) {
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

// ── Dev Mode ────────────────────────────────────────────────
export function isDevMode() {
    return !!(window.BUILD_INFO && window.BUILD_INFO.dev);
}

// ── Message ID Generator ────────────────────────────────────
export function generateMsgId() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Push Notifications ──────────────────────────────────────
export async function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        await Notification.requestPermission();
    }
}

export function showLocalNotification(title, body, peerId) {
    if ('serviceWorker' in navigator && Notification.permission === 'granted') {
        navigator.serviceWorker.ready.then(reg => {
            reg.showNotification(title, {
                body,
                icon: './icons/icon-192.png',
                tag: 'parolnet-' + peerId,
                data: { peerId },
                vibrate: [200, 100, 200]
            });
        });
    }
}
