// ParolNet PWA — Utility Functions

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
// Every toast is tap-to-dismiss; persistent toasts have no auto-hide
// timer. Error toasts (level: 'error') default to persistent:true so
// the user MUST acknowledge them — matches the "loud failures" rule.
//
// Rapid successive calls reuse a single DOM node (message overwrites).
// That's an accepted tradeoff: we lose intermediate toast text but we
// NEVER silently drop the caller's error — the latest failure is
// always on screen.
const TOAST_STYLE_BASE = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);padding:12px 24px;border-radius:8px;font-size:14px;z-index:9999;max-width:80%;text-align:center;display:none;cursor:pointer;';
const TOAST_STYLE_INFO = 'background:#333;color:#fff;';
const TOAST_STYLE_ERROR = 'background:#b3261e;color:#fff;';

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

    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        document.body.appendChild(toast);
        toast.addEventListener('click', () => {
            toast.style.display = 'none';
            if (toast._timeout) { clearTimeout(toast._timeout); toast._timeout = null; }
        });
    }
    toast.style.cssText = TOAST_STYLE_BASE + (level === 'error' ? TOAST_STYLE_ERROR : TOAST_STYLE_INFO);
    toast.textContent = message;
    toast.style.display = 'block';
    if (toast._timeout) { clearTimeout(toast._timeout); toast._timeout = null; }
    if (!persistent) {
        toast._timeout = setTimeout(() => { toast.style.display = 'none'; }, duration);
    }
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
