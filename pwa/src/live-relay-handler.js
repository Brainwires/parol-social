// Live relay_msg handler — pure-logic helper extracted from boot.js so
// tests can import it directly under node (boot.js pulls browser-only
// state and its transitive imports use browser-relative paths that
// don't resolve in the node test runner).
//
// Behavior: on ANY `delivered === false` outcome (or a synchronous throw
// from `handle`), re-buffer the frame into sw-inbox and kick drainSwInbox.
// drainSwInbox owns classification (transient vs terminal), readiness
// gating, and dedup — doing that classification twice (once here, once
// in the drain) is what lost frames for non-transient-but-recoverable
// reasons like `decrypt-failed` during a session-restore race.
//
// Deps are injected so the caller (boot.js) can wire in the real
// handleRelayMessage / swInboxRebuffer / drainSwInbox and tests can
// stub them.
//
// @internal — exported for unit tests; the only production caller is
// the SW message listener inside registerServiceWorker().
export function handleLiveRelayMsg(msg, handle, rebuffer, drain) {
    let res;
    try {
        res = handle(msg);
    } catch (e) {
        console.warn('[SW-Live] handleRelayMessage threw, re-buffering:', e && e.message);
        return rebuffer(msg).then(() => drain().catch(() => {}));
    }
    if (res && res.delivered === false) {
        return rebuffer(msg).then(() => drain().catch(() => {}));
    }
    return Promise.resolve();
}
