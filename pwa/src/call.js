// ParolNet PWA — Per-Call RTCPeerConnection (1:1 voice + video)
//
// Separate from webrtc.js's data-channel mesh PC on purpose: that PC exists
// for the lifetime of a chat session and carries the Signal-style ratchet
// traffic; a call PC is short-lived (ring → pickup → hangup) and carries
// RTP media tracks. Both reuse the same getRtcConfig() so the privacy-mode
// `iceTransportPolicy: 'relay'` discipline (no public IP leak to the
// contact) applies uniformly — a call must never be the vector that
// circumvents the data-channel TURN-only guarantee.
//
// Public surface is deliberately narrow (five verbs) so the caller in
// ui-chat.js doesn't need to reach into RTCPeerConnection internals:
//   startCallConnection    — caller side: make offer, return SDP
//   acceptCallConnection   — callee side: apply offer, make answer, return SDP
//   completeCallConnection — caller side: apply the callee's answer
//   addRemoteIce           — trickle-ICE candidate from the other side
//   teardownCallConnection — close PC, clear state, unbind media sinks

import { localStream, setRemoteStream } from './state.js';
import { getRtcConfig, isWebrtcPrivacyMode } from './webrtc.js';
import { sendCallSignal } from './messaging.js';
import { showErrorToast } from './utils.js';
import { t } from './i18n.js';

// peerId -> { pc, callId, pendingIceIn }
// pendingIceIn queues remote ICE candidates that arrived before
// setRemoteDescription completed — common race when caller's first ICE
// trickle races with the callee's setRemoteDescription(offer).
const callPeerConnections = new Map();

// peerId -> timeoutId. Started when SDP exchange completes; cleared when
// pc.connectionState reaches 'connected' or the call is torn down. If it
// fires, ICE / DTLS / RTP never came up (typically TURN unreachable from
// one side) and we treat it the same as pc.connectionState === 'failed'.
const mediaWatchdogs = new Map();
const MEDIA_WATCHDOG_MS = 15000;

function clearMediaWatchdog(peerId) {
    const id = mediaWatchdogs.get(peerId);
    if (id) {
        clearTimeout(id);
        mediaWatchdogs.delete(peerId);
    }
}

export function startMediaWatchdog(peerId) {
    clearMediaWatchdog(peerId);
    const id = setTimeout(() => {
        mediaWatchdogs.delete(peerId);
        const record = callPeerConnections.get(peerId);
        if (!record) return;
        if (record.pc.connectionState === 'connected') return;
        console.warn('[Call] media watchdog fired — pc state:', record.pc.connectionState);
        showErrorToast(t('toast.callMediaTimeout'));
        window.dispatchEvent(new CustomEvent('parolnet:call-failed', {
            detail: { peerId, reason: 'media-timeout' },
        }));
    }, MEDIA_WATCHDOG_MS);
    mediaWatchdogs.set(peerId, id);
}

function filterIceCandidateInPrivacyMode(candidateStr) {
    // Same predicate as initWebRTC's onicecandidate handler. Privacy mode
    // must never allow host or server-reflexive candidates on the wire —
    // both leak the client's public IP to the remote peer even when
    // iceTransportPolicy: 'relay' is set on the local PC.
    if (!isWebrtcPrivacyMode()) return false;
    return candidateStr.includes('typ host') || candidateStr.includes('typ srflx');
}

// Idempotent status-label setter. Called from both the PC state-change
// handler here and the answer-signal path in messaging.js — whichever
// arrives first wins, the other is a no-op overwrite of the same text.
// Kept inside call.js (rather than imported from ui-chat.js) because
// ui-chat.js already imports from this module; importing back would
// create a circular dependency on the ui-chat side.
export function setCallStatus(text) {
    const el = document.getElementById('call-status');
    if (el) el.textContent = text;
}

function attachRemoteTrack(event) {
    const stream = event.streams && event.streams[0];
    const track = event.track;
    console.log('[Call] ontrack fired — kind:', track && track.kind, 'hasStream:', !!stream);
    if (!stream) {
        console.warn('[Call] ontrack: no event.streams[0] — remote media will not play');
        return;
    }
    setRemoteStream(stream);
    if (!track) return;
    if (track.kind === 'audio') {
        const el = document.getElementById('remote-audio');
        if (el) el.srcObject = stream;
        else console.warn('[Call] ontrack: <audio id="remote-audio"> not in DOM');
    } else if (track.kind === 'video') {
        const el = document.getElementById('remote-video');
        if (el) {
            el.srcObject = stream;
            el.classList.remove('hidden');
        } else {
            console.warn('[Call] ontrack: <video id="remote-video"> not in DOM');
        }
    }
}

// Walk getStats() and summarise candidate-pair outcomes. Called when the PC
// state goes to 'failed' so the console captures *why* ICE never came up
// instead of just the terminal state. Best-effort: stats API varies across
// browsers, so we fail soft.
async function logIceStats(peerId, pc) {
    try {
        const stats = await pc.getStats();
        let nominated = 0, succeeded = 0, failed = 0, total = 0;
        const transports = [];
        for (const r of stats.values()) {
            if (r.type === 'candidate-pair') {
                total++;
                if (r.nominated) nominated++;
                if (r.state === 'succeeded') succeeded++;
                if (r.state === 'failed') failed++;
            } else if (r.type === 'transport') {
                transports.push({ dtls: r.dtlsState, ice: r.iceState, selected: r.selectedCandidatePairId });
            }
        }
        console.warn('[Call]', peerId.slice(0, 8), 'getStats — pairs total:', total,
                     'nominated:', nominated, 'succeeded:', succeeded, 'failed:', failed,
                     'transports:', transports);
    } catch (e) {
        console.warn('[Call] getStats failed:', e && e.message);
    }
}

function createCallPc(peerId, callId) {
    const cfg = getRtcConfig();
    console.log('[Call]', peerId.slice(0, 8), 'createCallPc — iceServers:', (cfg.iceServers || []).length,
                'policy:', cfg.iceTransportPolicy || 'all', 'privacy:', isWebrtcPrivacyMode());
    if (isWebrtcPrivacyMode() && (!cfg.iceServers || cfg.iceServers.length === 0)) {
        console.warn('[Call] privacy mode ON but iceServers is empty — TURN credentials may not have loaded yet');
    }
    const pc = new RTCPeerConnection(cfg);

    // Per-PC ICE candidate counters. Useful when the connection never comes
    // up — a zero-sent count points at TURN/STUN missing, a zero-received
    // count points at signaling not flowing.
    const iceStats = { sent: 0, filtered: 0, sendFailed: 0, received: 0, applied: 0, queued: 0 };

    pc.onicecandidate = (event) => {
        if (!event.candidate) {
            console.log('[ICE]', peerId.slice(0, 8), 'end-of-candidates — sent:', iceStats.sent,
                        'filtered:', iceStats.filtered, 'sendFailed:', iceStats.sendFailed);
            return;
        }
        const candidateStr = event.candidate.candidate || '';
        if (filterIceCandidateInPrivacyMode(candidateStr)) {
            iceStats.filtered++;
            console.debug('[Call] privacy mode: filtered non-relay candidate:', candidateStr);
            return;
        }
        iceStats.sent++;
        // Fire-and-forget: ICE trickles are idempotent on the receive side
        // and the remote PC tolerates out-of-order arrival.
        sendCallSignal(peerId, 'ice', { callId, candidate: event.candidate.toJSON() })
            .then(result => {
                if (!result || !result.ok) {
                    iceStats.sendFailed++;
                    console.warn('[ICE]', peerId.slice(0, 8), 'send failed:', result && result.reason);
                }
            })
            .catch(e => {
                iceStats.sendFailed++;
                console.warn('[Call] ICE send threw:', e && e.message);
            });
        if (iceStats.sent % 5 === 0) {
            console.log('[ICE]', peerId.slice(0, 8), 'progress — sent:', iceStats.sent,
                        'filtered:', iceStats.filtered, 'sendFailed:', iceStats.sendFailed);
        }
    };

    pc.ontrack = attachRemoteTrack;

    pc.onconnectionstatechange = () => {
        const state = pc.connectionState;
        console.log('[Call]', peerId.slice(0, 8), 'pc state:', state,
                    '| ice:', pc.iceConnectionState,
                    '| gather:', pc.iceGatheringState,
                    '| signal:', pc.signalingState);
        // Drive the status label from the PC lifecycle. Idempotent — the
        // answer-signal path in messaging.js may flip to 'Connected' first,
        // which is fine: setCallStatus just mirrors into #call-status.
        if (state === 'connecting') {
            // Only the caller should show 'Ringing...' — the callee's
            // answerIncomingCall has already flipped the label to
            // 'Connected' by this point, and PC 'connecting' fires on
            // both sides. Gate on 'Calling...' so we only advance the
            // caller's label and don't regress the callee's.
            const el = document.getElementById('call-status');
            if (el && el.textContent === 'Calling...') {
                setCallStatus('Ringing...');
            }
        } else if (state === 'connected') {
            clearMediaWatchdog(peerId);
            setCallStatus('Connected');
        } else if (state === 'failed') {
            // Only react if we still own this PC — teardown races with the
            // state-change event and we don't want to fire a toast after
            // the user already hung up.
            if (callPeerConnections.get(peerId) && callPeerConnections.get(peerId).pc === pc) {
                console.warn('[Call]', peerId.slice(0, 8), 'pc failed — ICE stats:',
                             'sent:', iceStats.sent, 'filtered:', iceStats.filtered,
                             'received:', iceStats.received, 'applied:', iceStats.applied,
                             'queued:', iceStats.queued);
                logIceStats(peerId, pc);
                showErrorToast(t('toast.callConnectionLost'));
                // ui-chat.js owns hangup semantics (remote signal + teardown
                // + timer + view nav). Cross-module import from call.js back
                // into ui-chat.js would create a cycle — ui-chat.js already
                // imports from call.js — so we dispatch a window event and
                // let ui-chat.js's module-scoped listener invoke hangupCall.
                window.dispatchEvent(new CustomEvent('parolnet:call-failed', {
                    detail: { peerId },
                }));
            }
        }
    };

    if (localStream) {
        for (const track of localStream.getTracks()) {
            try { pc.addTrack(track, localStream); } catch (e) {
                console.warn('[Call] addTrack failed:', e && e.message);
            }
        }
    }

    const record = { pc, callId, pendingIceIn: [], iceStats };
    callPeerConnections.set(peerId, record);
    return record;
}

export async function startCallConnection(peerId, callId, _withVideo) {
    // Clean up any stale record — happens when the UI retries a call without
    // tearing down cleanly (e.g., previous attempt failed after getUserMedia).
    teardownCallConnection(peerId);

    const { pc } = createCallPc(peerId, callId);
    try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        console.log('[Call]', peerId.slice(0, 8), 'offer SDP created — length:',
                    pc.localDescription.sdp.length);
        return pc.localDescription.sdp;
    } catch (e) {
        console.warn('[Call] startCallConnection failed:', e && e.message);
        showErrorToast(t('toast.callConnectionFailed'));
        teardownCallConnection(peerId);
        throw e;
    }
}

export async function acceptCallConnection(peerId, callId, offerSdp, _withVideo) {
    teardownCallConnection(peerId);

    const record = createCallPc(peerId, callId);
    const { pc } = record;
    try {
        await pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
        console.log('[Call]', peerId.slice(0, 8), 'remote description applied: offer');
        // Flush any remote ICE that arrived before we had a remote description.
        const flushedCount = record.pendingIceIn.length;
        for (const cand of record.pendingIceIn) {
            try { await pc.addIceCandidate(cand); record.iceStats.applied++; }
            catch (e) { console.warn('[Call] flushed ICE add failed:', e && e.message); }
        }
        if (flushedCount > 0) {
            console.log('[Call]', peerId.slice(0, 8), 'flushed', flushedCount, 'queued ICE candidates');
        }
        record.pendingIceIn = [];
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        console.log('[Call]', peerId.slice(0, 8), 'answer SDP created — length:',
                    pc.localDescription.sdp.length);
        return pc.localDescription.sdp;
    } catch (e) {
        console.warn('[Call] acceptCallConnection failed:', e && e.message);
        showErrorToast(t('toast.callConnectionFailed'));
        teardownCallConnection(peerId);
        throw e;
    }
}

export async function completeCallConnection(peerId, answerSdp) {
    const record = callPeerConnections.get(peerId);
    if (!record) {
        console.warn('[Call] completeCallConnection: no PC for', peerId.slice(0, 8));
        return;
    }
    try {
        await record.pc.setRemoteDescription({ type: 'answer', sdp: answerSdp });
        console.log('[Call]', peerId.slice(0, 8), 'remote description applied: answer');
        // Flush early remote ICE (caller side typically doesn't have any,
        // but the callee may start trickling before their answer reaches us).
        const flushedCount = record.pendingIceIn.length;
        for (const cand of record.pendingIceIn) {
            try { await record.pc.addIceCandidate(cand); record.iceStats.applied++; }
            catch (e) { console.warn('[Call] flushed ICE add failed:', e && e.message); }
        }
        if (flushedCount > 0) {
            console.log('[Call]', peerId.slice(0, 8), 'flushed', flushedCount, 'queued ICE candidates');
        }
        record.pendingIceIn = [];
    } catch (e) {
        console.warn('[Call] completeCallConnection failed:', e && e.message);
        throw e;
    }
}

export async function addRemoteIce(peerId, candidate) {
    if (!candidate) return;
    const record = callPeerConnections.get(peerId);
    if (!record) {
        // No PC yet — incoming call hasn't been accepted. Drop silently; when
        // the callee accepts, the caller's trickle continues after answer is
        // exchanged, so losing pre-accept ICE is harmless.
        console.log('[ICE]', peerId.slice(0, 8), 'received but no PC yet — dropped');
        return;
    }
    record.iceStats.received++;
    const pc = record.pc;
    // If remote description isn't set yet, queue the candidate for flush.
    if (!pc.remoteDescription || !pc.remoteDescription.type) {
        record.pendingIceIn.push(candidate);
        record.iceStats.queued++;
        return;
    }
    try {
        await pc.addIceCandidate(candidate);
        record.iceStats.applied++;
    } catch (e) {
        console.warn('[Call] addIceCandidate failed:', e && e.message);
    }
}

export function teardownCallConnection(peerId) {
    clearMediaWatchdog(peerId);
    const record = callPeerConnections.get(peerId);
    if (record) {
        record.pendingIceIn = [];
        // Do NOT stop the local tracks here — they're the same MediaStreamTrack
        // instances held by state.localStream, and stopLocalMedia() in
        // ui-chat.js owns their lifecycle. Stopping them twice would race.
        try { record.pc.close(); } catch (_) {}
    }
    callPeerConnections.delete(peerId);

    const remoteVideo = document.getElementById('remote-video');
    if (remoteVideo) {
        remoteVideo.srcObject = null;
        remoteVideo.classList.add('hidden');
    }
    const remoteAudio = document.getElementById('remote-audio');
    if (remoteAudio) {
        remoteAudio.srcObject = null;
    }
    setRemoteStream(null);
}

export function hasCallConnection(peerId) {
    return callPeerConnections.has(peerId);
}
