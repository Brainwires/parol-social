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

function filterIceCandidateInPrivacyMode(candidateStr) {
    // Same predicate as initWebRTC's onicecandidate handler. Privacy mode
    // must never allow host or server-reflexive candidates on the wire —
    // both leak the client's public IP to the remote peer even when
    // iceTransportPolicy: 'relay' is set on the local PC.
    if (!isWebrtcPrivacyMode()) return false;
    return candidateStr.includes('typ host') || candidateStr.includes('typ srflx');
}

function attachRemoteTrack(event) {
    const stream = event.streams && event.streams[0];
    if (!stream) return;
    setRemoteStream(stream);
    const track = event.track;
    if (!track) return;
    if (track.kind === 'audio') {
        const el = document.getElementById('remote-audio');
        if (el) el.srcObject = stream;
    } else if (track.kind === 'video') {
        const el = document.getElementById('remote-video');
        if (el) {
            el.srcObject = stream;
            el.classList.remove('hidden');
        }
    }
}

function createCallPc(peerId, callId) {
    const pc = new RTCPeerConnection(getRtcConfig());

    pc.onicecandidate = (event) => {
        if (!event.candidate) return;
        const candidateStr = event.candidate.candidate || '';
        if (filterIceCandidateInPrivacyMode(candidateStr)) {
            console.debug('[Call] privacy mode: filtered non-relay candidate:', candidateStr);
            return;
        }
        // Fire-and-forget: ICE trickles are idempotent on the receive side
        // and the remote PC tolerates out-of-order arrival.
        sendCallSignal(peerId, 'ice', { callId, candidate: event.candidate.toJSON() })
            .catch(e => console.warn('[Call] ICE send failed:', e && e.message));
    };

    pc.ontrack = attachRemoteTrack;

    pc.onconnectionstatechange = () => {
        console.log('[Call]', peerId.slice(0, 8), 'pc state:', pc.connectionState);
    };

    if (localStream) {
        for (const track of localStream.getTracks()) {
            try { pc.addTrack(track, localStream); } catch (e) {
                console.warn('[Call] addTrack failed:', e && e.message);
            }
        }
    }

    const record = { pc, callId, pendingIceIn: [] };
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
        // Flush any remote ICE that arrived before we had a remote description.
        for (const cand of record.pendingIceIn) {
            try { await pc.addIceCandidate(cand); }
            catch (e) { console.warn('[Call] flushed ICE add failed:', e && e.message); }
        }
        record.pendingIceIn = [];
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
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
        // Flush early remote ICE (caller side typically doesn't have any,
        // but the callee may start trickling before their answer reaches us).
        for (const cand of record.pendingIceIn) {
            try { await record.pc.addIceCandidate(cand); }
            catch (e) { console.warn('[Call] flushed ICE add failed:', e && e.message); }
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
        return;
    }
    const pc = record.pc;
    // If remote description isn't set yet, queue the candidate for flush.
    if (!pc.remoteDescription || !pc.remoteDescription.type) {
        record.pendingIceIn.push(candidate);
        return;
    }
    try {
        await pc.addIceCandidate(candidate);
    } catch (e) {
        console.warn('[Call] addIceCandidate failed:', e && e.message);
    }
}

export function teardownCallConnection(peerId) {
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
