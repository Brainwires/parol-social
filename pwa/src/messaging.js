// ParolNet PWA — Message Routing, Groups, File Receive, Calls
import {
    wasm, cryptoStore, currentView, currentPeerId, setCurrentPeerId,
    currentGroupId, setCurrentGroupId, currentGroupCallId, setCurrentGroupCallId,
    incomingCallInfo, setIncomingCallInfo, localStream, setLocalStream,
    pendingFileReceives, groupCallPollInterval, setGroupCallPollInterval,
    currentCallId, setCurrentCallId
} from './state.js';
import { showToast, showErrorToast, escapeHtml, escapeAttr, formatTime, formatSize, showLocalNotification } from './utils.js';
import { dbGet, dbPut, dbGetAll, dbGetByIndex, dbDelete, updateContactState } from './db.js';
import { showView } from './views.js';
import { hasDirectConnection, sendViaWebRTC, seenGossipMessages, markGossipSeen,
         handleRTCOffer, handleRTCAnswer, handleRTCIce } from './webrtc.js';
import { sendToRelay, discoverPeers, startDiscoveryInterval, connMgr } from './connection.js';
import { spendOneToken, maybeRefill, requestBatch, queueSize } from './token-pool.js';
import { lookupHomeRelay } from './peer-relay-cache.js';
import { isOnionActive, sendViaOnion } from './onion.js';
import { loadContacts, appendMessage, answerIncomingCall, loadAddressBook,
         stopLocalMedia, stopCallTimer, clearNoAnswerTimer } from './ui-chat.js';
import { completeCallConnection, addRemoteIce, teardownCallConnection,
         setCallStatus } from './call.js';
import { t } from './i18n.js';
import {
    MSG_TYPE_CHAT, MSG_TYPE_SYSTEM, MSG_TYPE_FILE_CHUNK, MSG_TYPE_FILE_CONTROL,
    MSG_TYPE_CALL_SIGNAL, MSG_TYPE_GROUP_TEXT, MSG_TYPE_GROUP_CALL_SIGNAL,
    MSG_TYPE_GROUP_FILE_OFFER, MSG_TYPE_GROUP_FILE_CHUNK,
    MSG_TYPE_SENDER_KEY_DISTRIBUTION, MSG_TYPE_GROUP_ADMIN, MSG_TYPE_DECOY,
    MSG_TYPE_IDENTITY_ROTATE
} from './protocol-constants.js';
import { markRealSend } from './cover-traffic.js';

// ── Session Persistence ──────────────────────────────────
function persistSessions() {
    if (!wasm || !wasm.export_sessions) return;
    try {
        const blob = wasm.export_sessions();
        if (blob) dbPut('settings', { key: 'sessions_blob', value: blob });
    } catch(e) { console.warn('Session persist failed:', e.message); }
}

// ── Envelope wrapping helper ─────────────────────────────
// Wraps a structured (JSON-serializable) payload in a PNP-001 envelope for a
// given peer. Returns the bucket-padded hex string, or null if no secure
// session exists with the peer. The inner payload is JSON (not CBOR) because
// the receiver decodes with JSON.parse — this matches how chat text is wrapped.
function encodeEnvelope(toPeerId, msgType, obj) {
    if (!wasm || !wasm.envelope_encode || !wasm.has_session || !wasm.has_session(toPeerId)) {
        return null;
    }
    try {
        const inner = new TextEncoder().encode(JSON.stringify(obj));
        const nowSecs = BigInt(Math.floor(Date.now() / 1000));
        return wasm.envelope_encode(toPeerId, msgType, inner, nowSecs);
    } catch (e) {
        console.warn('[Envelope] encode failed for msgType=0x' + msgType.toString(16), e);
        return null;
    }
}

// Send an envelope-wrapped structured payload via the best available transport
// (direct WebRTC preferred, relay fallback). Every real send also notifies the
// cover-traffic timer so the next decoy tick is suppressed (PNP-006-MUST-005).
//
// Outer relay frames carry a Privacy Pass `token` (PNP-001-MUST-048). The
// token is spent FIFO from the pool; if the pool is empty the relay-send
// path aborts and the user is notified via `toast.relayTokenEmpty`.
// WebRTC direct sends do NOT consume a token — the relay is bypassed
// entirely in that case.
//
// H12 Phase 2: `sendEnvelope` now consults the peer-relay cache first.
// If the destination's home relay differs from ours, we open (or reuse)
// an outbound connection to that relay and spend a token from *its*
// per-relay pool. If the lookup fails (404 / net / sig mismatch) we
// fall back to the home-relay send path — that still works for
// locally-connected peers and produces a deterministic "peer not
// connected" bounce for truly-offline peers. Returns a Promise<bool>.
async function sendEnvelope(toPeerId, msgType, obj) {
    const env = encodeEnvelope(toPeerId, msgType, obj);
    if (!env) return false;
    return sendRawEnvelope(toPeerId, env);
}

/// Transport dispatch for a pre-encoded PNP-001 envelope. Shared by every
/// call site that already has envelope bytes in hand — call-signal offers
/// (bootstrap source_hint envelopes, file chunks, identity-rotation
/// notifications, cover-traffic decoys, etc.). All of those MUST spend a
/// Privacy Pass token before the outer frame leaves the client per
/// PNP-001-MUST-048; this helper centralizes that discipline so none of
/// them can forget it again.
///
/// The WebRTC-first / onion / home-relay / cross-relay cascade is identical
/// to `sendEnvelope`; only the encoding step is pulled out.
export async function sendRawEnvelope(toPeerId, env) {
    if (!env) return false;
    markRealSend();
    if (hasDirectConnection(toPeerId)) {
        return sendViaWebRTC(toPeerId, env);
    }
    if (isOnionActive()) {
        return sendViaOnion(toPeerId, env);
    }

    let homeRelay = null;
    try { homeRelay = await lookupHomeRelay(toPeerId); } catch (_) { homeRelay = null; }

    if (!homeRelay || homeRelay === connMgr.relayUrl) {
        let token;
        try {
            token = spendOneToken(connMgr.relayUrl);
        } catch (e) {
            console.warn('[Relay] home token pool empty — dropping send; refill in progress');
            showToast(t('toast.relayTokenEmpty'));
            maybeRefill(connMgr.relayUrl);
            return false;
        }
        const ok = sendToRelay(toPeerId, env, token);
        if (ok) maybeRefill(connMgr.relayUrl);
        // A null homeRelay is the common case — brand-new contacts, peers on
        // our own relay, or single-relay deployments. The home-relay send
        // path above handles all three. Emitting a toast here surfaced a
        // false error on every send to an uncached peer; the relay-server
        // will bounce with "peer not connected" if the fallback genuinely
        // can't deliver.
        return ok;
    }

    const opened = await connMgr.openOutbound(homeRelay);
    if (!opened) {
        showToast(t('toast.peerLookupFailed'));
        return false;
    }
    if (queueSize(homeRelay) === 0) {
        const res = await requestBatch(homeRelay);
        if (!res || !res.ok) {
            showToast(t('toast.relayTokenEmpty'));
            return false;
        }
    }
    let token;
    try {
        token = spendOneToken(homeRelay);
    } catch (_) {
        showToast(t('toast.relayTokenEmpty'));
        return false;
    }
    const ok = connMgr.sendToRelayUrl(homeRelay, toPeerId, env, token);
    if (ok) maybeRefill(homeRelay);
    return ok;
}

// Call-signaling helper. Wraps a `{action, callId, ...payload}` body in a
// PNP-001 CALL_SIGNAL envelope and hands it to sendRawEnvelope so the
// outer frame inherits the Privacy Pass token + WebRTC-first / onion /
// cross-relay dispatch cascade. Exported so call.js can fire ICE/hangup
// signals without re-implementing the envelope + transport plumbing.
export async function sendCallSignal(peerId, action, payload = {}) {
    if (!wasm || !wasm.envelope_encode || !wasm.has_session || !wasm.has_session(peerId)) {
        return false;
    }
    try {
        const inner = new TextEncoder().encode(JSON.stringify({ action, ...payload }));
        const nowSecs = BigInt(Math.floor(Date.now() / 1000));
        const envelope = wasm.envelope_encode(peerId, MSG_TYPE_CALL_SIGNAL, inner, nowSecs);
        return await sendRawEnvelope(peerId, envelope);
    } catch (e) {
        console.warn('[CallSignal] encode failed:', e && e.message);
        return false;
    }
}

// ── Relay Message Handling ────────────────────────────────
export function handleRelayMessage(msg) {
    switch (msg.type) {
        case 'challenge':
            // Relay requires challenge-response auth: sign the nonce with our Ed25519 key
            if (msg.nonce && wasm && wasm.sign_bytes && wasm.get_public_key) {
                try {
                    const signature = wasm.sign_bytes(msg.nonce);
                    const pubkey = wasm.get_public_key();
                    const peerId = window._peerId;
                    connMgr._swPost({
                        type: 'relay_register_auth',
                        peerId,
                        pubkey,
                        signature,
                        nonce: msg.nonce
                    });
                    console.log('[Auth] Challenge signed, sending authenticated register');
                } catch(e) {
                    console.warn('[Auth] Failed to sign challenge:', e);
                }
            } else {
                console.warn('[Auth] Cannot sign challenge — WASM not ready or missing sign_bytes');
            }
            break;

        case 'registered':
            console.log('Registered with relay. Online peers:', msg.online_peers);
            discoverPeers();
            startDiscoveryInterval();
            break;

        case 'message':
            // All wire frames are PNP-001 envelopes — onIncomingMessage tries
            // each known session until one decrypts (sealed-sender path; no
            // `from` field on the wire per PNP-001-MUST-048).
            onIncomingMessage(msg.payload);
            break;

        case 'queued':
            // PNP-001-MUST-068: provisional-delivery signal, not a failure.
            // PNP-001-SHOULD-015: clients MUST NOT render this as an error.
            // A modal toast would miscommunicate the state, so we log only.
            console.log('[Relay] queued (peer offline — relay will store-and-forward)');
            break;

        case 'rtc_offer':
            handleRTCOffer(msg.from, msg.payload).catch(e => console.warn('[WebRTC] offer error:', e));
            break;
        case 'rtc_answer':
            handleRTCAnswer(msg.from, msg.payload).catch(e => console.warn('[WebRTC] answer error:', e));
            break;
        case 'rtc_ice':
            handleRTCIce(msg.from, msg.payload).catch(e => console.warn('[WebRTC] ICE error:', e));
            break;

        case 'error':
            console.warn('Relay error:', msg.message);
            if (msg.message === 'peer not connected') {
                showToast(t('toast.peerNotOnline'));
            }
            break;
    }
}

// ── Group Management ───────────────────────────────────────

export function switchListTab(tab) {
    document.querySelectorAll('.list-tab').forEach(t => t.classList.remove('active'));
    const btn = document.querySelector(`.list-tab[data-list="${tab}"]`);
    if (btn) btn.classList.add('active');
    const contactList = document.getElementById('contact-list');
    const groupList = document.getElementById('group-list');
    const addressBookList = document.getElementById('address-book-list');
    const createGroupBtn = document.getElementById('create-group-btn');
    if (contactList) contactList.classList.add('hidden');
    if (groupList) groupList.classList.add('hidden');
    if (addressBookList) addressBookList.classList.add('hidden');
    if (createGroupBtn) createGroupBtn.classList.add('hidden');
    if (tab === 'groups') {
        if (groupList) groupList.classList.remove('hidden');
        if (createGroupBtn) createGroupBtn.classList.remove('hidden');
        loadGroups();
    } else if (tab === 'address-book') {
        if (addressBookList) addressBookList.classList.remove('hidden');
        loadAddressBook();
    } else {
        if (contactList) contactList.classList.remove('hidden');
        loadContacts();
    }
}

export async function loadGroups() {
    try {
        const groups = await dbGetAll('groups');
        renderGroupList(groups);
    } catch (e) {
        console.warn('Failed to load groups:', e);
        renderGroupList([]);
    }
}

function renderGroupList(groups) {
    const list = document.getElementById('group-list');
    if (!list) return;
    if (!groups || groups.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No groups yet</p><p>Create or join a group</p></div>';
        return;
    }
    list.innerHTML = groups.map(g => `
        <div class="contact-item" onclick="openGroupChat('${escapeAttr(g.groupId)}')">
            <div class="contact-avatar">${escapeHtml((g.name || 'G')[0].toUpperCase())}</div>
            <div class="contact-info">
                <div class="contact-name" dir="auto">${escapeHtml(g.name || 'Unnamed Group')}</div>
                <div class="contact-last-msg" dir="auto">${escapeHtml(g.lastMessage || 'No messages yet')}</div>
            </div>
            <div class="contact-meta">
                <div class="contact-time">${escapeHtml(g.lastTime || '')}</div>
            </div>
        </div>
    `).join('');
}

export function showCreateGroupDialog() {
    showView('create-group');
    const nameInput = document.getElementById('create-group-name');
    if (nameInput) { nameInput.value = ''; nameInput.focus(); }
}

export async function createGroup() {
    const nameInput = document.getElementById('create-group-name');
    if (!nameInput) return;
    const name = nameInput.value.trim();
    if (!name) { showToast(t('toast.enterGroupName')); return; }
    const groupId = 'grp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    const myPeerId = window._peerId || '';
    const group = {
        groupId,
        name,
        members: [myPeerId],
        createdBy: myPeerId,
        createdAt: Date.now(),
        lastMessage: '',
        lastTime: ''
    };
    try {
        await dbPut('groups', group);
        if (wasm && wasm.create_sender_key) {
            try { wasm.create_sender_key(groupId); } catch(e) { console.warn('[Group] Sender key init:', e); }
        }
        showToast(t('toast.groupCreated'));
        openGroupChat(groupId);
    } catch (e) {
        showToast(t('toast.groupCreateFailed'));
        console.error('[Group] Create failed:', e);
    }
}

export async function openGroupChat(groupId) {
    setCurrentGroupId(groupId);
    showView('group-chat');
    const group = await dbGet('groups', groupId);
    const nameEl = document.getElementById('group-chat-name');
    if (nameEl) nameEl.textContent = group ? group.name : groupId.slice(0, 12);
    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl && group) badgeEl.textContent = (group.members || []).length;
    await loadGroupMessages(groupId);
}

async function loadGroupMessages(groupId) {
    const container = document.getElementById('group-message-list');
    if (!container) return;
    try {
        const messages = await dbGetByIndex('group_messages', 'groupId', groupId);
        messages.sort((a, b) => a.timestamp - b.timestamp);
        container.innerHTML = '';
        for (const m of messages) {
            appendGroupMessage(m);
        }
        container.scrollTop = container.scrollHeight;
    } catch (e) {
        console.warn('Failed to load group messages:', e);
        container.innerHTML = '';
    }
}

export function appendGroupMessage(msg) {
    const container = document.getElementById('group-message-list');
    if (!container) return;
    const myPeerId = window._peerId || '';
    const isMine = msg.sender === myPeerId;
    const div = document.createElement('div');
    div.className = `message ${isMine ? 'sent' : 'received'}`;
    if (!isMine) {
        const senderLabel = document.createElement('div');
        senderLabel.className = 'group-msg-sender';
        senderLabel.textContent = (msg.sender || '').slice(0, 8) + '...';
        div.appendChild(senderLabel);
    }
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    if (msg.domContent) {
        bubble.appendChild(msg.domContent);
    } else {
        bubble.setAttribute('dir', 'auto');
        bubble.textContent = msg.content || '';
    }
    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = formatTime(msg.timestamp);
    div.appendChild(bubble);
    div.appendChild(time);
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

export async function sendGroupMessage() {
    const input = document.getElementById('group-message-input');
    if (!input) return;
    const text = input.value.trim();
    if (!text || !currentGroupId) return;

    const myPeerId = window._peerId || '';
    const msg = {
        groupId: currentGroupId,
        sender: myPeerId,
        content: text,
        timestamp: Date.now()
    };

    try { await dbPut('group_messages', msg); } catch(e) { console.warn(e); }
    appendGroupMessage(msg);
    input.value = '';

    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const obj = {
        groupId: currentGroupId,
        sender: myPeerId,
        content: text,
        timestamp: msg.timestamp
    };
    for (const memberId of (group.members || [])) {
        if (memberId === myPeerId) continue;
        const sent = await sendEnvelope(memberId, MSG_TYPE_GROUP_TEXT, obj);
        if (!sent) {
            console.warn('[Group] No session with member; message dropped for', memberId.slice(0, 8));
        }
    }

    group.lastMessage = text.slice(0, 50);
    group.lastTime = formatTime(Date.now());
    try { await dbPut('groups', group); } catch(e) {}
}

async function handleIncomingGroupMessage(msg) {
    if (!msg.groupId) return;
    const stored = {
        groupId: msg.groupId,
        sender: msg.sender || '',
        content: msg.content || '',
        timestamp: msg.timestamp || Date.now()
    };
    try { await dbPut('group_messages', stored); } catch(e) { console.warn(e); }

    try {
        const group = await dbGet('groups', msg.groupId);
        if (group) {
            group.lastMessage = (msg.content || '').slice(0, 50);
            group.lastTime = formatTime(Date.now());
            await dbPut('groups', group);
        }
    } catch(e) {}

    if (currentView === 'group-chat' && currentGroupId === msg.groupId) {
        appendGroupMessage(stored);
    } else {
        showToast(t('toast.newGroupMessage'));
        showLocalNotification('Group Message', (msg.content || '').slice(0, 100), msg.groupId);
    }
}

export async function showGroupMembers() {
    const modal = document.getElementById('group-members-modal');
    if (!modal || !currentGroupId) return;
    modal.classList.remove('hidden');

    const group = await dbGet('groups', currentGroupId);
    const memberList = document.getElementById('group-members-list');
    if (!memberList || !group) return;
    const myPeerId = window._peerId || '';
    const isCreator = group.createdBy === myPeerId;

    memberList.innerHTML = (group.members || []).map(memberId => {
        const isMe = memberId === myPeerId;
        const shortId = memberId.slice(0, 12) + '...';
        const role = memberId === group.createdBy ? 'Creator' : 'Member';
        const removeBtn = isCreator && !isMe
            ? `<button class="group-member-remove" onclick="removeMemberFromGroup('${escapeAttr(memberId)}')">Remove</button>`
            : '';
        return `
            <div class="group-member-item">
                <div>
                    <div class="group-member-name">${escapeHtml(shortId)}${isMe ? ' (You)' : ''}</div>
                    <div class="group-member-role">${role}</div>
                </div>
                ${removeBtn}
            </div>
        `;
    }).join('');
}

export function closeGroupMembers() {
    const modal = document.getElementById('group-members-modal');
    if (modal) modal.classList.add('hidden');
}

export async function addMemberFromInput() {
    const input = document.getElementById('add-member-input');
    if (!input) return;
    const peerId = input.value.trim();
    if (!peerId) { showToast(t('toast.enterPeerId')); return; }
    await addMemberToGroup(peerId);
    input.value = '';
}

export async function addMemberToGroup(peerId) {
    if (!currentGroupId || !peerId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    if (group.members.includes(peerId)) { showToast(t('toast.alreadyMember')); return; }
    group.members.push(peerId);
    await dbPut('groups', group);

    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl) badgeEl.textContent = group.members.length;

    const inviteSent = await sendEnvelope(peerId, MSG_TYPE_GROUP_ADMIN, {
        action: 'invite',
        groupId: group.groupId,
        groupName: group.name,
        members: group.members
    });
    if (!inviteSent) {
        console.warn('[Group] No session — cannot deliver invite to', peerId.slice(0, 8));
    }

    if (wasm && wasm.create_sender_key) {
        try {
            const keyData = wasm.create_sender_key(currentGroupId);
            if (keyData) {
                sendEnvelope(peerId, MSG_TYPE_SENDER_KEY_DISTRIBUTION, {
                    groupId: currentGroupId,
                    keyData: Array.from(new Uint8Array(keyData))
                });
            }
        } catch(e) { console.warn('[Group] Sender key distribution:', e); }
    }

    showToast(t('toast.memberAdded'));
    showGroupMembers();
}

export async function removeMemberFromGroup(peerId) {
    if (!currentGroupId || !peerId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    group.members = group.members.filter(m => m !== peerId);
    await dbPut('groups', group);

    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl) badgeEl.textContent = group.members.length;

    showToast(t('toast.memberRemoved'));
    showGroupMembers();
}

export async function leaveCurrentGroup() {
    if (!currentGroupId) return;
    try { await dbDelete('groups', currentGroupId); } catch(e) {}
    setCurrentGroupId(null);
    closeGroupMembers();
    showView('contacts');
    switchListTab('groups');
    showToast(t('toast.groupLeft'));
}

async function handleGroupInvite(msg) {
    if (!msg.groupId || !msg.groupName) return;
    const myPeerId = window._peerId || '';
    const group = {
        groupId: msg.groupId,
        name: msg.groupName,
        members: msg.members || [msg.from, myPeerId],
        createdBy: msg.from,
        createdAt: Date.now(),
        lastMessage: '',
        lastTime: ''
    };
    try {
        await dbPut('groups', group);
        showToast(t('toast.groupInvite', { groupName: msg.groupName }));
        if (currentView === 'contacts') loadGroups();
    } catch(e) {
        console.warn('[Group] Invite save failed:', e);
    }
}

function handleSenderKey(msg, fromPeerId) {
    if (!msg.groupId || !msg.keyData) return;
    if (wasm && wasm.receive_sender_key) {
        try {
            const keyBytes = new Uint8Array(msg.keyData);
            wasm.receive_sender_key(msg.groupId, fromPeerId, keyBytes);
            console.log('[Group] Received sender key for', msg.groupId, 'from', fromPeerId.slice(0, 8));
        } catch(e) {
            console.warn('[Group] Sender key receive failed:', e);
        }
    }
}

// ── File Receive Flow ──────────────────────────────────────

function handleFileOffer(msg) {
    if (!msg.from || !msg.fileId) return;
    pendingFileReceives[msg.fileId] = {
        from: msg.from,
        name: msg.fileName || 'file',
        size: msg.fileSize || 0,
        totalChunks: msg.totalChunks || 1,
        chunksReceived: 0,
        chunks: [],
        accepted: false
    };
    if (currentView === 'chat' && currentPeerId === msg.from) {
        showFileOfferInChat(msg);
    } else {
        showToast(t('toast.fileOffered', { fileName: msg.fileName || 'file' }));
        showLocalNotification('File Offer', msg.fileName || 'file', msg.from);
    }
}

function showFileOfferInChat(msg) {
    const container = document.getElementById('message-list');
    if (!container) return;
    const div = document.createElement('div');
    div.className = 'message received';
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    const offer = document.createElement('div');
    offer.className = 'file-offer';
    offer.id = 'file-offer-' + msg.fileId;
    const nameEl = document.createElement('div');
    nameEl.className = 'file-offer-name';
    nameEl.textContent = msg.fileName || 'file';
    const sizeEl = document.createElement('div');
    sizeEl.className = 'file-offer-size';
    sizeEl.textContent = formatSize(msg.fileSize || 0);
    const actions = document.createElement('div');
    actions.className = 'file-offer-actions';
    const acceptBtn = document.createElement('button');
    acceptBtn.textContent = 'Accept';
    acceptBtn.className = 'call-action-btn accept';
    acceptBtn.onclick = () => acceptFileOffer(msg.fileId);
    const declineBtn = document.createElement('button');
    declineBtn.textContent = 'Decline';
    declineBtn.className = 'call-action-btn decline';
    declineBtn.onclick = () => declineFileOffer(msg.fileId);
    actions.appendChild(acceptBtn);
    actions.appendChild(declineBtn);
    offer.appendChild(nameEl);
    offer.appendChild(sizeEl);
    offer.appendChild(actions);
    bubble.appendChild(offer);
    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = formatTime(Date.now());
    div.appendChild(bubble);
    div.appendChild(time);
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

export async function acceptFileOffer(fileId) {
    const pending = pendingFileReceives[fileId];
    if (!pending) return;
    pending.accepted = true;
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        const actions = offerEl.querySelector('.file-offer-actions');
        if (actions) actions.innerHTML = '<div class="file-status">Receiving... 0%</div>';
    }
    const sent = await sendEnvelope(pending.from, MSG_TYPE_FILE_CONTROL, { action: 'accept', fileId });
    if (!sent) {
        console.warn('[File] No session with sender; accept not delivered');
    }
}

export function declineFileOffer(fileId) {
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        const actions = offerEl.querySelector('.file-offer-actions');
        if (actions) actions.innerHTML = '<div class="file-status">Declined</div>';
    }
    delete pendingFileReceives[fileId];
}

function handleFileAccept(msg) {
    if (!msg.fileId) return;
    console.log('[File] Peer accepted file:', msg.fileId);
    if (wasm && wasm.get_next_chunk) {
        sendFileChunked(msg.fileId, msg.from || currentPeerId);
    }
}

function handleFileChunk(msg) {
    const pending = pendingFileReceives[msg.fileId];
    if (!pending || !pending.accepted) return;
    pending.chunks[msg.chunkIndex] = msg.data;
    pending.chunksReceived++;
    const pct = Math.round((pending.chunksReceived / pending.totalChunks) * 100);
    const offerEl = document.getElementById('file-offer-' + msg.fileId);
    if (offerEl) {
        const status = offerEl.querySelector('.file-status');
        if (status) status.textContent = 'Receiving... ' + pct + '%';
    }
    if (pending.chunksReceived >= pending.totalChunks) {
        offerDownload(msg.fileId);
    }
}

function offerDownload(fileId) {
    const pending = pendingFileReceives[fileId];
    if (!pending) return;
    const parts = [];
    for (let i = 0; i < pending.totalChunks; i++) {
        if (pending.chunks[i]) {
            const bytes = new Uint8Array(pending.chunks[i]);
            parts.push(bytes);
        }
    }
    const blob = new Blob(parts);
    const url = URL.createObjectURL(blob);
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        offerEl.innerHTML = '';
        const nameEl = document.createElement('div');
        nameEl.className = 'file-offer-name';
        nameEl.textContent = pending.name;
        const link = document.createElement('a');
        link.className = 'file-download-link';
        link.href = url;
        link.download = pending.name;
        link.textContent = 'Download (' + formatSize(pending.size) + ')';
        offerEl.appendChild(nameEl);
        offerEl.appendChild(link);
    }
    delete pendingFileReceives[fileId];
}

async function sendFileChunked(fileId, toPeerId) {
    if (!toPeerId) return;
    if (!wasm || !wasm.get_next_chunk || !wasm.envelope_encode) return;
    if (!wasm.has_session || !wasm.has_session(toPeerId)) {
        console.warn('[File] No session with', toPeerId.slice(0, 8), '— chunks not sent');
        return;
    }
    let chunkIndex = 0;
    const encoder = new TextEncoder();
    while (true) {
        try {
            const chunk = wasm.get_next_chunk(fileId);
            if (!chunk || chunk.length === 0) break;
            const inner = JSON.stringify({
                fileId,
                chunkIndex,
                totalChunks: -1,
                data: Array.from(chunk)
            });
            const nowSecs = BigInt(Math.floor(Date.now() / 1000));
            const envelope = wasm.envelope_encode(toPeerId, MSG_TYPE_FILE_CHUNK, encoder.encode(inner), nowSecs);
            // sendRawEnvelope picks WebRTC when available, falls back to the
            // token-gated relay path. Without the token the relay silently
            // dropped every chunk — file transfers were a no-op.
            await sendRawEnvelope(toPeerId, envelope);
            chunkIndex++;
            if (chunkIndex % 10 === 0) {
                await new Promise(r => setTimeout(r, 0));
            }
        } catch(e) {
            console.warn('[File] Chunk send error:', e);
            break;
        }
    }
}

// ── Incoming Call Notification ──────────────────────────────

function handleIncomingCall(msg) {
    setIncomingCallInfo({
        from: msg.from,
        callId: msg.callId,
        withVideo: !!msg.withVideo,
        // Offer SDP is required on the callee side to build the answer
        // in acceptCallConnection(). Stashed here so acceptIncomingCall()
        // can hand it to answerIncomingCall() unmodified.
        offerSdp: msg.sdp || null,
    });
    showIncomingCallNotification(msg.from, msg.callId);
}

function showIncomingCallNotification(fromPeerId, callId) {
    const notif = document.getElementById('incoming-call-notification');
    if (!notif) return;
    const nameEl = document.getElementById('incoming-call-name');
    if (nameEl) nameEl.textContent = fromPeerId.slice(0, 12) + '...';
    notif.classList.remove('hidden');
    showLocalNotification('Incoming Call', 'Call from ' + fromPeerId.slice(0, 12), fromPeerId);
}

export function acceptIncomingCall() {
    if (!incomingCallInfo) return;
    if (incomingCallInfo.isGroup) {
        joinGroupCall();
        return;
    }
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    setCurrentPeerId(incomingCallInfo.from);
    setCurrentCallId(incomingCallInfo.callId);
    answerIncomingCall(incomingCallInfo.callId, {
        withVideo: !!incomingCallInfo.withVideo,
        offerSdp: incomingCallInfo.offerSdp,
    });
    showView('call');
    const nameEl = document.getElementById('call-peer-name');
    if (nameEl) nameEl.textContent = incomingCallInfo.from.slice(0, 16) + '...';
    setIncomingCallInfo(null);
}

export function declineIncomingCall() {
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    if (!incomingCallInfo) return;
    sendEnvelope(incomingCallInfo.from, MSG_TYPE_CALL_SIGNAL, {
        action: 'reject',
        callId: incomingCallInfo.callId
    });
    setIncomingCallInfo(null);
}

// ── Group Calls ────────────────────────────────────────────

export async function startGroupCall() {
    if (!currentGroupId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const callId = 'gcall-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
    setCurrentGroupCallId(callId);

    try {
        setLocalStream(await navigator.mediaDevices.getUserMedia({ audio: true }));
    } catch(e) {
        showToast(t('toast.microphoneError', { error: e.message }));
        return;
    }

    showGroupCallView(group.name, group.members);

    const myPeerId = window._peerId || '';
    const obj = {
        action: 'invite',
        groupId: currentGroupId,
        callId,
        groupName: group.name
    };
    for (const memberId of (group.members || [])) {
        if (memberId === myPeerId) continue;
        const sent = await sendEnvelope(memberId, MSG_TYPE_GROUP_CALL_SIGNAL, obj);
        if (!sent) {
            console.warn('[GroupCall] No session with', memberId.slice(0, 8));
        }
    }
}

function showGroupCallView(groupName, members) {
    showView('group-call');
    const nameEl = document.getElementById('group-call-name');
    if (nameEl) nameEl.textContent = groupName || 'Group Call';

    const grid = document.getElementById('group-call-grid');
    if (!grid) return;
    grid.innerHTML = '';
    const myPeerId = window._peerId || '';

    const selfTile = document.createElement('div');
    selfTile.className = 'group-call-tile';
    selfTile.id = 'gcall-tile-self';
    const selfName = document.createElement('div');
    selfName.className = 'group-call-tile-name';
    selfName.textContent = 'You';
    selfTile.appendChild(selfName);
    grid.appendChild(selfTile);

    for (const memberId of (members || [])) {
        if (memberId === myPeerId) continue;
        if (grid.children.length >= 8) break;
        const tile = document.createElement('div');
        tile.className = 'group-call-tile';
        tile.id = 'gcall-tile-' + memberId.slice(0, 12);
        const tileName = document.createElement('div');
        tileName.className = 'group-call-tile-name';
        tileName.textContent = memberId.slice(0, 8) + '...';
        tile.appendChild(tileName);
        grid.appendChild(tile);
    }
}

function handleGroupCallInvite(msg) {
    if (!msg.groupId || !msg.callId) return;
    setIncomingCallInfo({ from: msg.from, callId: msg.callId, isGroup: true, groupId: msg.groupId, groupName: msg.groupName });
    const notif = document.getElementById('incoming-call-notification');
    if (!notif) return;
    const nameEl = document.getElementById('incoming-call-name');
    if (nameEl) nameEl.textContent = (msg.groupName || 'Group') + ' call';
    const labelEl = document.getElementById('incoming-call-label');
    if (labelEl) labelEl.textContent = 'Group call invitation';
    notif.classList.remove('hidden');
    showLocalNotification('Group Call', (msg.groupName || 'Group') + ' call', msg.from);
}

export async function joinGroupCall() {
    if (!incomingCallInfo || !incomingCallInfo.isGroup) return;
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    setCurrentGroupCallId(incomingCallInfo.callId);
    setCurrentGroupId(incomingCallInfo.groupId);

    try {
        setLocalStream(await navigator.mediaDevices.getUserMedia({ audio: true }));
    } catch(e) {
        showToast(t('toast.microphoneError', { error: e.message }));
        setIncomingCallInfo(null);
        return;
    }

    const group = await dbGet('groups', incomingCallInfo.groupId);
    showGroupCallView(incomingCallInfo.groupName || (group ? group.name : 'Group'), group ? group.members : [incomingCallInfo.from]);
    setIncomingCallInfo(null);
}

export function leaveGroupCallUI() {
    if (localStream) {
        localStream.getTracks().forEach(t => t.stop());
        setLocalStream(null);
    }
    if (groupCallPollInterval) {
        clearInterval(groupCallPollInterval);
        setGroupCallPollInterval(null);
    }
    setCurrentGroupCallId(null);
    showView(currentGroupId ? 'group-chat' : 'contacts');
}

export function toggleGroupMute() {
    if (!localStream) return;
    const audioTrack = localStream.getAudioTracks()[0];
    if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        const btn = document.querySelector('.group-call-controls .call-control-btn:first-child');
        if (btn) btn.textContent = audioTrack.enabled ? 'Mute' : 'Unmute';
    }
}

// ── Group File Transfer ────────────────────────────────────

export function attachGroupFile() {
    const input = document.getElementById('group-file-input');
    if (input) input.click();
}

export async function onGroupFileSelected(event) {
    const file = event.target.files[0];
    if (!file || !currentGroupId) return;
    event.target.value = '';

    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const myPeerId = window._peerId || '';
    const fileId = 'gf-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);

    const msgEl = document.createElement('div');
    msgEl.className = 'file-transfer';
    msgEl.id = 'gfile-' + fileId;
    const nameEl = document.createElement('div');
    nameEl.className = 'file-name';
    nameEl.textContent = '\uD83D\uDCCE ' + file.name;
    const sizeEl = document.createElement('div');
    sizeEl.className = 'file-size';
    sizeEl.textContent = formatSize(file.size);
    const statusEl = document.createElement('div');
    statusEl.className = 'file-status';
    statusEl.textContent = 'Sending to group...';
    msgEl.appendChild(nameEl);
    msgEl.appendChild(sizeEl);
    msgEl.appendChild(statusEl);
    appendGroupMessage({ sender: myPeerId, domContent: msgEl, timestamp: Date.now(), groupId: currentGroupId });

    try {
        const buffer = await file.arrayBuffer();
        const data = new Uint8Array(buffer);
        const CHUNK_SIZE = 16384;
        const totalChunks = Math.ceil(data.length / CHUNK_SIZE);

        for (const memberId of (group.members || [])) {
            if (memberId === myPeerId) continue;
            const offerSent = await sendEnvelope(memberId, MSG_TYPE_GROUP_FILE_OFFER, {
                groupId: currentGroupId,
                fileId,
                fileName: file.name,
                fileSize: file.size,
                totalChunks,
                sender: myPeerId
            });
            if (!offerSent) {
                console.warn('[GroupFile] No session with', memberId.slice(0, 8), '— skipping');
                continue;
            }

            for (let i = 0; i < totalChunks; i++) {
                const chunk = data.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
                await sendEnvelope(memberId, MSG_TYPE_GROUP_FILE_CHUNK, {
                    groupId: currentGroupId,
                    fileId,
                    chunkIndex: i,
                    totalChunks,
                    data: Array.from(chunk)
                });
                if (i % 10 === 0 && i > 0) {
                    await new Promise(r => setTimeout(r, 0));
                }
            }
        }
        statusEl.textContent = 'Sent';
    } catch(e) {
        statusEl.textContent = 'Failed: ' + e.message;
        console.error('[GroupFile] Send failed:', e);
    }
}

function handleGroupFileOffer(msg) {
    if (!msg.fileId || !msg.groupId) return;
    pendingFileReceives[msg.fileId] = {
        from: msg.sender || '',
        name: msg.fileName || 'file',
        size: msg.fileSize || 0,
        totalChunks: msg.totalChunks || 1,
        chunksReceived: 0,
        chunks: [],
        accepted: true,
        isGroup: true,
        groupId: msg.groupId
    };
    if (currentView === 'group-chat' && currentGroupId === msg.groupId) {
        const offerDiv = document.createElement('div');
        offerDiv.className = 'file-offer';
        offerDiv.id = 'file-offer-' + msg.fileId;
        const nameEl = document.createElement('div');
        nameEl.className = 'file-offer-name';
        nameEl.textContent = msg.fileName || 'file';
        const sizeEl = document.createElement('div');
        sizeEl.className = 'file-offer-size';
        sizeEl.textContent = formatSize(msg.fileSize || 0);
        const statusEl = document.createElement('div');
        statusEl.className = 'file-status';
        statusEl.textContent = 'Receiving... 0%';
        offerDiv.appendChild(nameEl);
        offerDiv.appendChild(sizeEl);
        offerDiv.appendChild(statusEl);
        appendGroupMessage({
            sender: msg.sender || '',
            domContent: offerDiv,
            timestamp: Date.now(),
            groupId: msg.groupId
        });
    }
}

function handleGroupFileChunk(msg) {
    const pending = pendingFileReceives[msg.fileId];
    if (!pending) return;
    pending.chunks[msg.chunkIndex] = msg.data;
    pending.chunksReceived++;
    const pct = Math.round((pending.chunksReceived / pending.totalChunks) * 100);
    const offerEl = document.getElementById('file-offer-' + msg.fileId);
    if (offerEl) {
        const status = offerEl.querySelector('.file-status');
        if (status) status.textContent = 'Receiving... ' + pct + '%';
    }
    if (pending.chunksReceived >= pending.totalChunks) {
        offerDownload(msg.fileId);
    }
}

// ── Incoming Message Handler ──────────────────────────────

// Route a decrypted envelope payload to the right handler based on the PNP-001
// msg_type code (see specs/PNP-001-wire-protocol.md §3.4).
//
// Exported so pure-JS tests can exercise the dispatch table without loading WASM.
export function dispatchByMsgType(msgType, fromPeerId, plaintext, handlers) {
    const h = handlers || DEFAULT_DISPATCH_HANDLERS;
    switch (msgType) {
        case MSG_TYPE_DECOY:
            // PNP-006 cover traffic: silently drop. No UI, no handler, no log —
            // the threat model requires decoys be indistinguishable from noise
            // even in local diagnostics.
            return;
        case MSG_TYPE_CHAT:
            return h.chat(fromPeerId, plaintext);
        case MSG_TYPE_SYSTEM:
            return h.system(fromPeerId, plaintext);
        case MSG_TYPE_FILE_CHUNK:
            return h.fileChunk(fromPeerId, plaintext);
        case MSG_TYPE_FILE_CONTROL:
            return h.fileControl(fromPeerId, plaintext);
        case MSG_TYPE_CALL_SIGNAL:
            return h.callSignal(fromPeerId, plaintext);
        case MSG_TYPE_GROUP_TEXT:
            return h.groupText(fromPeerId, plaintext);
        case MSG_TYPE_GROUP_CALL_SIGNAL:
            return h.groupCallSignal(fromPeerId, plaintext);
        case MSG_TYPE_GROUP_FILE_OFFER:
            return h.groupFileOffer(fromPeerId, plaintext);
        case MSG_TYPE_GROUP_FILE_CHUNK:
            return h.groupFileChunk(fromPeerId, plaintext);
        case MSG_TYPE_SENDER_KEY_DISTRIBUTION:
            return h.senderKey(fromPeerId, plaintext);
        case MSG_TYPE_GROUP_ADMIN:
            return h.groupAdmin(fromPeerId, plaintext);
        case MSG_TYPE_IDENTITY_ROTATE:
            return h.identityRotate(fromPeerId, plaintext);
        default:
            // PNP-001 MUST-008: unknown types are silently discarded.
            console.warn('[Dispatch] unknown msg_type', msgType, 'from', fromPeerId.slice(0, 8));
            return undefined;
    }
}

function parseJsonPlaintext(plaintext) {
    try {
        return JSON.parse(new TextDecoder().decode(plaintext));
    } catch (e) {
        return null;
    }
}

function handleChatPlaintext(fromPeerId, plaintext) {
    const messageText = new TextDecoder().decode(plaintext);
    const msg = {
        peerId: fromPeerId,
        direction: 'received',
        content: messageText,
        timestamp: Date.now()
    };
    dbPut('messages', msg).catch(e => {
        console.warn('Failed to store message:', e);
        showErrorToast(t('toast.messageStoreFailed'));
    });
    // Upsert the stable identity row (name + future pubkey anchor if any) and
    // the volatile state row separately. lastMessage/lastTime/unread live on
    // contact_state (v5) so panic-wipe can zero them without losing trust
    // anchors.
    dbPut('contacts', {
        peerId: fromPeerId,
        name: fromPeerId.slice(0, 8) + '...',
    }).catch(e => {
        console.warn('[Contact] upsert failed:', e);
        showErrorToast(t('toast.contactStateFailed'));
    });
    updateContactState(fromPeerId, {
        lastMessage: messageText.slice(0, 50),
        lastTime: formatTime(Date.now()),
        unread: 1,
    }).catch(e => {
        console.warn('[Contact] state update failed:', e);
        showErrorToast(t('toast.contactStateFailed'));
    });

    if (currentView === 'chat' && currentPeerId === fromPeerId) {
        appendMessage(msg);
    } else {
        showLocalNotification('New Message', messageText.slice(0, 100), fromPeerId);
        showToast(t('toast.newMessage', { name: fromPeerId.slice(0, 8) }));
        if (currentView === 'contacts') {
            loadContacts();
        }
    }
}

function handleSystemPlaintext(fromPeerId, plaintext) {
    // Reserved for future SYSTEM bodies. The QR bootstrap no longer rides
    // in a SYSTEM message body — session materialization is handled at the
    // envelope layer (PNP-001 §5.3.1) via the cleartext source_hint.
    const body = new TextDecoder().decode(plaintext);
    if (body.length > 0) {
        console.log('[System]', fromPeerId.slice(0, 8), body.slice(0, 40));
    }
}

function handleFileChunkPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) { console.warn('[FileChunk] malformed envelope payload from', fromPeerId.slice(0, 8)); return; }
    handleFileChunk(obj);
}

function handleFileControlPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) return;
    if (obj.action === 'offer') {
        handleFileOffer({ ...obj, from: fromPeerId });
    } else if (obj.action === 'accept') {
        handleFileAccept({ ...obj, from: fromPeerId });
    } else {
        console.warn('[FileControl] unknown action:', obj.action);
    }
}

function handleCallSignalPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) return;
    switch (obj.action) {
        case 'offer':
            handleIncomingCall({ ...obj, from: fromPeerId });
            break;
        case 'answer': {
            // Caller side: callee accepted. Apply their SDP so RTP actually
            // starts flowing, then flip the "Calling..." label. Without the
            // setRemoteDescription the PC stays in have-local-offer state
            // forever and no media crosses.
            clearNoAnswerTimer();
            completeCallConnection(fromPeerId, obj.sdp).catch(e => {
                console.warn('[CallSignal] completeCallConnection failed:', e && e.message);
                showErrorToast(t('toast.callConnectionFailed'));
            });
            // Provisional label flip. The PC will also drive this via
            // onconnectionstatechange → 'connected'; setCallStatus is
            // idempotent so whichever path wins the race is fine.
            setCallStatus('Connected');
            break;
        }
        case 'ice':
            addRemoteIce(fromPeerId, obj.candidate).catch(e => {
                console.warn('[CallSignal] addRemoteIce failed:', e && e.message);
            });
            break;
        case 'hangup':
            // Remote ended the call. Mirror hangupCall's local cleanup so
            // both sides end up in the same post-call state: PC closed,
            // local media stopped, timer halted, view reset.
            clearNoAnswerTimer();
            teardownCallConnection(fromPeerId);
            stopLocalMedia();
            stopCallTimer();
            setCurrentCallId(null);
            showView(currentPeerId ? 'chat' : 'contacts');
            showToast(t('toast.callEnded'));
            break;
        case 'reject':
            showToast(t('toast.callDeclined'));
            break;
        default:
            console.warn('[CallSignal] unknown action:', obj.action);
    }
}

function handleGroupTextPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) return;
    handleIncomingGroupMessage(obj);
}

function handleGroupCallSignalPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) return;
    if (obj.action === 'invite') {
        handleGroupCallInvite({ ...obj, from: fromPeerId });
    } else {
        console.warn('[GroupCallSignal] unknown action:', obj.action);
    }
}

function handleGroupFileOfferPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) return;
    handleGroupFileOffer(obj);
}

function handleGroupFileChunkPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) return;
    handleGroupFileChunk(obj);
}

function handleSenderKeyPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) return;
    handleSenderKey(obj, fromPeerId);
}

function handleGroupAdminPlaintext(fromPeerId, plaintext) {
    const obj = parseJsonPlaintext(plaintext);
    if (!obj) return;
    if (obj.action === 'invite') {
        handleGroupInvite({ ...obj, from: fromPeerId });
    } else {
        console.warn('[GroupAdmin] unknown action:', obj.action);
    }
}

// PNP-002 §8: signed identity-rotation attestation. The OLD Ed25519 key of
// the sender signs a payload stating the new PeerId + new Ed25519 pubkey.
// We look up the contact's stored OLD pubkey (trust anchor, stored at
// contact-add time), verify the signature via WASM, and if valid remap the
// contact's peer_id field to the new PeerId while preserving the session.
async function handleIdentityRotatePlaintext(fromPeerId, plaintext) {
    if (!wasm || !wasm.handle_identity_rotation) {
        console.warn('[IdentityRotate] WASM not available — dropping');
        return;
    }
    const payloadJson = new TextDecoder().decode(plaintext);
    let contact;
    try {
        contact = await dbGet('contacts', fromPeerId);
    } catch (e) {
        console.warn('[IdentityRotate] contact lookup failed:', e);
        return;
    }
    if (!contact || !contact.identityPubKey) {
        // No stored trust anchor — drop silently. Matches PNP-001-MUST-008.
        console.warn('[IdentityRotate] no stored identityPubKey for', fromPeerId.slice(0, 8));
        return;
    }

    let result;
    try {
        result = wasm.handle_identity_rotation(contact.identityPubKey, payloadJson);
    } catch (e) {
        console.warn('[IdentityRotate] verify failed:', e && e.message);
        return;
    }
    if (!result || !result.ok) {
        console.warn('[IdentityRotate] signature verification failed from', fromPeerId.slice(0, 8));
        return;
    }

    const newPeerId = result.new_peer_id_hex;
    const newPubHex = result.new_ed25519_pub_hex;
    if (!newPeerId || newPeerId === fromPeerId) return;

    // Remap the contact record to the new PeerId. The Double Ratchet session
    // is keyed by the peer identity object in WASM state; re-storing under
    // the new PeerId keeps everything reachable via the new key.
    const updated = {
        ...contact,
        peerId: newPeerId,
        identityPubKey: newPubHex,
        // Keep the old identity pubkey for the grace window so receivers of
        // stale (in-flight) rotation retransmissions don't drop silently.
        previousIdentityPubKey: contact.identityPubKey,
        rotatedAt: result.rotated_at,
        rotatedGraceExpiresAt: result.grace_expires_at,
    };
    // lastMessage/lastTime live in contact_state (v5) — trust anchors stay in
    // contacts, everything volatile lives in the sibling store.
    delete updated.lastMessage;
    delete updated.lastTime;
    delete updated.unread;
    try {
        await dbDelete('contacts', fromPeerId);
        await dbDelete('contact_state', fromPeerId);
        await dbPut('contacts', updated);
        await updateContactState(newPeerId, {
            lastMessage: t('toast.identityRotated'),
            lastTime: formatTime(Date.now()),
        });
    } catch (e) {
        console.warn('[IdentityRotate] contact remap failed:', e);
        return;
    }
    const name = contact.name || fromPeerId.slice(0, 8);
    showToast(t('toast.contactRotated', { name }));
    showLocalNotification('Identity rotated', name, newPeerId);
    if (currentView === 'contacts') loadContacts();
}

const DEFAULT_DISPATCH_HANDLERS = {
    chat: handleChatPlaintext,
    system: handleSystemPlaintext,
    fileChunk: handleFileChunkPlaintext,
    fileControl: handleFileControlPlaintext,
    callSignal: handleCallSignalPlaintext,
    groupText: handleGroupTextPlaintext,
    groupCallSignal: handleGroupCallSignalPlaintext,
    groupFileOffer: handleGroupFileOfferPlaintext,
    groupFileChunk: handleGroupFileChunkPlaintext,
    senderKey: handleSenderKeyPlaintext,
    groupAdmin: handleGroupAdminPlaintext,
    identityRotate: handleIdentityRotatePlaintext,
};

function hexToBytes(hex) {
    if (!hex) return new Uint8Array(0);
    const out = new Uint8Array(hex.length >> 1);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
}

// PNP-001-MUST-048 sealed-sender receive. Outer frame carries no `from`, so
// the Rust-side `trial_decrypt` iterates all committed sessions AEAD-first;
// if none match AND a pending_bootstrap exists (we are the QR presenter),
// it runs §5.3.1 materialization on the cleartext source_hint. Bootstrap
// success commits the session and returns `bootstrapped: true`, which we
// turn into the "new secure contact" UI.
export function onIncomingMessage(payload) {
    if (!payload || typeof payload !== 'string') return;

    const dedupKey = payload.slice(0, 128);
    if (seenGossipMessages.has(dedupKey)) return;
    markGossipSeen(dedupKey);

    if (!wasm || !wasm.trial_decrypt) {
        console.warn('[Envelope] WASM not available — dropping frame');
        return;
    }

    let decoded;
    try {
        decoded = wasm.trial_decrypt(payload);
    } catch (e) {
        // No committed session decrypted AND no bootstrap fallback succeeded.
        // Surface the reason so bootstrap-path failures are diagnosable;
        // ordinary misrouted-traffic drops become visible rather than silent.
        console.warn('[Envelope] trial_decrypt failed:', e && e.message ? e.message : e);
        return;
    }
    console.log('[Envelope] decrypted', {
        from: decoded.source_peer_id.slice(0, 8),
        msgType: decoded.msg_type,
        bootstrapped: decoded.bootstrapped,
    });
    persistSessions();

    const sourcePeer = decoded.source_peer_id;

    if (decoded.bootstrapped) {
        // PNP-001 §5.3.1: the responder session is now committed server-side
        // by the WASM layer. Wire the contact on the UI side.
        const ikHex = decoded.source_hint || null;
        Promise.all([
            dbPut('contacts', {
                peerId: sourcePeer,
                name: sourcePeer.slice(0, 8) + '...',
                identityPubKey: ikHex,
            }),
            updateContactState(sourcePeer, {
                lastMessage: t('contact.sessionEstablished'),
                lastTime: formatTime(Date.now()),
                unread: 0,
            }),
        ]).then(() => {
            showToast(t('toast.secureContact', { name: sourcePeer.slice(0, 8) }));
            if (currentView === 'contacts') loadContacts();
        }).catch(err => console.warn('[Bootstrap] contact persist failed:', err));
    }

    const plaintext = hexToBytes(decoded.plaintext_hex);
    dispatchByMsgType(decoded.msg_type, sourcePeer, plaintext);
}
