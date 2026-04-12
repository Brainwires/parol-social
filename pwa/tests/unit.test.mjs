import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomFillSync } from 'node:crypto';

// ── SHA1 Hex (reimplemented for Node, mirrors app.js sha1Hex) ──
function sha1Hex(input) {
    return createHash('sha1').update(input).digest('hex');
}

// ── Tests ──

describe('sha1Hex', () => {
    test('produces 40-char hex string', () => {
        const result = sha1Hex('parolnet-mesh-v1');
        assert.equal(result.length, 40);
        assert.match(result, /^[0-9a-f]{40}$/);
    });

    test('mesh hash is deterministic', () => {
        const a = sha1Hex('parolnet-mesh-v1');
        const b = sha1Hex('parolnet-mesh-v1');
        assert.equal(a, b);
    });

    test('different inputs produce different hashes', () => {
        const a = sha1Hex('parolnet-mesh-v1');
        const b = sha1Hex('parolnet-mesh-v2');
        assert.notEqual(a, b);
    });

    test('contact hash is symmetric', () => {
        const idA = 'aaaa'.repeat(16); // 64 chars
        const idB = 'bbbb'.repeat(16);
        const sorted1 = [idA, idB].sort().join(':') + ':parolnet-contact';
        const sorted2 = [idB, idA].sort().join(':') + ':parolnet-contact';
        assert.equal(sha1Hex(sorted1), sha1Hex(sorted2));
    });
});

describe('generateMsgId', () => {
    // Reimplemented from app.js
    function generateMsgId() {
        const arr = new Uint8Array(16);
        randomFillSync(arr);
        return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    test('produces 32-char hex string', () => {
        const id = generateMsgId();
        assert.equal(id.length, 32);
        assert.match(id, /^[0-9a-f]{32}$/);
    });

    test('produces unique IDs', () => {
        const ids = new Set();
        for (let i = 0; i < 100; i++) ids.add(generateMsgId());
        assert.equal(ids.size, 100);
    });
});

describe('gossip dedup', () => {
    test('markGossipSeen and check', () => {
        const seen = new Set();
        const SEEN_MAX = 1000;

        function markSeen(msgId) {
            seen.add(msgId);
            if (seen.size > SEEN_MAX) {
                const first = seen.values().next().value;
                seen.delete(first);
            }
        }

        markSeen('msg1');
        markSeen('msg2');
        assert.equal(seen.has('msg1'), true);
        assert.equal(seen.has('msg2'), true);
        assert.equal(seen.has('msg3'), false);
    });

    test('rolling window evicts oldest', () => {
        const seen = new Set();
        const SEEN_MAX = 5;

        function markSeen(msgId) {
            seen.add(msgId);
            if (seen.size > SEEN_MAX) {
                const first = seen.values().next().value;
                seen.delete(first);
            }
        }

        for (let i = 0; i < 7; i++) markSeen('msg' + i);
        assert.equal(seen.size, 5);
        assert.equal(seen.has('msg0'), false); // evicted
        assert.equal(seen.has('msg1'), false); // evicted
        assert.equal(seen.has('msg6'), true);  // latest
    });
});

describe('message queue', () => {
    test('queue and flush', () => {
        const queue = [];
        const MAX_SIZE = 200;

        function queueMessage(toPeerId, payload) {
            if (queue.length >= MAX_SIZE) queue.shift();
            queue.push({ toPeerId, payload, timestamp: Date.now() });
        }

        queueMessage('peer1', 'hello');
        queueMessage('peer2', 'world');
        assert.equal(queue.length, 2);
        assert.equal(queue[0].toPeerId, 'peer1');
        assert.equal(queue[1].payload, 'world');
    });

    test('queue evicts oldest when full', () => {
        const queue = [];
        const MAX_SIZE = 3;

        function queueMessage(toPeerId, payload) {
            if (queue.length >= MAX_SIZE) queue.shift();
            queue.push({ toPeerId, payload, timestamp: Date.now() });
        }

        queueMessage('a', '1');
        queueMessage('b', '2');
        queueMessage('c', '3');
        queueMessage('d', '4'); // evicts 'a'
        assert.equal(queue.length, 3);
        assert.equal(queue[0].toPeerId, 'b');
        assert.equal(queue[2].toPeerId, 'd');
    });

    test('flush removes expired messages', () => {
        const queue = [];
        const MAX_AGE = 3600000;

        // Add an expired message
        queue.push({ toPeerId: 'old', payload: 'stale', timestamp: Date.now() - MAX_AGE - 1000 });
        // Add a fresh message
        queue.push({ toPeerId: 'new', payload: 'fresh', timestamp: Date.now() });

        // Simulate flush (without actual send)
        const flushed = [];
        const toFlush = queue.splice(0, queue.length);
        for (const msg of toFlush) {
            if (Date.now() - msg.timestamp > MAX_AGE) continue; // skip expired
            flushed.push(msg);
        }

        assert.equal(flushed.length, 1);
        assert.equal(flushed[0].toPeerId, 'new');
    });
});

describe('tracker peer ID derivation', () => {
    test('first 40 hex chars of 64-char PeerId', () => {
        const fullPeerId = 'abcdef0123456789'.repeat(4); // 64 chars
        const trackerPeerId = fullPeerId.slice(0, 40);
        assert.equal(trackerPeerId.length, 40);
        assert.equal(trackerPeerId, 'abcdef0123456789'.repeat(2) + 'abcdef01');
    });

    test('identity verification: first 20 bytes match', () => {
        const fullPeerId = 'aa'.repeat(32); // 64 hex chars = 32 bytes
        const trackerPeerId = fullPeerId.slice(0, 40); // first 20 bytes = 40 hex chars
        assert.equal(fullPeerId.startsWith(trackerPeerId), true);
    });
});

describe('connection status logic', () => {
    test('all connected = online', () => {
        const hasRelay = true, hasTracker = true, hasWebRTC = true;
        let status;
        if ((hasRelay || hasTracker) && hasWebRTC) status = 'online';
        else if (hasRelay || hasTracker || hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'online');
    });

    test('tracker only = partial', () => {
        const hasRelay = false, hasTracker = true, hasWebRTC = false;
        let status;
        if ((hasRelay || hasTracker) && hasWebRTC) status = 'online';
        else if (hasRelay || hasTracker || hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'partial');
    });

    test('nothing = offline', () => {
        const hasRelay = false, hasTracker = false, hasWebRTC = false;
        let status;
        if ((hasRelay || hasTracker) && hasWebRTC) status = 'online';
        else if (hasRelay || hasTracker || hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'offline');
    });

    test('WebRTC only = partial', () => {
        const hasRelay = false, hasTracker = false, hasWebRTC = true;
        let status;
        if ((hasRelay || hasTracker) && hasWebRTC) status = 'online';
        else if (hasRelay || hasTracker || hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'partial');
    });

    test('relay + WebRTC = online', () => {
        const hasRelay = true, hasTracker = false, hasWebRTC = true;
        let status;
        if ((hasRelay || hasTracker) && hasWebRTC) status = 'online';
        else if (hasRelay || hasTracker || hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'online');
    });

    test('relay only = partial', () => {
        const hasRelay = true, hasTracker = false, hasWebRTC = false;
        let status;
        if ((hasRelay || hasTracker) && hasWebRTC) status = 'online';
        else if (hasRelay || hasTracker || hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'partial');
    });
});

describe('tracker protocol messages', () => {
    test('announce message format', () => {
        const msg = {
            action: 'announce',
            info_hash: 'a'.repeat(40),
            peer_id: 'b'.repeat(40),
            numwant: 5,
            offers: [{
                offer_id: 'c'.repeat(20),
                offer: { type: 'offer', sdp: 'v=0\r\n...' }
            }]
        };
        const json = JSON.stringify(msg);
        const parsed = JSON.parse(json);
        assert.equal(parsed.action, 'announce');
        assert.equal(parsed.info_hash.length, 40);
        assert.equal(parsed.offers.length, 1);
        assert.equal(parsed.offers[0].offer.type, 'offer');
    });

    test('answer message format', () => {
        const msg = {
            action: 'announce',
            info_hash: 'a'.repeat(40),
            peer_id: 'b'.repeat(40),
            to_peer_id: 'c'.repeat(40),
            offer_id: 'd'.repeat(20),
            answer: { type: 'answer', sdp: 'v=0\r\n...' }
        };
        const json = JSON.stringify(msg);
        const parsed = JSON.parse(json);
        assert.equal(parsed.to_peer_id.length, 40);
        assert.equal(parsed.answer.type, 'answer');
    });
});

describe('hasDirectConnection', () => {
    test('returns true when dc is open', () => {
        const rtcConnections = {
            'peer1': { dc: { readyState: 'open' } }
        };
        function hasDirectConnection(peerId) {
            const conn = rtcConnections[peerId];
            return conn && conn.dc && conn.dc.readyState === 'open';
        }
        assert.equal(hasDirectConnection('peer1'), true);
    });

    test('returns false when dc is closed', () => {
        const rtcConnections = {
            'peer1': { dc: { readyState: 'closed' } }
        };
        function hasDirectConnection(peerId) {
            const conn = rtcConnections[peerId];
            return conn && conn.dc && conn.dc.readyState === 'open';
        }
        assert.equal(hasDirectConnection('peer1'), false);
    });

    test('returns false when no connection exists', () => {
        const rtcConnections = {};
        function hasDirectConnection(peerId) {
            const conn = rtcConnections[peerId];
            return conn && conn.dc && conn.dc.readyState === 'open';
        }
        assert.ok(!hasDirectConnection('peer1'));
    });

    test('returns false when dc is null', () => {
        const rtcConnections = { 'peer1': { dc: null } };
        function hasDirectConnection(peerId) {
            const conn = rtcConnections[peerId];
            return conn && conn.dc && conn.dc.readyState === 'open';
        }
        assert.ok(!hasDirectConnection('peer1'));
    });
});
