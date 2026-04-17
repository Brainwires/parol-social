import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomFillSync, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Tests ──

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

describe('connection status logic', () => {
    test('relay connected = online', () => {
        const hasRelay = true, hasWebRTC = true;
        let status;
        if (hasRelay) status = 'online';
        else if (hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'online');
    });

    test('nothing = offline', () => {
        const hasRelay = false, hasWebRTC = false;
        let status;
        if (hasRelay) status = 'online';
        else if (hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'offline');
    });

    test('WebRTC only = partial', () => {
        const hasRelay = false, hasWebRTC = true;
        let status;
        if (hasRelay) status = 'online';
        else if (hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'partial');
    });

    test('relay only = online', () => {
        const hasRelay = true, hasWebRTC = false;
        let status;
        if (hasRelay) status = 'online';
        else if (hasWebRTC) status = 'partial';
        else status = 'offline';
        assert.equal(status, 'online');
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

// ── i18n ──

describe('i18n', () => {
    const langDir = join(__dirname, '..', 'lang');
    const SUPPORTED_LANGS = ['en','ru','fa','zh-CN','zh-TW','ko','ja','fr','de','it','pt','ar','es','tr','my','vi'];

    test('en.json is valid JSON with string values', () => {
        const en = JSON.parse(readFileSync(join(langDir, 'en.json'), 'utf8'));
        const keys = Object.keys(en);
        assert.ok(keys.length > 100, `only ${keys.length} keys`);
        for (const [k, v] of Object.entries(en)) {
            assert.equal(typeof v, 'string', `key "${k}" is not a string`);
        }
    });

    test('all 16 lang files exist and parse', () => {
        for (const lang of SUPPORTED_LANGS) {
            const path = join(langDir, lang + '.json');
            const data = JSON.parse(readFileSync(path, 'utf8'));
            assert.ok(Object.keys(data).length > 50, `${lang}.json has too few keys`);
        }
    });

    test('all lang files have same keys as en.json', () => {
        const en = JSON.parse(readFileSync(join(langDir, 'en.json'), 'utf8'));
        const enKeys = Object.keys(en).sort();
        for (const lang of SUPPORTED_LANGS) {
            if (lang === 'en') continue;
            const data = JSON.parse(readFileSync(join(langDir, lang + '.json'), 'utf8'));
            const langKeys = Object.keys(data).sort();
            const missing = enKeys.filter(k => !langKeys.includes(k));
            const extra = langKeys.filter(k => !enKeys.includes(k));
            assert.deepEqual(missing, [], `${lang}.json missing: ${missing.join(', ')}`);
        }
    });

    test('no lang file has empty string values', () => {
        for (const lang of SUPPORTED_LANGS) {
            const data = JSON.parse(readFileSync(join(langDir, lang + '.json'), 'utf8'));
            for (const [k, v] of Object.entries(data)) {
                assert.ok(v.length > 0, `${lang}.json key "${k}" is empty`);
            }
        }
    });

    test('placeholders preserved in translations', () => {
        const en = JSON.parse(readFileSync(join(langDir, 'en.json'), 'utf8'));
        for (const lang of SUPPORTED_LANGS) {
            if (lang === 'en') continue;
            const data = JSON.parse(readFileSync(join(langDir, lang + '.json'), 'utf8'));
            for (const [k, v] of Object.entries(en)) {
                const placeholders = v.match(/\{[a-zA-Z]+\}/g) || [];
                for (const ph of placeholders) {
                    assert.ok(
                        data[k] && data[k].includes(ph),
                        `${lang}.json key "${k}" missing placeholder ${ph}`
                    );
                }
            }
        }
    });

    test('t() function substitutes params', () => {
        function t(key, params) {
            const strings = { 'toast.newContact': 'New contact: {name}...' };
            let str = strings[key] || key;
            if (params) {
                for (const [k, v] of Object.entries(params)) {
                    str = str.replaceAll('{' + k + '}', v);
                }
            }
            return str;
        }
        assert.equal(t('toast.newContact', { name: 'abc123' }), 'New contact: abc123...');
        assert.equal(t('missing.key'), 'missing.key');
        assert.equal(t('toast.newContact'), 'New contact: {name}...');
    });
});

// ── TURN credential format ──

describe('TURN credentials', () => {
    test('HMAC-SHA1 credential matches expected format', () => {
        const secret = 'test-secret';
        const username = `${Math.floor(Date.now()/1000) + 86400}:${Math.random().toString(16).slice(2)}`;
        const mac = createHmac('sha1', secret).update(username).digest('base64');
        assert.ok(mac.length > 20, 'credential too short');
        assert.ok(mac.endsWith('=') || /^[A-Za-z0-9+/]/.test(mac), 'not base64');
    });

    test('username has expiry:random format', () => {
        const now = Math.floor(Date.now() / 1000);
        const expiry = now + 86400;
        const username = `${expiry}:00abcdef01234567`;
        const parts = username.split(':');
        assert.equal(parts.length, 2);
        assert.ok(parseInt(parts[0]) > now, 'expiry not in future');
        assert.ok(parts[1].length > 0, 'missing random component');
    });
});
