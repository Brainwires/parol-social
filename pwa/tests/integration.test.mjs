import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

// Check if 'ws' module is available
let WebSocket, WebSocketServer;
try {
    const ws = await import('ws');
    WebSocket = ws.default;
    WebSocketServer = ws.WebSocketServer;
} catch(e) {
    console.log('Skipping integration tests: "ws" package not installed');
    console.log('Install with: npm install --save-dev ws');
    process.exit(0);
}

function sha1Hex(input) {
    return createHash('sha1').update(input).digest('hex');
}

describe('mock tracker integration', () => {
    let server;
    let serverPort;

    before(async () => {
        // Start a mock WebTorrent tracker
        server = new WebSocketServer({ port: 0 });
        serverPort = server.address().port;

        // Track connected peers by info_hash
        const peers = new Map(); // info_hash -> Map<peer_id, ws>

        server.on('connection', (ws) => {
            let clientPeerId = null;

            ws.on('message', (data) => {
                const msg = JSON.parse(data.toString());

                if (msg.action === 'announce') {
                    const hash = msg.info_hash;
                    clientPeerId = msg.peer_id;

                    if (!peers.has(hash)) peers.set(hash, new Map());
                    const hashPeers = peers.get(hash);
                    hashPeers.set(clientPeerId, ws);

                    // If this announce has offers, try to match with another peer
                    if (msg.offers && msg.offers.length > 0) {
                        for (const [otherPeerId, otherWs] of hashPeers) {
                            if (otherPeerId === clientPeerId) continue;
                            if (otherWs.readyState !== 1) continue; // WebSocket.OPEN

                            // Forward the first offer to the other peer
                            const offer = msg.offers[0];
                            otherWs.send(JSON.stringify({
                                action: 'announce',
                                peer_id: clientPeerId,
                                offer_id: offer.offer_id,
                                offer: offer.offer
                            }));
                            break;
                        }
                    }

                    // If this announce has an answer, forward it
                    if (msg.answer && msg.to_peer_id) {
                        const targetWs = hashPeers.get(msg.to_peer_id);
                        if (targetWs && targetWs.readyState === 1) {
                            targetWs.send(JSON.stringify({
                                offer_id: msg.offer_id,
                                answer: msg.answer
                            }));
                        }
                    }
                }
            });

            ws.on('close', () => {
                if (clientPeerId) {
                    for (const [, hashPeers] of peers) {
                        hashPeers.delete(clientPeerId);
                    }
                }
            });
        });
    });

    after(() => {
        server.close();
    });

    test('two peers discover each other via mock tracker', async () => {
        const infoHash = sha1Hex('parolnet-mesh-v1');
        const peerA_id = randomBytes(20).toString('hex');
        const peerB_id = randomBytes(20).toString('hex');

        const wsA = new WebSocket(`ws://localhost:${serverPort}`);
        const wsB = new WebSocket(`ws://localhost:${serverPort}`);

        await Promise.all([
            new Promise(r => wsA.on('open', r)),
            new Promise(r => wsB.on('open', r))
        ]);

        // Peer B announces first (no offers, just registers)
        wsB.send(JSON.stringify({
            action: 'announce',
            info_hash: infoHash,
            peer_id: peerB_id,
            numwant: 5,
            offers: []
        }));

        // Small delay for registration
        await new Promise(r => setTimeout(r, 100));

        // Peer A announces with an offer
        const offerId = randomBytes(10).toString('hex');
        const fakeOffer = { type: 'offer', sdp: 'v=0\r\nfake-sdp-from-A' };

        wsA.send(JSON.stringify({
            action: 'announce',
            info_hash: infoHash,
            peer_id: peerA_id,
            numwant: 5,
            offers: [{ offer_id: offerId, offer: fakeOffer }]
        }));

        // Peer B should receive the offer
        const offerMsg = await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('timeout waiting for offer')), 5000);
            wsB.on('message', (data) => {
                const msg = JSON.parse(data.toString());
                if (msg.offer) {
                    clearTimeout(timeout);
                    resolve(msg);
                }
            });
        });

        assert.equal(offerMsg.peer_id, peerA_id);
        assert.equal(offerMsg.offer_id, offerId);
        assert.equal(offerMsg.offer.sdp, 'v=0\r\nfake-sdp-from-A');

        // Peer B sends an answer back
        const fakeAnswer = { type: 'answer', sdp: 'v=0\r\nfake-sdp-from-B' };
        wsB.send(JSON.stringify({
            action: 'announce',
            info_hash: infoHash,
            peer_id: peerB_id,
            to_peer_id: peerA_id,
            offer_id: offerId,
            answer: fakeAnswer
        }));

        // Peer A should receive the answer
        const answerMsg = await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('timeout waiting for answer')), 5000);
            wsA.on('message', (data) => {
                const msg = JSON.parse(data.toString());
                if (msg.answer) {
                    clearTimeout(timeout);
                    resolve(msg);
                }
            });
        });

        assert.equal(answerMsg.offer_id, offerId);
        assert.equal(answerMsg.answer.sdp, 'v=0\r\nfake-sdp-from-B');

        wsA.close();
        wsB.close();
    });

    test('contact-specific hash isolates peers', async () => {
        const contactHash = sha1Hex('peerA:peerB:parolnet-contact');
        const meshHash = sha1Hex('parolnet-mesh-v1');

        // These should be different
        assert.notEqual(contactHash, meshHash);
        assert.equal(contactHash.length, 40);

        const peerC_id = randomBytes(20).toString('hex');
        const peerD_id = randomBytes(20).toString('hex');

        const wsC = new WebSocket(`ws://localhost:${serverPort}`);
        const wsD = new WebSocket(`ws://localhost:${serverPort}`);

        await Promise.all([
            new Promise(r => wsC.on('open', r)),
            new Promise(r => wsD.on('open', r))
        ]);

        // Peer C announces on contact hash
        wsC.send(JSON.stringify({
            action: 'announce',
            info_hash: contactHash,
            peer_id: peerC_id,
            numwant: 1,
            offers: []
        }));

        // Peer D announces on MESH hash (different!)
        wsD.send(JSON.stringify({
            action: 'announce',
            info_hash: meshHash,
            peer_id: peerD_id,
            numwant: 1,
            offers: [{ offer_id: randomBytes(10).toString('hex'), offer: { type: 'offer', sdp: 'test' } }]
        }));

        // Peer C should NOT receive D's offer (different info_hash)
        let receivedOffer = false;
        wsC.on('message', (data) => {
            const msg = JSON.parse(data.toString());
            if (msg.offer) receivedOffer = true;
        });

        await new Promise(r => setTimeout(r, 500));
        assert.equal(receivedOffer, false, 'Peer C should not receive offers from a different info_hash');

        wsC.close();
        wsD.close();
    });

    test('multiple peers on same hash all discover each other', async () => {
        const hash = sha1Hex('test-multi-peer');
        const peers = [];

        for (let i = 0; i < 3; i++) {
            const ws = new WebSocket(`ws://localhost:${serverPort}`);
            await new Promise(r => ws.on('open', r));
            const id = randomBytes(20).toString('hex');
            peers.push({ ws, id });

            ws.send(JSON.stringify({
                action: 'announce',
                info_hash: hash,
                peer_id: id,
                numwant: 5,
                offers: []
            }));
        }

        await new Promise(r => setTimeout(r, 100));

        // Peer 0 announces with offers -- should be forwarded to peer 1 or 2
        const offerId = randomBytes(10).toString('hex');
        peers[0].ws.send(JSON.stringify({
            action: 'announce',
            info_hash: hash,
            peer_id: peers[0].id,
            numwant: 5,
            offers: [{ offer_id: offerId, offer: { type: 'offer', sdp: 'multi-test' } }]
        }));

        // At least one other peer should receive the offer
        const received = await Promise.race([
            new Promise(resolve => {
                peers[1].ws.on('message', (data) => {
                    const msg = JSON.parse(data.toString());
                    if (msg.offer) resolve(msg);
                });
                peers[2].ws.on('message', (data) => {
                    const msg = JSON.parse(data.toString());
                    if (msg.offer) resolve(msg);
                });
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000))
        ]);

        assert.equal(received.peer_id, peers[0].id);
        assert.equal(received.offer.sdp, 'multi-test');

        for (const p of peers) p.ws.close();
    });
});
