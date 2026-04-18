// Puppeteer-based end-to-end harness for the PWA.
//
// See pwa/tests/e2e/README.md for the design and operator instructions.
//
// This file is intentionally skip-clean when puppeteer is not installed — the
// scaffolding lives in the repo so CI + contributors can wire up their local
// dev env once and re-run without diffing test code. Actual per-test browser
// driving lands in a follow-up.

import { test, describe } from 'node:test';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Detect whether puppeteer is installed in pwa/node_modules. The E2E suite
 * skips cleanly when it's absent so the default `npm test` doesn't require
 * a 200 MB Chromium download.
 */
function puppeteerAvailable() {
    return existsSync(join(__dirname, '..', '..', 'node_modules', 'puppeteer', 'package.json'));
}

/**
 * Resolved config for the stack the harness talks to. Overridable via env so
 * operators can point at staging without editing code.
 */
const RELAY_URL = process.env.E2E_RELAY_URL || 'ws://localhost:9000/ws';
const PWA_BASE = process.env.E2E_PWA_BASE || 'http://localhost:1411';
const TURN_HOST = process.env.E2E_TURN_HOST || 'localhost:3478';

const SUITE_SKIP = !puppeteerAvailable();

describe('PWA end-to-end (Puppeteer)', () => {
    if (SUITE_SKIP) {
        test('suite skipped — puppeteer not installed', { skip: true }, () => {});
        return;
    }

    test('golden-path: Alice and Bob exchange text over WebRTC', async (t) => {
        // Imports deferred so a clean `npm test` without puppeteer doesn't try
        // to resolve the package at module-eval time.
        const { default: puppeteer } = await import('puppeteer');
        t.skip('stub — actual UI driving not wired yet');
        void puppeteer;
    });

    test('file transfer: 2 MiB blob reassembles via PNP-001 §3.9 fragmentation', async (t) => {
        t.skip('stub — depends on #5 fragmentation wiring into file transfer UI');
    });

    test('1:1 call: ICE via coturn TURN relay succeeds', async (t) => {
        t.skip('stub — requires compose coturn running on E2E_TURN_HOST');
    });

    test('group call (PNP-009): 3-party media mesh establishes', async (t) => {
        t.skip('stub — requires three contexts + compose relay + coturn');
    });

    test('TURN round-trip: credential fetch → relay → coturn allocation', async (t) => {
        t.skip('stub — requires E2E_RELAY_URL + E2E_TURN_HOST reachable');
    });
});

// Export the stack config so follow-up implementation can import it
// instead of re-reading env inside each test.
export const E2E_CONFIG = Object.freeze({
    RELAY_URL,
    PWA_BASE,
    TURN_HOST,
});
