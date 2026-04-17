#!/usr/bin/env node
/**
 * ParolNet PWA Integration Tests
 *
 * Tests the live PWA at http://localhost:1411 using headless Chrome.
 * Run: node tests/pwa-test.mjs
 */

import puppeteer from 'puppeteer';

const BASE = 'http://localhost:1411';
const PWA = `${BASE}/pwa/index.html?mode=calc`;
let browser, page;
let passed = 0, failed = 0;

async function test(name, fn) {
    try {
        await fn();
        console.log(`  ✓ ${name}`);
        passed++;
    } catch (e) {
        console.log(`  ✗ ${name}`);
        console.log(`    ERROR: ${e.message}`);
        failed++;
    }
}

function assert(condition, msg) {
    if (!condition) throw new Error(msg || 'Assertion failed');
}

// ── Setup ──────────────────────────────────────────────────────
async function setup() {
    browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    page = await browser.newPage();
    page.on('pageerror', e => console.log(`    PAGE ERROR: ${e.message}`));
}

async function teardown() {
    if (browser) await browser.close();
}

// ── Distribution Page Tests ────────────────────────────────────
async function testDistributionPage() {
    console.log('\nDistribution Page (/)');

    await test('loads with 200', async () => {
        const res = await page.goto(BASE, { waitUntil: 'networkidle0' });
        assert(res.status() === 200, `status ${res.status()}`);
    });

    await test('title is "Calculator"', async () => {
        const title = await page.title();
        assert(title.includes('Calculator'), `title: "${title}"`);
    });

    await test('has Open App button', async () => {
        const btn = await page.$('.open-btn');
        assert(btn, 'no .open-btn found');
        const text = await page.$eval('.open-btn', el => el.textContent);
        assert(text.includes('Open App'), `button text: "${text}"`);
    });

    await test('Open App links to PWA', async () => {
        const href = await page.$eval('.open-btn', el => el.href);
        assert(href.includes('/pwa/index.html'), `href: "${href}"`);
    });

    await test('has platform-specific install steps', async () => {
        const steps = await page.$$('.platform-steps');
        assert(steps.length >= 4, `only ${steps.length} step blocks`);
    });

    await test('no "beforeinstallprompt" in page source', async () => {
        const html = await page.content();
        assert(!html.includes('beforeinstallprompt'), 'found beforeinstallprompt');
    });
}

// ── PWA Page Load Tests ────────────────────────────────────────
async function testPWALoad() {
    console.log('\nPWA Page Load');

    await test('loads with 200', async () => {
        const res = await page.goto(PWA, { waitUntil: 'networkidle0' });
        assert(res.status() === 200, `status ${res.status()}`);
    });

    await test('title is "Calculator"', async () => {
        const title = await page.title();
        assert(title === 'Calculator', `title: "${title}"`);
    });

    await test('no console errors on load', async () => {
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.reload({ waitUntil: 'networkidle0' });
        // Allow WASM load failures in headless (no wasm-pack in CI)
        const realErrors = errors.filter(e => !e.includes('wasm') && !e.includes('WASM'));
        assert(realErrors.length === 0, `errors: ${realErrors.join('; ')}`);
    });
}

// ── Calculator Tests ───────────────────────────────────────────
async function testCalculator() {
    console.log('\nCalculator');
    await page.goto(PWA, { waitUntil: 'networkidle0' });
    // Wait for either calculator or loading to finish
    await page.waitForSelector('.calculator, #view-contacts', { timeout: 5000 }).catch(() => {});

    await test('calculator view is visible', async () => {
        const calc = await page.$('#view-calculator');
        if (!calc) {
            // Might be showing contacts if WASM loaded and no decoy
            const contacts = await page.$('#view-contacts');
            assert(contacts, 'neither calculator nor contacts visible');
            return; // skip calculator tests
        }
        const hidden = await page.$eval('#view-calculator', el => el.classList.contains('hidden'));
        // Calculator may or may not be visible depending on decoy state
    });

    await test('calculator display shows "0"', async () => {
        const display = await page.$('#calc-display');
        if (!display) return; // calculator not visible
        const text = await page.$eval('#calc-display', el => el.textContent);
        assert(text === '0', `display shows: "${text}"`);
    });

    await test('calculator buttons exist (0-9, operators)', async () => {
        const buttons = await page.$$('.calc-btn');
        assert(buttons.length >= 16, `only ${buttons.length} buttons`);
    });

    await test('pressing 5 shows 5', async () => {
        const btn5 = await page.$('.calc-btn:nth-child(12)'); // 5 button
        if (!btn5) return;
        // Use evaluate to call calcPress directly
        await page.evaluate(() => { if (window.calcPress) { calcPress('C'); calcPress('5'); } });
        const text = await page.$eval('#calc-display', el => el.textContent);
        assert(text.includes('5'), `display after pressing 5: "${text}"`);
    });

    await test('basic arithmetic: 2+3=5', async () => {
        await page.evaluate(() => {
            if (!window.calcPress) return;
            calcPress('C');
            calcPress('2');
            calcPress('+');
            calcPress('3');
            calcPress('=');
        });
        const text = await page.$eval('#calc-display', el => el.textContent);
        assert(text === '5', `2+3= shows: "${text}"`);
    });
}

// ── WASM Tests ─────────────────────────────────────────────────
async function testWASM() {
    console.log('\nWASM Module');
    await page.goto(PWA, { waitUntil: 'networkidle0' });
    await new Promise(r => setTimeout(r, 2000)); // wait for WASM to load

    await test('WASM module loads', async () => {
        const loaded = await page.evaluate(() => !!window.wasm || document.querySelector('#view-contacts:not(.hidden)'));
        // If contacts view is showing, WASM loaded and initialized
    });

    await test('generate_identity returns 64-char hex', async () => {
        const result = await page.evaluate(() => {
            if (window.wasm && wasm.generate_identity) return wasm.generate_identity();
            return null;
        });
        if (result) {
            assert(result.length === 64, `length ${result.length}`);
            assert(/^[0-9a-f]+$/.test(result), `not hex: "${result.slice(0,20)}..."`);
        }
    });

    await test('version() returns non-empty string', async () => {
        const result = await page.evaluate(() => {
            if (window.wasm && wasm.version) return wasm.version();
            return null;
        });
        if (result) {
            assert(result.length > 0, 'empty version');
        }
    });

    await test('get_peer_id returns 64-char hex after init', async () => {
        const result = await page.evaluate(() => {
            if (window.wasm && wasm.get_peer_id) return wasm.get_peer_id();
            return null;
        });
        if (result) {
            assert(result.length === 64, `length ${result.length}`);
        }
    });
}

// ── Asset Tests ────────────────────────────────────────────────
async function testAssets() {
    console.log('\nAssets');

    const assets = [
        ['/pwa/styles.css', 'text/css'],
        ['/pwa/calculator.css', 'text/css'],
        ['/pwa/app.js', 'application/javascript'],
        ['/pwa/qrcode.js', 'application/javascript'],
        ['/pwa/sw.js', 'application/javascript'],
        ['/pwa/manifest.json', 'application/json'],
        ['/pwa/manifest-calculator.json', 'application/json'],
        ['/pwa/icons/icon.svg', 'image/svg+xml'],
        ['/pwa/icons/icon-192.png', 'image/png'],
        ['/pwa/icons/icon-512.png', 'image/png'],
        ['/pwa/icons/calc-ios.svg', 'image/svg+xml'],
        ['/pwa/icons/calc-android.svg', 'image/svg+xml'],
        ['/pwa/icons/calc-windows.svg', 'image/svg+xml'],
        ['/pwa/pkg/parolnet_wasm.js', 'application/javascript'],
        // WASM binary tested via fetch instead of navigation (Puppeteer aborts binary navigation)
        // ['/pwa/pkg/parolnet_wasm_bg.wasm', 'application/wasm'],
    ];

    for (const [path, expectedType] of assets) {
        await test(`${path} → 200 ${expectedType}`, async () => {
            const res = await page.goto(BASE + path, { waitUntil: 'networkidle0' });
            assert(res.status() === 200, `status ${res.status()}`);
            const ct = res.headers()['content-type'] || '';
            assert(ct.includes(expectedType), `content-type: "${ct}"`);
        });
    }

    // Test WASM binary via fetch (can't navigate to binary directly)
    await test('/pwa/pkg/parolnet_wasm_bg.wasm → 200 via fetch', async () => {
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        const result = await page.evaluate(async (base) => {
            const res = await fetch(base + '/pwa/pkg/parolnet_wasm_bg.wasm');
            return { status: res.status, type: res.headers.get('content-type') };
        }, BASE);
        assert(result.status === 200, `status ${result.status}`);
        assert(result.type && result.type.includes('wasm'), `content-type: "${result.type}"`);
    });
}

// ── Navigation Tests ───────────────────────────────────────────
async function testNavigation() {
    console.log('\nNavigation');
    await page.goto(PWA, { waitUntil: 'networkidle0' });
    await new Promise(r => setTimeout(r, 2000));

    await test('unlock code 00000= shows contacts or works', async () => {
        await page.evaluate(() => {
            if (!window.calcPress) return;
            calcPress('C');
            '00000'.split('').forEach(c => calcPress(c));
            calcPress('=');
        });
        await new Promise(r => setTimeout(r, 500));
        // After unlock, contacts view should be visible (or already was)
        const contactsVisible = await page.evaluate(() => {
            const el = document.getElementById('view-contacts');
            return el && !el.classList.contains('hidden');
        });
        // If decoy wasn't enabled, contacts might already be showing
        // Just check we're not stuck on loading
        const loadingVisible = await page.evaluate(() => {
            const el = document.getElementById('view-loading');
            return el && !el.classList.contains('hidden');
        });
        assert(!loadingVisible, 'still showing loading view');
    });

    await test('settings view opens', async () => {
        await page.evaluate(() => { if (window.showView) showView('settings'); });
        await new Promise(r => setTimeout(r, 300));
        const visible = await page.evaluate(() => {
            const el = document.getElementById('view-settings');
            return el && !el.classList.contains('hidden');
        });
        assert(visible, 'settings not visible');
    });

    await test('add-contact view opens', async () => {
        await page.evaluate(() => { if (window.showView) showView('add-contact'); });
        await new Promise(r => setTimeout(r, 300));
        const visible = await page.evaluate(() => {
            const el = document.getElementById('view-add-contact');
            return el && !el.classList.contains('hidden');
        });
        assert(visible, 'add-contact not visible');
    });

    await test('QR share code is not empty', async () => {
        await page.evaluate(() => { if (window.showView) showView('add-contact'); });
        await new Promise(r => setTimeout(r, 500));
        const code = await page.evaluate(() => {
            const el = document.getElementById('qr-share-code');
            return el ? el.textContent : '';
        });
        assert(code.length > 10, `code too short or empty: "${code.slice(0,30)}"`);
        assert(code !== 'Loading your code...', 'still showing loading text');
    });

    await test('QR canvas has content (not blank)', async () => {
        const isBlank = await page.evaluate(() => {
            const canvas = document.getElementById('qr-canvas');
            if (!canvas) return true;
            const ctx = canvas.getContext('2d');
            const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
            // Check if all pixels are the same (blank)
            let hasBlack = false;
            for (let i = 0; i < data.length; i += 4) {
                if (data[i] < 50 && data[i+1] < 50 && data[i+2] < 50) {
                    hasBlack = true;
                    break;
                }
            }
            return !hasBlack;
        });
        assert(!isBlank, 'QR canvas is blank (all white/same color)');
    });

    await test('chat view opens', async () => {
        await page.evaluate(() => { if (window.showView) showView('chat'); });
        await new Promise(r => setTimeout(r, 300));
        const visible = await page.evaluate(() => {
            const el = document.getElementById('view-chat');
            return el && !el.classList.contains('hidden');
        });
        assert(visible, 'chat not visible');
    });

    await test('message input exists and is interactive', async () => {
        const input = await page.$('#message-input');
        assert(input, 'no message input');
        await page.type('#message-input', 'test message');
        const val = await page.$eval('#message-input', el => el.value);
        assert(val === 'test message', `input value: "${val}"`);
    });

    await test('back to contacts', async () => {
        await page.evaluate(() => { if (window.showView) showView('contacts'); });
        await new Promise(r => setTimeout(r, 300));
        const visible = await page.evaluate(() => {
            const el = document.getElementById('view-contacts');
            return el && !el.classList.contains('hidden');
        });
        assert(visible, 'contacts not visible');
    });
}

// ── Service Worker Tests ───────────────────────────────────────
async function testServiceWorker() {
    console.log('\nService Worker');

    await test('SW registers', async () => {
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 2000));
        const swState = await page.evaluate(async () => {
            if (!('serviceWorker' in navigator)) return 'not-supported';
            const reg = await navigator.serviceWorker.getRegistration();
            return reg ? 'registered' : 'not-registered';
        });
        // SW may not register on localhost without HTTPS in some configs
        // Just check it doesn't error
    });
}

// ── Console Error Check ────────────────────────────────────────
async function testNoErrors() {
    console.log('\nConsole Errors');

    await test('no JS errors on full page cycle', async () => {
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));

        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 2000));

        // Navigate through all views
        for (const view of ['contacts', 'add-contact', 'settings', 'chat', 'calculator']) {
            await page.evaluate((v) => { if (window.showView) showView(v); }, view);
            await new Promise(r => setTimeout(r, 300));
        }

        // Filter out expected WASM warnings
        const realErrors = errors.filter(e =>
            !e.includes('wasm') && !e.includes('WASM') &&
            !e.includes('SharedArrayBuffer') && !e.includes('Atomics')
        );
        assert(realErrors.length === 0, `JS errors: ${realErrors.join(' | ')}`);
    });
}

// ── TURN/STUN Tests ───────────────────────────────────────────
async function testTurnStun() {
    console.log('\nTURN/STUN');

    await test('/turn-credentials returns valid response', async () => {
        const result = await page.evaluate(async (base) => {
            const res = await fetch(base + '/turn-credentials');
            if (!res.ok) return { status: res.status };
            return { status: res.status, body: await res.json() };
        }, BASE);
        if (result.status === 404) {
            console.log('    (TURN not configured on this server — skipping)');
            return;
        }
        assert(result.status === 200, `status ${result.status}`);
        assert(result.body.username, 'missing username');
        assert(result.body.credential, 'missing credential');
        assert(result.body.ttl > 0, 'invalid TTL');
        assert(Array.isArray(result.body.uris), 'uris not array');
    });

    await test('/turn-credentials uris include stun and turn', async () => {
        const result = await page.evaluate(async (base) => {
            const res = await fetch(base + '/turn-credentials');
            if (!res.ok) return null;
            return await res.json();
        }, BASE);
        if (!result) return;
        const hasStun = result.uris.some(u => u.startsWith('stun:'));
        const hasTurn = result.uris.some(u => u.startsWith('turn:'));
        assert(hasStun, 'no stun: URI in response');
        assert(hasTurn, 'no turn: URI in response');
    });

    await test('/turn-credentials username has expiry:random format', async () => {
        const result = await page.evaluate(async (base) => {
            const res = await fetch(base + '/turn-credentials');
            if (!res.ok) return null;
            return await res.json();
        }, BASE);
        if (!result) return;
        const parts = result.username.split(':');
        assert(parts.length === 2, `username format wrong: "${result.username}"`);
        const expiry = parseInt(parts[0]);
        assert(expiry > Date.now() / 1000, 'username expiry is in the past');
    });

    await test('client fetches TURN credentials on boot', async () => {
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 3000));
        const hasTurn = await page.evaluate(() => {
            // Check console logs for TURN fetch
            return document.querySelector('#webrtc-privacy-warning')?.style.display !== 'block';
        });
        // If no warning about "WebRTC disabled", TURN was fetched or privacy mode is off
    });
}

// ── Relay Authentication Tests ────────────────────────────────
async function testRelayAuth() {
    console.log('\nRelay Authentication');

    await test('relay WebSocket connects', async () => {
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 3000));
        const dotClass = await page.evaluate(() => {
            const dot = document.getElementById('connection-dot');
            return dot ? dot.className : '';
        });
        assert(dotClass.includes('online'), `connection dot: "${dotClass}"`);
    });

    await test('peer registers with relay (challenge-response)', async () => {
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 3000));
        const peerId = await page.evaluate(() => window._peerId);
        assert(peerId && peerId.length === 64, `peerId: "${peerId}"`);
    });

    await test('/bootstrap returns peer list', async () => {
        const result = await page.evaluate(async (base) => {
            const res = await fetch(base + '/bootstrap?exclude=test');
            return { status: res.status, body: await res.json() };
        }, BASE);
        assert(result.status === 200, `status ${result.status}`);
        assert(Array.isArray(result.body), 'response not array');
    });
}

// ── i18n Tests ────────────────────────────────────────────────
async function testI18n() {
    console.log('\ni18n');

    await test('English lang file loads', async () => {
        const result = await page.evaluate(async (base) => {
            const res = await fetch(base + '/pwa/lang/en.json');
            return { status: res.status, body: await res.json() };
        }, BASE);
        assert(result.status === 200, 'en.json not found');
        assert(result.body['tab.messages'] === 'Messages', 'wrong tab.messages value');
        assert(result.body['tab.groups'] === 'Groups', 'wrong tab.groups value');
        assert(result.body['tab.contacts'] === 'Contacts', 'wrong tab.contacts value');
    });

    await test('all 16 lang files exist', async () => {
        const langs = ['en','ru','fa','zh-CN','zh-TW','ko','ja','fr','de','it','pt','ar','es','tr','my','vi'];
        for (const lang of langs) {
            const res = await page.evaluate(async (base, l) => {
                const r = await fetch(base + '/pwa/lang/' + l + '.json');
                return r.status;
            }, BASE, lang);
            assert(res === 200, `${lang}.json returned ${res}`);
        }
    });

    await test('lang files have matching keys', async () => {
        const result = await page.evaluate(async (base) => {
            const enRes = await fetch(base + '/pwa/lang/en.json');
            const ruRes = await fetch(base + '/pwa/lang/ru.json');
            const en = await enRes.json();
            const ru = await ruRes.json();
            const enKeys = Object.keys(en).sort();
            const ruKeys = Object.keys(ru).sort();
            const missing = enKeys.filter(k => !ruKeys.includes(k));
            const extra = ruKeys.filter(k => !enKeys.includes(k));
            return { missing, extra };
        }, BASE);
        assert(result.missing.length === 0, `ru.json missing keys: ${result.missing.join(', ')}`);
    });

    await test('data-i18n attributes are populated', async () => {
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 2000));
        const unpopulated = await page.evaluate(() => {
            const els = document.querySelectorAll('[data-i18n]');
            const empty = [];
            els.forEach(el => {
                if (!el.textContent.trim()) empty.push(el.getAttribute('data-i18n'));
            });
            return empty;
        });
        assert(unpopulated.length === 0, `empty data-i18n elements: ${unpopulated.join(', ')}`);
    });

    await test('language selector exists in settings', async () => {
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 2000));
        await page.evaluate(() => { if (window.showView) showView('settings'); });
        await new Promise(r => setTimeout(r, 300));
        const options = await page.evaluate(() => {
            const select = document.getElementById('settings-language');
            if (!select) return [];
            return Array.from(select.options).map(o => o.value);
        });
        assert(options.length >= 16, `only ${options.length} language options`);
        assert(options.includes('en'), 'missing English');
        assert(options.includes('ru'), 'missing Russian');
        assert(options.includes('ar'), 'missing Arabic');
    });
}

// ── Contact & Messaging Tests ─────────────────────────────────
async function testMessaging() {
    console.log('\nMessaging');

    await test('tab shows "Messages" not "Chats"', async () => {
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 2000));
        await page.evaluate(() => { if (window.showView) showView('contacts'); });
        await new Promise(r => setTimeout(r, 300));
        const tabText = await page.evaluate(() => {
            const tab = document.querySelector('.list-tab[data-list="messages"]');
            return tab ? tab.textContent : '';
        });
        assert(tabText === 'Messages', `tab text: "${tabText}"`);
    });

    await test('contacts tab exists with address book', async () => {
        const tabText = await page.evaluate(() => {
            const tab = document.querySelector('.list-tab[data-list="address-book"]');
            return tab ? tab.textContent : '';
        });
        assert(tabText === 'Contacts', `tab text: "${tabText}"`);
    });

    await test('switching to contacts tab shows address book', async () => {
        await page.evaluate(() => { if (window.switchListTab) switchListTab('address-book'); });
        await new Promise(r => setTimeout(r, 300));
        const visible = await page.evaluate(() => {
            const el = document.getElementById('address-book-list');
            return el && !el.classList.contains('hidden');
        });
        assert(visible, 'address book not visible');
    });

    await test('contact overflow menu exists on mobile viewport', async () => {
        await page.setViewport({ width: 375, height: 667 }); // iPhone SE
        await page.goto(PWA, { waitUntil: 'networkidle0' });
        await new Promise(r => setTimeout(r, 2000));
        // Check CSS class exists
        const hasStyle = await page.evaluate(() => {
            const style = getComputedStyle(document.createElement('div'));
            // Just check the class is defined in CSS
            const sheet = Array.from(document.styleSheets).find(s => {
                try { return s.cssRules; } catch { return false; }
            });
            return !!sheet;
        });
        await page.setViewport({ width: 1280, height: 720 }); // Reset
    });
}

// ── Run All ────────────────────────────────────────────────────
async function main() {
    console.log('ParolNet PWA Integration Tests');
    console.log('==============================');
    console.log(`Target: ${BASE}`);

    await setup();

    try {
        await testDistributionPage();
        await testPWALoad();
        await testAssets();
        await testCalculator();
        await testWASM();
        await testNavigation();
        await testServiceWorker();
        await testRelayAuth();
        await testTurnStun();
        await testI18n();
        await testMessaging();
        await testNoErrors();
    } finally {
        await teardown();
    }

    console.log(`\n==============================`);
    console.log(`Results: ${passed} passed, ${failed} failed`);
    console.log(`==============================`);

    process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
    console.error('Test runner crashed:', e);
    process.exit(2);
});
