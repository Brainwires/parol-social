import puppeteer from 'puppeteer';

const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage();

const errors = [];
const warnings = [];
page.on('pageerror', e => errors.push('PAGE ERROR: ' + e.message));
page.on('console', msg => {
    if (msg.type() === 'error') errors.push('CONSOLE ERROR: ' + msg.text());
    if (msg.type() === 'warning') warnings.push('CONSOLE WARN: ' + msg.text());
});

await page.goto('http://localhost:1411/pwa/index.html?mode=calc', { waitUntil: 'networkidle0' });
await new Promise(r => setTimeout(r, 3000));

// Which view is showing?
const viewStates = await page.evaluate(() => {
    const views = ['loading','calculator','contacts','add-contact','chat','call','settings'];
    const result = {};
    views.forEach(v => {
        const el = document.getElementById('view-' + v);
        result[v] = el ? !el.classList.contains('hidden') : 'MISSING';
    });
    return result;
});
console.log('=== VIEW STATES ===');
console.log(JSON.stringify(viewStates, null, 2));

// WASM and JS state
const wasmState = await page.evaluate(() => ({
    wasmExists: !!window.wasm,
    peerId: window._peerId || null,
    makeQR: typeof window.makeQR,
    renderQRToCanvas: typeof window.renderQRToCanvas,
    calcPress: typeof window.calcPress,
    showView: typeof window.showView,
    sendMessage: typeof window.sendMessage,
    openChat: typeof window.openChat,
    initiateCall: typeof window.initiateCall,
    attachFile: typeof window.attachFile,
    connectViaPassphrase: typeof window.connectViaPassphrase,
}));
console.log('\n=== JS GLOBALS ===');
console.log(JSON.stringify(wasmState, null, 2));

// Navigate to add-contact, check QR
await page.evaluate(() => { if (window.showView) showView('add-contact'); });
await new Promise(r => setTimeout(r, 1000));

const qrState = await page.evaluate(() => {
    const canvas = document.getElementById('qr-canvas');
    const codeEl = document.getElementById('qr-share-code');
    let canvasBlank = true;
    if (canvas) {
        const ctx = canvas.getContext('2d');
        const d = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
        for (let i = 0; i < d.length; i += 4) {
            if (d[i] < 50) { canvasBlank = false; break; }
        }
    }
    return {
        canvasExists: !!canvas,
        canvasBlank,
        codeText: codeEl ? codeEl.textContent.slice(0, 100) : 'ELEMENT MISSING',
        codeLength: codeEl ? codeEl.textContent.length : 0,
    };
});
console.log('\n=== QR CODE STATE ===');
console.log(JSON.stringify(qrState, null, 2));

// Check for broken onclick handlers
const brokenHandlers = await page.evaluate(() => {
    const broken = [];
    document.querySelectorAll('[onclick]').forEach(el => {
        const handler = el.getAttribute('onclick');
        const fnName = handler.match(/^(\w+)\(/)?.[1];
        if (fnName && typeof window[fnName] !== 'function') {
            broken.push({ text: el.textContent.trim().slice(0,30), onclick: handler, error: fnName + ' not a function' });
        }
        if (handler.includes('alert(')) {
            broken.push({ text: el.textContent.trim().slice(0,30), onclick: handler, error: 'uses alert()' });
        }
    });
    return broken;
});
console.log('\n=== BROKEN HANDLERS ===');
console.log(JSON.stringify(brokenHandlers, null, 2));

// Check settings peer ID
await page.evaluate(() => { if (window.showView) showView('settings'); });
await new Promise(r => setTimeout(r, 500));
const settingsState = await page.evaluate(() => ({
    peerId: document.getElementById('settings-peer-id')?.textContent || 'MISSING',
    version: document.getElementById('settings-version')?.textContent || 'MISSING',
}));
console.log('\n=== SETTINGS ===');
console.log(JSON.stringify(settingsState, null, 2));

// Try sending a message
await page.evaluate(() => { if (window.showView) showView('chat'); });
await new Promise(r => setTimeout(r, 300));
const chatState = await page.evaluate(() => ({
    inputExists: !!document.getElementById('message-input'),
    messageListExists: !!document.getElementById('message-list'),
    messageCount: document.querySelectorAll('.message').length,
    sendBtnExists: !!document.querySelector('.send-btn'),
}));
console.log('\n=== CHAT ===');
console.log(JSON.stringify(chatState, null, 2));

console.log('\n=== ERRORS ===');
errors.forEach(e => console.log('  ' + e));
if (errors.length === 0) console.log('  None');

console.log('\n=== WARNINGS ===');
warnings.forEach(w => console.log('  ' + w));
if (warnings.length === 0) console.log('  None');

// Take screenshot
await page.evaluate(() => { if (window.showView) showView('add-contact'); });
await new Promise(r => setTimeout(r, 500));
await page.screenshot({ path: '/tmp/pwa-qr-screen.png', fullPage: true });
console.log('\nScreenshot saved to /tmp/pwa-qr-screen.png');

await browser.close();
