#!/usr/bin/env node
// ParolNet PWA Build Script
// Bundles JS modules, computes integrity hashes, updates sw.js, generates build-info.
//
// Usage:
//   node pwa/build.mjs              # Production build
//   node pwa/build.mjs --watch      # Dev mode (watch + serve)

import * as esbuild from 'esbuild';
import { createHash } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { execSync } from 'child_process';
import { dirname, join, basename } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const isWatch = process.argv.includes('--watch');

function sha256(filePath) {
    const data = readFileSync(filePath);
    return createHash('sha256').update(data).digest('hex');
}

// Parse the ASSETS_TO_CACHE array out of sw.source.js — so adding an entry
// there automatically integrity-pins it. Returns an array of relative paths
// (e.g. "app.js", "pkg/parolnet_wasm_bg.wasm", "lang/en.json").
function parseCachedAssets(source) {
    const m = source.match(/const ASSETS_TO_CACHE = \[([\s\S]*?)\];/);
    if (!m) throw new Error('sw.source.js missing ASSETS_TO_CACHE array');
    const entries = [];
    for (const line of m[1].split('\n')) {
        const s = line.match(/['"]([^'"]+)['"]/);
        if (!s) continue;
        const rel = s[1].replace(/^\.\//, '');
        entries.push(rel);
    }
    return entries;
}

function patchSwHashes() {
    const sourcePath = join(__dirname, 'sw.source.js');
    const outPath = join(__dirname, 'sw.js');
    const source = readFileSync(sourcePath, 'utf8');

    // Hash every cached asset that resolves to a real file on disk. Entries
    // like "./" (the app shell) and assets not yet built are silently skipped.
    const assets = parseCachedAssets(source);
    const hashes = {};
    const missing = [];
    for (const rel of assets) {
        if (rel === '' || rel.endsWith('/')) continue;
        const abs = join(__dirname, rel);
        if (!existsSync(abs)) { missing.push(rel); continue; }
        hashes[rel] = sha256(abs);
    }

    const marker = 'const RESOURCE_HASHES = __RESOURCE_HASHES__;';
    if (!source.includes(marker)) {
        throw new Error('sw.source.js missing placeholder line: ' + marker);
    }
    const out = source.replace(marker, `const RESOURCE_HASHES = ${JSON.stringify(hashes, null, 4)};`);

    writeFileSync(outPath, out);
    console.log(`  SW generated from sw.source.js (${Object.keys(hashes).length} assets hashed${missing.length ? `, ${missing.length} skipped: ${missing.join(', ')}` : ''})`);
}

function generateBuildInfo() {
    const date = new Date().toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
    let commit = 'unknown';
    try { commit = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim(); } catch {}
    const info = `window.BUILD_INFO={date:'dev ${date}',dev:true};`;
    writeFileSync(join(__dirname, 'build-info.js'), info);
    console.log(`  Build info: ${date} (${commit})`);
}

// ── esbuild config ──────────────────────────────────────────
const config = {
    entryPoints: ['src/boot.js'],
    bundle: true,
    outfile: 'app.js',
    format: 'esm',
    sourcemap: true,
    target: ['es2020'],
    absWorkingDir: __dirname,
    external: [
        './crypto-store.js',
        './data-export.js',
        './relay-client.js',
        './pkg/parolnet_wasm.js',
        './network-config.js',
        './build-info.js',
    ],
};

// ── Run ─────────────────────────────────────────────────────
if (isWatch) {
    const ctx = await esbuild.context(config);
    await ctx.watch();
    console.log('Watching for changes...');
} else {
    console.log('Building PWA JS...');
    const t0 = performance.now();
    await esbuild.build(config);
    const ms = Math.round(performance.now() - t0);
    console.log(`  Bundled in ${ms}ms`);
    patchSwHashes();
    generateBuildInfo();
    console.log('Done.');
}
