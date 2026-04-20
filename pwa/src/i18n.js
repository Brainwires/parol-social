// ParolNet PWA — Internationalization
// JSON lang files loaded at boot, cached by SW.

const SUPPORTED_LANGS = [
    'en', 'ru', 'fa', 'zh-CN', 'zh-TW', 'ko', 'ja',
    'fr', 'de', 'it', 'pt', 'ar', 'es', 'tr', 'my', 'vi'
];

const RTL_LANGS = ['ar', 'fa'];

let strings = {};
let enStrings = {};
let currentLang = 'en';

export async function initI18n(savedLang) {
    currentLang = savedLang || detectLanguage();
    if (!SUPPORTED_LANGS.includes(currentLang)) currentLang = 'en';
    // Always load English first so missing-key fallback works even after
    // switching to another language whose catalog lacks a new key.
    try {
        const enResp = await fetch('./lang/en.json');
        if (enResp.ok) enStrings = await enResp.json();
    } catch {
        // Offline / cache miss — enStrings stays empty and t() falls back
        // to the key itself, same as the legacy behaviour.
    }
    await loadStrings(currentLang);
    applyToDOM();
}

async function loadStrings(lang) {
    if (lang === 'en') {
        strings = enStrings;
        return;
    }
    try {
        const resp = await fetch('./lang/' + lang + '.json');
        if (!resp.ok) throw new Error(resp.status);
        strings = await resp.json();
    } catch {
        strings = enStrings;
        currentLang = 'en';
    }
}

export function t(key, params) {
    // Fallback chain: current-language string → English string → key name.
    // This keeps new keys readable in non-English locales until a translator
    // localizes them, instead of showing "toast.foo" to end users.
    let str = strings[key] || enStrings[key] || key;
    if (params) {
        for (const [k, v] of Object.entries(params)) {
            str = str.replaceAll('{' + k + '}', v);
        }
    }
    return str;
}

export function getCurrentLang() {
    return currentLang;
}

export async function changeLanguage(lang) {
    if (!SUPPORTED_LANGS.includes(lang)) return;
    currentLang = lang;
    await loadStrings(lang);
    applyToDOM();
}

// Pure, testable matcher: given the browser's ordered preference list and
// the set of supported locale codes, return the best match or 'en'.
//   Rules:
//     1. Exact match on a preferred tag (case-insensitive).
//     2. Chinese region aliasing: zh-Hant / zh-HK / zh-TW / zh-MO → zh-TW;
//        any other zh-* (Hans, CN, SG, …) → zh-CN.
//     3. Base-language match (e.g. 'fr-CA' → 'fr', 'pt-BR' → 'pt').
//     4. Fallback: 'en'.
//   The first preference that yields any match wins; we do not skip ahead
//   to a later preference merely because the earlier one only matched at
//   the base level — that's what the user actually asked for.
export function detectLocale(prefs, supported) {
    if (!Array.isArray(prefs) || prefs.length === 0) prefs = ['en'];
    if (!Array.isArray(supported) || supported.length === 0) return 'en';
    const supportedLower = supported.map(s => s.toLowerCase());
    const origByLower = new Map(supported.map(s => [s.toLowerCase(), s]));

    for (const raw of prefs) {
        if (!raw || typeof raw !== 'string') continue;
        const pref = raw.trim();
        if (!pref) continue;
        const lower = pref.toLowerCase();

        // 1. Exact match.
        if (supportedLower.includes(lower)) return origByLower.get(lower);

        const base = lower.split('-')[0];

        // 2. Chinese region aliasing.
        if (base === 'zh') {
            const isTraditional = /(^|-)hant(-|$)/.test(lower)
                || /-(hk|tw|mo)(-|$)/.test(lower);
            if (isTraditional && supportedLower.includes('zh-tw')) {
                return origByLower.get('zh-tw');
            }
            if (supportedLower.includes('zh-cn')) return origByLower.get('zh-cn');
        }

        // 3. Base-language match.
        if (supportedLower.includes(base)) return origByLower.get(base);
    }

    // 4. Fallback.
    return supportedLower.includes('en') ? origByLower.get('en') : supported[0];
}

function detectLanguage() {
    const prefs = (typeof navigator !== 'undefined' && Array.isArray(navigator.languages) && navigator.languages.length)
        ? navigator.languages
        : [ (typeof navigator !== 'undefined' && (navigator.language || navigator.userLanguage)) || 'en' ];
    return detectLocale(prefs, SUPPORTED_LANGS);
}

export function applyToDOM() {
    const isRtl = RTL_LANGS.includes(currentLang);
    document.documentElement.lang = currentLang;
    document.documentElement.dir = isRtl ? 'rtl' : 'ltr';

    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.textContent = t(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        el.title = t(el.getAttribute('data-i18n-title'));
    });
    document.querySelectorAll('[data-i18n-html]').forEach(el => {
        el.innerHTML = t(el.getAttribute('data-i18n-html'));
    });
}

export { SUPPORTED_LANGS };
