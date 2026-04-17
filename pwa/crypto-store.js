// ParolNet PWA — Encrypted Storage Layer
// AES-256-GCM with PBKDF2 key derivation via Web Crypto API.
// Zero external dependencies.

async function deriveKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptValue(key, value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const data = enc.encode(JSON.stringify(value));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    // Combine iv + ciphertext into single Uint8Array
    const result = new Uint8Array(12 + ct.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ct), 12);
    return result;
}

async function decryptValue(key, encrypted) {
    // encrypted is Uint8Array: first 12 bytes IV, rest ciphertext
    const buf = encrypted instanceof Uint8Array ? encrypted : new Uint8Array(encrypted);
    const iv = buf.slice(0, 12);
    const ct = buf.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(plain));
}

export class CryptoStore {
    constructor() {
        this._key = null;
        this._enabled = false;
    }

    isEnabled() { return this._enabled; }
    isUnlocked() { return this._key !== null; }

    // First-time setup: generate salt, derive key, store verification token.
    // If duressPassphrase is provided (non-empty), also generates a second
    // salt + verifier so unlock can branch into the silent-wipe path.
    async setup(passphrase, duressPassphrase, dbPutRaw, dbGetRaw) {
        // Back-compat: old callers pass (passphrase, dbPutRaw, dbGetRaw).
        // Detect by arity — if the second arg is a function, shift.
        if (typeof duressPassphrase === 'function') {
            dbGetRaw = dbPutRaw;
            dbPutRaw = duressPassphrase;
            duressPassphrase = undefined;
        }

        const salt = crypto.getRandomValues(new Uint8Array(16));
        this._key = await deriveKey(passphrase, salt);

        // Store salt (unencrypted — it's not secret)
        await dbPutRaw('crypto_meta', { key: 'salt', value: Array.from(salt) });

        // Store verification token: encrypt a known string so we can verify passphrase on unlock
        const verifier = await encryptValue(this._key, { verify: 'parolnet' });
        await dbPutRaw('crypto_meta', { key: 'verifier', value: Array.from(verifier) });

        // Optional duress credential
        if (duressPassphrase !== undefined && duressPassphrase !== null && duressPassphrase !== '') {
            if (duressPassphrase === passphrase) {
                throw new Error('Duress passphrase must differ from real passphrase');
            }
            const duressSalt = crypto.getRandomValues(new Uint8Array(16));
            const duressKey = await deriveKey(duressPassphrase, duressSalt);
            const duressVerifier = await encryptValue(duressKey, { verify: 'parolnet-duress' });
            await dbPutRaw('crypto_meta', { key: 'duress_salt', value: Array.from(duressSalt) });
            await dbPutRaw('crypto_meta', { key: 'duress_verifier', value: Array.from(duressVerifier) });
        }

        this._enabled = true;
    }

    // Add or replace a duress credential for an already-set-up store. Verifies
    // the caller actually knows the real passphrase by re-deriving the real key
    // from the stored salt and decrypting the existing verifier.
    async addDuressCredential(passphrase, duressPassphrase, dbPutRaw, dbGetRaw) {
        if (duressPassphrase === undefined || duressPassphrase === null || duressPassphrase === '') {
            throw new Error('Duress passphrase required');
        }
        if (duressPassphrase === passphrase) {
            throw new Error('Duress passphrase must differ from real passphrase');
        }

        const saltRecord = await dbGetRaw('crypto_meta', 'salt');
        if (!saltRecord || !saltRecord.value) throw new Error('No encryption configured');
        const salt = new Uint8Array(saltRecord.value);
        const realKey = await deriveKey(passphrase, salt);

        const verifierRecord = await dbGetRaw('crypto_meta', 'verifier');
        if (!verifierRecord || !verifierRecord.value) throw new Error('Missing verifier');
        try {
            const result = await decryptValue(realKey, new Uint8Array(verifierRecord.value));
            if (result.verify !== 'parolnet') throw new Error('Bad verify');
        } catch {
            throw new Error('Wrong passphrase');
        }

        const duressSalt = crypto.getRandomValues(new Uint8Array(16));
        const duressKey = await deriveKey(duressPassphrase, duressSalt);
        const duressVerifier = await encryptValue(duressKey, { verify: 'parolnet-duress' });
        await dbPutRaw('crypto_meta', { key: 'duress_salt', value: Array.from(duressSalt) });
        await dbPutRaw('crypto_meta', { key: 'duress_verifier', value: Array.from(duressVerifier) });
    }

    // Check whether a duress credential is present.
    async isDuressConfigured(dbGetRaw) {
        try {
            const rec = await dbGetRaw('crypto_meta', 'duress_verifier');
            return !!(rec && rec.value);
        } catch {
            return false;
        }
    }

    // Unlock: load salt, derive key, verify against stored token.
    // ALWAYS performs both the real and duress derive+decrypt attempts —
    // including dummy work when the duress slot is absent — so timing is
    // uniform regardless of which credential (if any) succeeded.
    // Returns { ok: boolean, mode?: 'normal' | 'duress' }.
    async unlock(passphrase, dbGetRaw) {
        const saltRecord = await dbGetRaw('crypto_meta', 'salt');
        if (!saltRecord || !saltRecord.value) {
            throw new Error('No encryption configured');
        }
        const salt = new Uint8Array(saltRecord.value);

        const verifierRecord = await dbGetRaw('crypto_meta', 'verifier');
        if (!verifierRecord || !verifierRecord.value) {
            throw new Error('Missing verifier');
        }

        // Try to load duress metadata; if absent, fall back to dummy inputs of
        // the same size so the work below (derive + decrypt) is indistinguishable
        // from the configured-duress case.
        let duressSaltRecord = null;
        let duressVerifierRecord = null;
        try { duressSaltRecord = await dbGetRaw('crypto_meta', 'duress_salt'); } catch {}
        try { duressVerifierRecord = await dbGetRaw('crypto_meta', 'duress_verifier'); } catch {}

        const duressConfigured = !!(duressSaltRecord && duressSaltRecord.value
            && duressVerifierRecord && duressVerifierRecord.value);

        const duressSalt = duressConfigured
            ? new Uint8Array(duressSaltRecord.value)
            : crypto.getRandomValues(new Uint8Array(16));
        // Dummy verifier bytes when no duress is configured — length matches a
        // real 12-byte IV + 32-byte ciphertext (sentinel size) well enough for
        // decrypt() to do the full work and fail uniformly.
        const duressVerifier = duressConfigured
            ? new Uint8Array(duressVerifierRecord.value)
            : crypto.getRandomValues(new Uint8Array(12 + 32));

        // Always run both derivations.
        const realKey = await deriveKey(passphrase, salt);
        const duressKey = await deriveKey(passphrase, duressSalt);

        // Always run both decrypt attempts.
        let realResult = null;
        let duressResult = null;
        try {
            realResult = await decryptValue(realKey, new Uint8Array(verifierRecord.value));
        } catch { realResult = null; }
        try {
            duressResult = await decryptValue(duressKey, duressVerifier);
        } catch { duressResult = null; }

        if (realResult && realResult.verify === 'parolnet') {
            this._key = realKey;
            this._enabled = true;
            return { ok: true, mode: 'normal' };
        }
        if (duressConfigured && duressResult && duressResult.verify === 'parolnet-duress') {
            // Intentionally do NOT set this._key. Caller triggers panic wipe.
            return { ok: true, mode: 'duress' };
        }
        return { ok: false };
    }

    // Check if encryption has been set up (salt exists)
    async checkEnabled(dbGetRaw) {
        try {
            const saltRecord = await dbGetRaw('crypto_meta', 'salt');
            this._enabled = !!(saltRecord && saltRecord.value);
        } catch {
            this._enabled = false;
        }
        return this._enabled;
    }

    lock() {
        this._key = null;
        // Note: can't truly zeroize JS memory, but nulling removes reference
    }

    async encrypt(value) {
        if (!this._key) throw new Error('Store locked');
        return await encryptValue(this._key, value);
    }

    async decrypt(encrypted) {
        if (!this._key) throw new Error('Store locked');
        return await decryptValue(this._key, encrypted);
    }
}
