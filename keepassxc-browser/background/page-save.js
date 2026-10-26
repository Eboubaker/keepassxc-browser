'use strict';

// Background side of content/page-save.js: saves a credential a web page handed over,
// updating the entry with the same username when KeePassXC already has one for the URL,
// and reads the entry back to confirm KeePassXC really stored what was sent.
const pageSave = {};

// Finds the entry KeePassXC holds for the URL with this username
pageSave.lookup = async function(tab, url, username) {
    const entries = await keepass.retrieveCredentials(tab, [ url, url, true ]);
    if (!keepass.isConnected || keepass.isDatabaseClosed) {
        return { error: true };
    }

    const entry = username
        ? entries.find(e => e.login?.toLowerCase() === username.toLowerCase())
        : undefined;
    return { entries, entry };
};

// The codes the secret produces around now, or undefined when it can't be checked here
pageSave.expectedCodes = async function(totp) {
    let secret = totp;
    let digits = 6;
    let period = 30;
    let algorithm = 'SHA-1';

    if (/^otpauth:/i.test(totp)) {
        const params = new URL(totp).searchParams;
        if (params.has('encoder')) {
            return undefined; // Steam and other encoders are not plain digits
        }
        secret = params.get('secret') ?? '';
        digits = Number(params.get('digits')) || digits;
        period = Number(params.get('period')) || period;
        algorithm = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[(params.get('algorithm') ?? 'SHA1').toUpperCase()];
        if (!algorithm) {
            return undefined;
        }
    }

    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const c of secret.toUpperCase().replace(/[\s=-]/g, '')) {
        const value = alphabet.indexOf(c);
        if (value < 0) {
            return undefined;
        }
        bits += value.toString(2).padStart(5, '0');
    }
    const keyBytes = new Uint8Array((bits.match(/.{8}/g) ?? []).map(b => parseInt(b, 2)));
    if (!keyBytes.length) {
        return undefined;
    }

    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: algorithm }, false, [ 'sign' ]);
    const step = Math.floor(Date.now() / 1000 / period);
    const codes = [];
    for (const counter of [ step - 1, step, step + 1 ]) {
        const message = new DataView(new ArrayBuffer(8));
        message.setUint32(0, Math.floor(counter / 2 ** 32));
        message.setUint32(4, counter >>> 0);
        const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message.buffer));
        const offset = hmac[hmac.length - 1] & 0xf;
        const binary = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
        codes.push(String(binary % 10 ** digits).padStart(digits, '0'));
    }
    return codes;
};

// Whether the entry holds the password and, if one was sent, the same TOTP secret
pageSave.holds = async function(entry, password, totp) {
    if (!entry || entry.password !== password) {
        return false;
    }
    if (!totp) {
        return true;
    }
    if (!entry.totp) {
        return false;
    }
    const codes = await pageSave.expectedCodes(totp);
    return !codes || codes.includes(entry.totp);
};

// Args: [ url, username, password, totp ]. Tells the content script what saving would do.
pageSave.onLookup = async function(tab, args = []) {
    const [ url, username, password, rawTotp ] = args;
    const totp = rawTotp ? saveTotp.parseSecret(rawTotp, 1) : undefined;
    if (rawTotp && !totp) {
        return { result: 'invalid-totp' };
    }

    const found = await pageSave.lookup(tab, url, username);
    if (found.error) {
        return { result: CreationError.GENERAL };
    }
    if (found.entry && await pageSave.holds(found.entry, password, totp)) {
        return { result: 'unchanged' };
    }
    return { existing: found.entry ? { name: found.entry.name, login: found.entry.login } : null };
};

// Args: [ url, username, password, totp ]. Returns created, updated, unchanged, canceled,
// invalid-totp, totp-not-saved or error.
pageSave.onCommit = async function(tab, args = []) {
    const [ url, username, password, rawTotp ] = args;
    const totp = rawTotp ? saveTotp.parseSecret(rawTotp, 1) : undefined;
    if (rawTotp && !totp) {
        return 'invalid-totp';
    }

    // The user confirmed a save from this site, so it may also ask which logins are saved
    await pageSave.trustOrigin(tab);

    const before = await pageSave.lookup(tab, url, username);
    if (before.error) {
        return CreationError.GENERAL;
    }
    const existing = before.entry;
    if (existing && await pageSave.holds(existing, password, totp)) {
        return 'unchanged';
    }

    const result = await keepass.updateCredentials(tab, [ existing?.uuid, username, password, url, null, null, totp ]);
    if (result === CreationError.REFERENCES || (!existing && result !== CreationError.CREATED)) {
        return CreationError.GENERAL;
    }

    // Read the entry back: KeePassXC answers "success" even when it drops a field it doesn't know
    const after = await pageSave.lookup(tab, url, username);
    if (after.error) {
        return CreationError.GENERAL;
    }

    const knownUuids = new Set(before.entries.map(e => e.uuid));
    const saved = existing
        ? after.entries.find(e => e.uuid === existing.uuid)
        : after.entries.find(e => e.login === username && !knownUuids.has(e.uuid));

    if (await pageSave.holds(saved, password, totp)) {
        return existing ? 'updated' : CreationError.CREATED;
    }
    // KeePassXC replies "error" when the user declines its Update Entry dialog
    if (existing && result !== CreationError.UPDATED) {
        return CreationError.CANCELED;
    }
    return saved?.password === password ? 'totp-not-saved' : CreationError.GENERAL;
};

// Sites the user confirmed a save from. Only they may query, because a query runs without a
// dialog and would otherwise let any site probe which accounts the database holds.
pageSave.originOf = function(tab) {
    try {
        const origin = new URL(tab?.url).origin;
        return origin.startsWith('http') ? origin : undefined;
    } catch (_e) {
        return undefined;
    }
};

pageSave.trustOrigin = async function(tab) {
    const origin = pageSave.originOf(tab);
    if (!origin) {
        return;
    }
    const { pageSaveTrustedOrigins = [] } = await browser.storage.local.get('pageSaveTrustedOrigins');
    if (!pageSaveTrustedOrigins.includes(origin)) {
        await browser.storage.local.set({ pageSaveTrustedOrigins: [ ...pageSaveTrustedOrigins, origin ] });
    }
};

pageSave.isTrusted = async function(tab) {
    const origin = pageSave.originOf(tab);
    const { pageSaveTrustedOrigins = [] } = await browser.storage.local.get('pageSaveTrustedOrigins');
    return Boolean(origin) && pageSaveTrustedOrigins.includes(origin);
};

// Args: [ entries ] with { key, url, username, password, totp }. Reads only: never writes,
// never unlocks the database, and returns only a status per key, never entry contents.
// Statuses: saved, saved-no-totp, differs, missing.
pageSave.onQuery = async function(tab, args = []) {
    const [ requested = [] ] = args;
    if (!await pageSave.isTrusted(tab)) {
        logDebug('Credential query ignored from a site no save was confirmed from');
        return { result: CreationError.GENERAL };
    }

    const statuses = {};
    const byUrl = new Map();
    for (const item of requested) {
        byUrl.set(item.url, [ ...(byUrl.get(item.url) ?? []), item ]);
    }

    for (const [ url, items ] of byUrl) {
        const entries = await keepass.retrieveCredentials(tab, [ url, url, false ]);
        if (keepass.isDatabaseClosed) {
            return { result: 'locked' };
        }
        if (!keepass.isConnected) {
            return { result: CreationError.GENERAL };
        }

        for (const item of items) {
            const totp = item.totp ? saveTotp.parseSecret(item.totp, 1) : undefined;
            if (item.totp && !totp) {
                continue; // An invalid secret can't be compared, so leave this row's status out
            }
            const entry = item.username
                ? entries.find(e => e.login?.toLowerCase() === item.username.toLowerCase())
                : undefined;

            if (!entry) {
                statuses[item.key] = 'missing';
            } else if (entry.password !== item.password) {
                statuses[item.key] = 'differs';
            } else if (await pageSave.holds(entry, item.password, totp)) {
                statuses[item.key] = 'saved';
            } else {
                statuses[item.key] = 'saved-no-totp';
            }
        }
    }

    return { result: 'ok', statuses };
};
