'use strict';

// Background side of content/page-save.js: saves a credential a web page handed over,
// updating the entry with the same username when KeePassXC already has one for the URL,
// and reads the entry back to confirm KeePassXC really stored what was sent.
const pageSave = {};

// Service worker console logging. Never pass passwords or TOTP secrets here.
pageSave.log = function(...parts) {
    console.log('[KeePassXC page]', ...parts);
};

pageSave.mask = function(username) {
    return typeof username === 'string' ? username.replace(/^(.).*?(@|$)/, (_m, first, at) => `${first}***${at}`) : username;
};

// Args: [ message ], already redacted by the content script
pageSave.onLog = async function(tab, args = []) {
    const [ message ] = args;
    const direction = message?.type?.endsWith('-result') ? 'extension -> page' : 'page -> extension';
    pageSave.log(direction, pageSave.originOf(tab) ?? '', JSON.stringify(message));
};

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

// Sites the user confirmed a save from, and the entries each one saved:
// { [origin]: { entries: [ { uuid, url } ] } }. Query and remove only see a site's own entries,
// so a site can't probe or delete anything else in the database. Managed in options/page-access.
pageSave.originOf = function(tab) {
    try {
        const origin = new URL(tab?.url).origin;
        return origin.startsWith('http') ? origin : undefined;
    } catch (_e) {
        return undefined;
    }
};

pageSave.loadSites = async function() {
    const { pageSaveSites = {}, pageSaveTrustedOrigins } = await browser.storage.local.get(
        [ 'pageSaveSites', 'pageSaveTrustedOrigins' ]);

    // Earlier builds only kept trusted origins; they keep their trust but have no entries yet
    if (pageSaveTrustedOrigins) {
        for (const origin of pageSaveTrustedOrigins) {
            pageSaveSites[origin] ??= { entries: [] };
        }
        await browser.storage.local.set({ pageSaveSites });
        await browser.storage.local.remove('pageSaveTrustedOrigins');
    }
    return pageSaveSites;
};

// The site's record, or undefined when the user never confirmed a save from it
pageSave.siteOf = async function(tab) {
    const origin = pageSave.originOf(tab);
    return origin ? (await pageSave.loadSites())[origin] : undefined;
};

pageSave.recordEntry = async function(tab, uuid, url) {
    const origin = pageSave.originOf(tab);
    if (!origin || !uuid) {
        return;
    }
    const sites = await pageSave.loadSites();
    const site = sites[origin] ?? { entries: [] };
    site.entries = [ ...site.entries.filter(e => e.uuid !== uuid), { uuid, url } ];
    sites[origin] = site;
    await browser.storage.local.set({ pageSaveSites: sites });
};

pageSave.forgetEntry = async function(tab, uuid) {
    const origin = pageSave.originOf(tab);
    const sites = await pageSave.loadSites();
    if (sites[origin]) {
        sites[origin].entries = sites[origin].entries.filter(e => e.uuid !== uuid);
        await browser.storage.local.set({ pageSaveSites: sites });
    }
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
        pageSave.log('lookup: KeePassXC not connected or database locked', url);
        return { result: CreationError.GENERAL };
    }
    pageSave.log('lookup:', url, pageSave.mask(username), `${found.entries.length} entries for the URL,`,
        found.entry ? `matches ${found.entry.uuid}` : 'no entry with this username');

    // Skip the dialog only for this site's own entries; any other match still needs the user to
    // confirm, which also links the entry to the site
    const site = await pageSave.siteOf(tab);
    const own = found.entry && site?.entries.some(e => e.uuid === found.entry.uuid);
    if (own && await pageSave.holds(found.entry, password, totp)) {
        return { result: 'unchanged' };
    }
    return { existing: found.entry ? { name: found.entry.name, login: found.entry.login } : null };
};

// Args: [ url, username, password, totp ]. Returns created, updated, unchanged, canceled,
// invalid-totp, totp-not-saved or error. A saved entry is recorded as this site's own.
pageSave.onCommit = async function(tab, args = []) {
    const { result, uuid } = await pageSave.commit(tab, args);
    if (uuid && [ CreationError.CREATED, 'updated', 'unchanged' ].includes(result)) {
        await pageSave.recordEntry(tab, uuid, args[0]);
    }
    return result;
};

pageSave.commit = async function(tab, args = []) {
    const [ url, username, password, rawTotp ] = args;
    const totp = rawTotp ? saveTotp.parseSecret(rawTotp, 1) : undefined;
    if (rawTotp && !totp) {
        return { result: 'invalid-totp' };
    }

    const before = await pageSave.lookup(tab, url, username);
    if (before.error) {
        return { result: CreationError.GENERAL };
    }
    const existing = before.entry;
    if (existing && await pageSave.holds(existing, password, totp)) {
        return { result: 'unchanged', uuid: existing.uuid };
    }

    const result = await keepass.updateCredentials(tab, [ existing?.uuid, username, password, url, null, null, totp ]);
    pageSave.log('commit:', existing ? `update ${existing.uuid}` : 'new entry', pageSave.mask(username),
        totp ? 'with TOTP' : 'without TOTP', '-> KeePassXC replied', result);
    if (result === CreationError.REFERENCES || (!existing && result !== CreationError.CREATED)) {
        return { result: CreationError.GENERAL };
    }

    // Read the entry back: KeePassXC answers "success" even when it drops a field it doesn't know
    const after = await pageSave.lookup(tab, url, username);
    if (after.error) {
        return { result: CreationError.GENERAL };
    }

    const knownUuids = new Set(before.entries.map(e => e.uuid));
    const saved = existing
        ? after.entries.find(e => e.uuid === existing.uuid)
        : after.entries.find(e => e.login === username && !knownUuids.has(e.uuid));
    pageSave.log('read back:', saved ? `entry ${saved.uuid},` : 'entry not found,',
        saved ? `password ${saved.password === password ? 'matches' : 'differs'}, TOTP ${saved.totp ? 'present' : 'absent'}` : '');

    if (await pageSave.holds(saved, password, totp)) {
        return { result: existing ? 'updated' : CreationError.CREATED, uuid: saved.uuid };
    }
    // KeePassXC replies "error" when the user declines its Update Entry dialog
    if (existing && result !== CreationError.UPDATED) {
        return { result: CreationError.CANCELED };
    }
    return saved?.password === password ? { result: 'totp-not-saved', uuid: saved.uuid } : { result: CreationError.GENERAL };
};

// One query per site every two seconds; the page queries once on load
pageSave.QUERY_INTERVAL_MS = 2000;
pageSave.lastQuery = {};

// Args: [ entries ] with { key, url, username, password, totp }. Reads only: never writes,
// never unlocks the database, and returns only a status per key, never entry contents.
// Statuses: saved, saved-no-totp, differs, missing. Only the site's own entries count: anything
// else is "missing", so the answer reveals nothing the site didn't save itself.
// Returns { silent: true } for a site that is not trusted, so it gets no reply at all.
pageSave.onQuery = async function(tab, args = []) {
    const [ requested = [] ] = args;
    const site = await pageSave.siteOf(tab);
    const origin = pageSave.originOf(tab);
    if (!site) {
        pageSave.log('query ignored: no save was confirmed from', origin);
        return { silent: true };
    }
    if (Date.now() - (pageSave.lastQuery[origin] ?? 0) < pageSave.QUERY_INTERVAL_MS) {
        pageSave.log('query refused: too soon after the last one from', origin);
        return { result: CreationError.GENERAL };
    }
    pageSave.lastQuery[origin] = Date.now();

    const own = new Set(site.entries.map(e => e.uuid));
    const ownUrls = new Set(site.entries.map(e => e.url));
    const statuses = {};
    const byUrl = new Map();
    for (const item of requested) {
        byUrl.set(item.url, [ ...(byUrl.get(item.url) ?? []), item ]);
    }

    for (const [ url, items ] of byUrl) {
        // Only ask KeePassXC about URLs this site saved to, so it can't trigger access prompts elsewhere
        const entries = ownUrls.has(url) ? await keepass.retrieveCredentials(tab, [ url, url, false ]) : [];
        if (ownUrls.has(url) && keepass.isDatabaseClosed) {
            return { result: 'locked' };
        }
        if (ownUrls.has(url) && !keepass.isConnected) {
            return { result: CreationError.GENERAL };
        }

        for (const item of items) {
            const totp = item.totp ? saveTotp.parseSecret(item.totp, 1) : undefined;
            if (item.totp && !totp) {
                continue; // An invalid secret can't be compared, so leave this row's status out
            }
            const entry = entries.find(e => own.has(e.uuid) && e.login?.toLowerCase() === item.username.toLowerCase());

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

    pageSave.log('query:', `${requested.length} rows ->`, JSON.stringify(statuses));
    return { result: 'ok', statuses };
};

// Finds the single entry to remove among the site's own. More than one match is an error:
// never guess what to delete.
pageSave.findForRemoval = async function(tab, url, username) {
    const site = await pageSave.siteOf(tab);
    if (!site) {
        pageSave.log('remove ignored: no save was confirmed from', pageSave.originOf(tab));
        return { silent: true };
    }

    // Only ask KeePassXC about URLs this site saved to, so it can't trigger prompts for other sites
    if (!site.entries.some(e => e.url === url)) {
        pageSave.log('remove lookup:', url, 'is not a URL this site saved to');
        return { result: 'missing' };
    }

    const own = new Set(site.entries.map(e => e.uuid));
    const entries = await keepass.retrieveCredentials(tab, [ url, url, true ]);
    if (keepass.isDatabaseClosed) {
        return { result: 'locked' };
    }
    if (!keepass.isConnected) {
        return { result: CreationError.GENERAL };
    }

    const matches = entries.filter(e => own.has(e.uuid) && e.login?.toLowerCase() === username.toLowerCase());
    pageSave.log('remove lookup:', url, pageSave.mask(username), `${matches.length} matching entries saved by this site`);
    if (matches.length === 0) {
        return { result: 'missing' };
    }
    if (matches.length > 1) {
        return { result: CreationError.GENERAL };
    }
    return { entry: matches[0] };
};

// Args: [ url, username ]. Tells the content script which entry would be removed.
pageSave.onRemoveLookup = async function(tab, args = []) {
    const [ url, username ] = args;
    const found = await pageSave.findForRemoval(tab, url, username);
    if (found.entry) {
        return { existing: { name: found.entry.name, login: found.entry.login } };
    }
    return found.silent ? { silent: true } : { result: found.result };
};

// Args: [ url, username ]. Returns removed, missing, canceled, locked or error.
pageSave.onRemoveCommit = async function(tab, args = []) {
    const [ url, username ] = args;
    const found = await pageSave.findForRemoval(tab, url, username);
    if (!found.entry) {
        return found.result ?? CreationError.GENERAL;
    }

    // KeePassXC asks once more, then moves the entry to the Recycle Bin
    const [ dbid ] = keepass.getCryptoKey();
    const nonce = keepassClient.getNonce();
    const response = await keepassClient.sendMessage('delete-entry', tab,
        { action: 'delete-entry', id: dbid, uuid: found.entry.uuid }, nonce);
    pageSave.log('remove:', found.entry.uuid, '-> KeePassXC replied', JSON.stringify(response?.success));

    // "false" also means the user said No, so check whether the entry is really gone
    const after = await keepass.retrieveCredentials(tab, [ url, url, false ]);
    if (!keepass.isConnected || keepass.isDatabaseClosed) {
        return CreationError.GENERAL;
    }
    const stillThere = after.some(e => e.uuid === found.entry.uuid);
    pageSave.log('remove read back:', stillThere ? 'entry still present' : 'entry gone');
    if (!stillThere) {
        await pageSave.forgetEntry(tab, found.entry.uuid);
        return 'removed';
    }
    return response?.success === 'false' ? CreationError.CANCELED : CreationError.GENERAL;
};
