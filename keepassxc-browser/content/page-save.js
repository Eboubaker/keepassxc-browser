'use strict';

// Lets a web page ask to save a credential to KeePassXC (local build, not meant for upstream).
// The page posts { type: 'keepassxc-save-credentials', id, url, username, password, totp } to itself,
// and gets back { type: 'keepassxc-save-credentials-result', id, result } with result 'created',
// 'updated', 'unchanged', 'canceled', 'invalid-totp', 'totp-not-saved' or 'error'. An entry with the
// same username for the URL is updated instead of duplicated. Nothing is saved until the user
// confirms in an extension dialog.
const kpxcPageSave = {};
kpxcPageSave.busy = false;

kpxcPageSave.onMessage = async function(event) {
    if (event.source !== window || event.data?.type !== 'keepassxc-save-credentials') {
        return;
    }

    const { id, url, username, password, totp } = event.data;
    const reply = (result) => window.postMessage({ type: 'keepassxc-save-credentials-result', id, result }, window.location.origin);

    let target;
    try {
        target = new URL(url || window.location.href, window.location.href);
    } catch (_e) {
        target = undefined;
    }

    if (kpxcPageSave.busy
        || typeof username !== 'string'
        || typeof password !== 'string' || !password
        || (totp !== undefined && typeof totp !== 'string')
        || ![ 'http:', 'https:' ].includes(target?.protocol)) {
        reply(CreationError.GENERAL);
        return;
    }

    // The page can't fake this dialog: it runs in the extension's isolated world
    kpxcPageSave.busy = true;
    try {
        const lookup = await sendMessage('page_save_lookup', [ target.href, username, password, totp ]);
        if (lookup?.result) {
            reply(lookup.result);
            return;
        }

        const question = lookup?.existing
            ? tr('pageSaveConfirmUpdate', [ window.location.origin, lookup.existing.name, lookup.existing.login ])
            : tr('pageSaveConfirm', [ window.location.origin, target.href, username ]);
        // eslint-disable-next-line no-alert
        if (!window.confirm(question)) {
            reply(CreationError.CANCELED);
            return;
        }

        reply(await sendMessage('page_save_commit', [ target.href, username, password, totp ]) ?? CreationError.GENERAL);
    } catch (err) {
        logError(`Saving credentials from the page failed: ${err}`);
        reply(CreationError.GENERAL);
    } finally {
        kpxcPageSave.busy = false;
    }
};

// Read-only: the page posts { type: 'keepassxc-query-credentials', id, entries: [ { key, url,
// username, password, totp } ] } and gets back { type: 'keepassxc-query-credentials-result', id,
// result: 'ok' | 'locked' | 'error', statuses: { key: 'saved' | 'saved-no-totp' | 'differs' |
// 'missing' } }. No dialog, no writes. Only sites the user confirmed a save from get an answer,
// it covers only entries saved from that site, and a site may ask once every two seconds.
kpxcPageSave.onQuery = async function(event) {
    if (event.source !== window || event.data?.type !== 'keepassxc-query-credentials') {
        return;
    }

    const { id, entries } = event.data;
    const reply = (result, statuses = {}) => window.postMessage(
        { type: 'keepassxc-query-credentials-result', id, result, statuses }, window.location.origin);

    const valid = Array.isArray(entries) && entries.length <= 100 && entries.every((e) => {
        try {
            return (typeof e?.key === 'string' || typeof e?.key === 'number')
                && typeof e.username === 'string'
                && (e.password === undefined || typeof e.password === 'string')
                && (e.totp === undefined || typeof e.totp === 'string')
                && [ 'http:', 'https:' ].includes(new URL(e.url).protocol);
        } catch (_e) {
            return false;
        }
    });
    if (kpxcPageSave.busy || !valid) {
        reply(CreationError.GENERAL);
        return;
    }

    kpxcPageSave.busy = true;
    try {
        const items = entries.map(e => ({ key: String(e.key), url: new URL(e.url).href, username: e.username,
            password: e.password, totp: e.totp }));
        const response = await sendMessage('page_save_query', [ items ]);
        if (response?.silent) {
            return; // Sites the user never confirmed a save from get no answer at all
        }
        reply(response?.result ?? CreationError.GENERAL, response?.statuses);
    } catch (err) {
        logError(`Querying credentials for the page failed: ${err}`);
        reply(CreationError.GENERAL);
    } finally {
        kpxcPageSave.busy = false;
    }
};

// The page posts { type: 'keepassxc-remove-credentials', id, url, username } and gets back
// { type: 'keepassxc-remove-credentials-result', id, result: 'removed' | 'missing' | 'canceled' |
// 'locked' | 'error' }. Only sites the user confirmed a save from may ask, the user confirms here
// and again in KeePassXC, and KeePassXC moves the entry to the Recycle Bin.
kpxcPageSave.onRemove = async function(event) {
    if (event.source !== window || event.data?.type !== 'keepassxc-remove-credentials') {
        return;
    }

    const { id, url, username } = event.data;
    const reply = (result) => window.postMessage({ type: 'keepassxc-remove-credentials-result', id, result },
        window.location.origin);

    let target;
    try {
        target = new URL(url);
    } catch (_e) {
        target = undefined;
    }
    if (kpxcPageSave.busy || typeof username !== 'string' || !username
        || ![ 'http:', 'https:' ].includes(target?.protocol)) {
        reply(CreationError.GENERAL);
        return;
    }

    kpxcPageSave.busy = true;
    try {
        const lookup = await sendMessage('page_save_remove_lookup', [ target.href, username ]);
        if (lookup?.silent) {
            return; // Sites the user never confirmed a save from get no answer at all
        }
        if (!lookup?.existing) {
            reply(lookup?.result ?? CreationError.GENERAL);
            return;
        }

        // eslint-disable-next-line no-alert
        if (!window.confirm(tr('pageSaveConfirmRemove', [ window.location.origin, lookup.existing.name, lookup.existing.login ]))) {
            reply(CreationError.CANCELED);
            return;
        }

        reply(await sendMessage('page_save_remove_commit', [ target.href, username ]) ?? CreationError.GENERAL);
    } catch (err) {
        logError(`Removing credentials for the page failed: ${err}`);
        reply(CreationError.GENERAL);
    } finally {
        kpxcPageSave.busy = false;
    }
};

// Copies a message for logging with every credential removed: passwords, TOTP secrets and
// anything else that looks like a secret become '<removed>', usernames are masked
kpxcPageSave.redact = function(value, key = '') {
    if (/pass|secret|otp|token|auth|cookie|session/i.test(key) || /^otpauth:/i.test(value)) {
        return value ? '<removed>' : value;
    }
    if (/user|login|mail/i.test(key) && typeof value === 'string') {
        return value.replace(/^(.).*?(@|$)/, (_m, first, at) => `${first}***${at}`);
    }
    if (Array.isArray(value)) {
        return value.map(v => kpxcPageSave.redact(v));
    }
    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([ k, v ]) => [ k, kpxcPageSave.redact(v, k) ]));
    }
    return value;
};

// Logs every keepassxc-* message on the page, requests and replies alike, in the
// service worker console
kpxcPageSave.onAnyMessage = function(event) {
    if (event.source !== window || typeof event.data?.type !== 'string' || !event.data.type.startsWith('keepassxc-')) {
        return;
    }
    sendMessage('page_save_log', [ kpxcPageSave.redact(event.data) ]).catch(() => {});
};

// Only the top window handles requests, so frames from other sites can't trigger dialogs
if (window.self === window.top) {
    window.addEventListener('message', kpxcPageSave.onAnyMessage);
    window.addEventListener('message', kpxcPageSave.onMessage);
    window.addEventListener('message', kpxcPageSave.onQuery);
    window.addEventListener('message', kpxcPageSave.onRemove);
}
