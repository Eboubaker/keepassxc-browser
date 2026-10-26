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
// 'missing' } }. No dialog, no writes, and only sites the user confirmed a save from get answers.
kpxcPageSave.onQuery = async function(event) {
    if (event.source !== window || event.data?.type !== 'keepassxc-query-credentials') {
        return;
    }

    const { id, entries } = event.data;
    const reply = (result, statuses = {}) => window.postMessage(
        { type: 'keepassxc-query-credentials-result', id, result, statuses }, window.location.origin);

    const valid = Array.isArray(entries) && entries.length <= 500 && entries.every((e) => {
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
        reply(response?.result ?? CreationError.GENERAL, response?.statuses);
    } catch (err) {
        logError(`Querying credentials for the page failed: ${err}`);
        reply(CreationError.GENERAL);
    } finally {
        kpxcPageSave.busy = false;
    }
};

// Only the top window handles requests, so frames from other sites can't trigger dialogs
if (window.self === window.top) {
    window.addEventListener('message', kpxcPageSave.onMessage);
    window.addEventListener('message', kpxcPageSave.onQuery);
}
