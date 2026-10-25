'use strict';

// Lets a web page ask to save a credential to KeePassXC (local build, not meant for upstream).
// The page posts { type: 'keepassxc-save-credentials', id, url, username, password, totp } to itself,
// and gets back { type: 'keepassxc-save-credentials-result', id, result } with result 'created',
// 'canceled' or 'error'. Nothing is saved until the user confirms in an extension dialog.
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
        // eslint-disable-next-line no-alert
        if (!window.confirm(tr('pageSaveConfirm', [ window.location.origin, target.href, username ]))) {
            reply(CreationError.CANCELED);
            return;
        }

        const result = await sendMessage('add_credentials', [ username, password, target.href, null, null, totp ]);
        reply(result === CreationError.CREATED ? CreationError.CREATED : CreationError.GENERAL);
    } catch (err) {
        logError(`Saving credentials from the page failed: ${err}`);
        reply(CreationError.GENERAL);
    } finally {
        kpxcPageSave.busy = false;
    }
};

// Only the top window handles requests, so frames from other sites can't trigger dialogs
if (window.self === window.top) {
    window.addEventListener('message', kpxcPageSave.onMessage);
}
