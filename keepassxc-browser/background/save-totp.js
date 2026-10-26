'use strict';

// Saves a TOTP secret found on the current page to a KeePassXC entry matching the site.
// Requires a KeePassXC version that accepts the "totp" field in set-login.
const saveTotp = {};

// Accepts an otpauth://totp/ URI or a bare Base32 secret, like KeePassXC does.
// The minimum length keeps ordinary selected words from passing as a secret.
saveTotp.parseSecret = function(text, minLength = 16) {
    const value = text?.trim();
    if (!value) {
        return undefined;
    }

    if (/^otpauth:\/\/totp\//i.test(value)) {
        return value;
    }

    // Sites often show the secret in groups, e.g. "JBSW Y3DP EHPK 3PXP"
    const secret = value.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
    return new RegExp(`^[A-Z2-7]{${minLength},}$`).test(secret) ? secret : undefined;
};

// Looks for an otpauth:// QR code in the visible part of the tab
saveTotp.scanVisibleTab = async function(tab) {
    const dataUrl = await browser.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
    const bitmap = await createImageBitmap(await (await fetch(dataUrl)).blob());
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const context = canvas.getContext('2d', { willReadFrequently: true });
    context.drawImage(bitmap, 0, 0);

    const image = context.getImageData(0, 0, bitmap.width, bitmap.height);
    const code = jsQR(image.data, image.width, image.height);
    return saveTotp.parseSecret(code?.data);
};

saveTotp.notify = async function(tab, type, message) {
    await browser.tabs.sendMessage(tab.id, {
        action: 'frame_message',
        args: [ 'notification_from_frame', type, message ]
    }, { frameId: 0 }).catch((err) => logError(err));
};

saveTotp.fromContextMenu = async function(item, tab) {
    try {
        const totp = saveTotp.parseSecret(item.linkUrl)
            || saveTotp.parseSecret(item.selectionText)
            || await saveTotp.scanVisibleTab(tab);
        if (!totp) {
            await saveTotp.notify(tab, 'warning', tr('saveTotpNotFound'));
            return;
        }

        const entries = await keepass.retrieveCredentials(tab, [ tab.url, tab.url, true ]);
        if (!keepass.isConnected) {
            await saveTotp.notify(tab, 'error', tr('errorNotConnected'));
            return;
        }
        if (keepass.isDatabaseClosed) {
            await saveTotp.notify(tab, 'error', tr('rememberErrorDatabaseClosed'));
            return;
        }

        const choice = await browser.tabs.sendMessage(tab.id, {
            action: 'save_totp_choose_entry',
            args: entries.map(e => ({ name: e.name, login: e.login }))
        }, { frameId: 0 });
        if (choice === undefined || choice < 0) {
            return;
        }

        // Without an entry, KeePassXC creates a new one for the site
        const entry = entries[choice];
        const result = await keepass.updateCredentials(tab,
            [ entry?.uuid, entry?.login ?? '', entry?.password ?? '', tab.url, null, null, totp ]);

        if (result === CreationError.UPDATED || result === CreationError.CREATED) {
            await saveTotp.notify(tab, 'success', tr('saveTotpSaved'));
        } else {
            await saveTotp.notify(tab, 'error', tr('saveTotpNotSaved'));
        }
    } catch (err) {
        logError(`saveTotp failed: ${err}`);
        await saveTotp.notify(tab, 'error', tr('saveTotpNotSaved'));
    }
};
