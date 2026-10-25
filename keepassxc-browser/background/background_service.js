'use strict';

try {
    importScripts(
        '../common/browser-polyfill.min.js',
        '../common/global.js',
        '../common/sites.js',
        'nacl.min.js',
        'nacl-util.min.js',
        'client.js',
        'keepass.js',
        'httpauth.js',
        'offscreen.js',
        'browserAction.js',
        'tabs.js',
        'credentials.js',
        'page.js',
        'event.js',
        'jsQR.js',
        'save-totp.js',
        'init.js'
    );
} catch (e) {
    console.log('Cannot import background scripts: ', e);
}
