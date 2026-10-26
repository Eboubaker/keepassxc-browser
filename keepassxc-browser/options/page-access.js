'use strict';

// Lists the sites that may query and remove their own entries (background/page-save.js),
// and lets the user revoke them. Revoking only forgets the site; KeePassXC entries stay.
let shownOrigins = [];

const render = async function() {
    const { pageSaveSites = {}, pageSaveTrustedOrigins = [] } = await browser.storage.local.get(
        [ 'pageSaveSites', 'pageSaveTrustedOrigins' ]);
    for (const origin of pageSaveTrustedOrigins) {
        pageSaveSites[origin] ??= { entries: [] };
    }

    const origins = Object.keys(pageSaveSites).sort();
    shownOrigins = origins;
    const tbody = document.querySelector('#sites tbody');
    tbody.replaceChildren();
    document.getElementById('empty').hidden = origins.length > 0;
    document.getElementById('sites').hidden = origins.length === 0;
    document.getElementById('revokeAll').hidden = origins.length === 0;

    for (const origin of origins) {
        const row = document.createElement('tr');
        const site = document.createElement('td');
        site.textContent = origin;
        const entries = document.createElement('td');
        const urls = [ ...new Set(pageSaveSites[origin].entries.map(e => e.url)) ];
        entries.textContent = `${pageSaveSites[origin].entries.length}${urls.length ? ` (${urls.join(', ')})` : ''}`;

        const action = document.createElement('td');
        const button = document.createElement('button');
        button.className = 'btn btn-sm btn-danger';
        button.textContent = tr('pageAccessRevoke');
        button.addEventListener('click', () => revoke([ origin ]));
        action.append(button);

        row.append(site, entries, action);
        tbody.append(row);
    }
};

const revoke = async function(origins) {
    const { pageSaveSites = {}, pageSaveTrustedOrigins = [] } = await browser.storage.local.get(
        [ 'pageSaveSites', 'pageSaveTrustedOrigins' ]);
    for (const origin of origins) {
        delete pageSaveSites[origin];
    }
    await browser.storage.local.set({
        pageSaveSites,
        pageSaveTrustedOrigins: pageSaveTrustedOrigins.filter(o => !origins.includes(o))
    });
    await render();
};

document.getElementById('revokeAll').addEventListener('click', () => revoke(shownOrigins));

render();
