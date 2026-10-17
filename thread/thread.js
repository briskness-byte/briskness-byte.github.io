// The /thread/ page: a form, a status line and a list. Reading, checking and rendering live in
// ../lib/read.js, shared with the embed.
(function () {
'use strict';
const { normalizeUrl, toBech32, RELAYS, ask, renderText } = window.NCRead;

const $ = id => document.getElementById(id);
const status = msg => { $('status').textContent = msg; };

const when = ts => {
    const s = Math.floor(Date.now() / 1000) - ts;
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    if (s < 86400 * 30) return Math.floor(s / 86400) + 'd ago';
    return new Date(ts * 1000).toLocaleDateString();
};

async function show(raw) {
    const url = normalizeUrl(raw);
    if (!url) return status('That does not look like a web address.');
    history.replaceState(null, '', location.pathname + '?url=' + encodeURIComponent(url));
    $('thread').textContent = '';
    status('Asking ' + RELAYS.length + ' relays…');

    // NIP-22: the extension files a comment under an uppercase I (the root scope) and repeats it
    // lowercase for a top-level comment. Both are asked for; duplicates are dropped by id.
    const filters = [
        { kinds: [1111], '#I': [url], limit: 200 },
        { kinds: [1111], '#i': [url], limit: 200 },
    ];
    const seen = new Map();
    await Promise.all(RELAYS.map(r => ask(r, filters).then(evs => evs.forEach(e => seen.set(e.id, e)))));

    const events = [...seen.values()].sort((a, b) => a.created_at - b.created_at);
    if (!events.length) {
        return status('No comments on that page yet — or none that these relays hold.');
    }

    // Names, if the authors published any. Missing is normal, and an npub is shown instead.
    const names = new Map();
    const authors = [...new Set(events.map(e => e.pubkey))];
    await Promise.all(RELAYS.slice(0, 3).map(r => ask(r, [{ kinds: [0], authors, limit: authors.length }])
        .then(evs => evs.forEach(e => {
            try {
                const c = JSON.parse(e.content || '{}');
                const n = c.display_name || c.name;
                if (n && !names.has(e.pubkey)) names.set(e.pubkey, String(n).slice(0, 40));
            } catch (_) {}
        }))));

    const ids = new Set(events.map(e => e.id));
    for (const ev of events) {
        const li = document.createElement('li');
        // A comment answering another comment in this thread is shown indented. Anything else is
        // top level, including replies to something these relays did not return.
        const parent = (ev.tags || []).find(t => t[0] === 'e' && ids.has(t[1]));
        if (parent) li.className = 'reply';

        const who = document.createElement('div');
        who.className = 'who';
        const name = document.createElement('span');
        name.className = 'name';
        name.textContent = names.get(ev.pubkey) || (toBech32('npub', ev.pubkey).slice(0, 16) + '…');
        const time = document.createElement('span');
        time.className = 'when';
        time.textContent = when(ev.created_at);
        who.append(name, time);

        const body = document.createElement('div');
        body.className = 'text';
        renderText(body, ev.content || '');

        li.append(who, body);
        $('thread').appendChild(li);
    }
    status(events.length + (events.length === 1 ? ' comment' : ' comments') + ' on ' + url);
}

$('f').onsubmit = e => { e.preventDefault(); show($('u').value); };

const fromQuery = new URLSearchParams(location.search).get('url');
if (fromQuery) { $('u').value = fromQuery; show(fromQuery); }
})();
