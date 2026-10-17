// The /thread/ page: a form, a status line and a list. Reading, checking and the extension's rules
// for what is shown live in ../lib/read.js, shared with the embed; this file only draws.
(function () {
'use strict';
const { normalizeUrl, toBech32, RELAYS, readThread, renderText, canVerify } = window.NCRead;

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

const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
};

// A placeholder item that is replaced by the real thing when its button is pressed. A button
// rather than a clickable item, so it can be reached and pressed from the keyboard.
function placeholder(cls, label, open) {
    const li = el('li', cls);
    const b = el('button', 'opener', label);
    b.type = 'button';
    b.onclick = () => li.replaceWith(open());
    li.appendChild(b);
    return li;
}

function drawComment(item, reveal) {
    const { ev, sc, depth } = item;
    const li = el('li', depth > 0 ? 'reply d' + Math.min(depth, 6) : '');
    // Only reached for a deleted comment with replies under it. No name: the author asked for it
    // to be gone, and what is left marks that something was here.
    if (item.deleted) { li.classList.add('tomb'); li.textContent = 'Comment deleted by its author'; return li; }
    if (item.hidden && !reveal) {
        return placeholder(li.className + ' tomb', `Hidden (${sc.down} downvotes) — show`, () => drawComment(item, true));
    }

    const who = el('div', 'who');
    // The name is whatever its owner chose, so it could say anything — "Site owner", or another
    // person's name. The key it belongs to is always shown beside it.
    const npub = toBech32('npub', ev.pubkey);
    if (item.name) who.appendChild(el('span', 'name', String(item.name).slice(0, 40)));
    who.appendChild(el('span', 'npub', npub.slice(0, 12) + '…' + npub.slice(-4)));
    who.appendChild(el('span', 'when', when(ev.created_at)));
    if (item.legacy) {
        const tag = el('span', 'tag', 'note');
        tag.title = 'An ordinary Nostr note that links to this page, rather than a comment written on it.';
        who.appendChild(tag);
    }

    const body = el('div', 'text');
    renderText(body, ev.content);
    li.append(who, body);
    return li;
}

function draw(view) {
    const list = $('thread');
    list.textContent = '';
    if (view.capped) list.appendChild(el('li', 'tomb', `Showing the newest ${view.limit} comments — this thread has more than one request can carry.`));
    for (const item of view.items) {
        if (item.type === 'fold') {
            list.appendChild(placeholder('fold', `and ${item.rest.length} more like this from the same key — show`, () => {
                const frag = document.createDocumentFragment();
                item.rest.forEach(r => frag.appendChild(drawComment(r)));
                return frag;
            }));
        } else {
            list.appendChild(drawComment(item));
        }
    }
}

let current = 0;
async function show(raw) {
    const url = normalizeUrl(raw);
    if (!url) return status('That does not look like a web address.');
    if (!canVerify()) return status('This page needs https to check signatures, so it shows nothing without it.');
    history.replaceState(null, '', location.pathname + '?url=' + encodeURIComponent(url));
    $('thread').textContent = '';
    const run = ++current;
    status('Asking ' + RELAYS.length + ' relays…');
    await readThread(url, [], (view, done) => {
        if (run !== current) return;
        draw(view);
        if (!view.items.length) return status(view.total
            ? 'The comments on that page were deleted by their authors.'
            : 'No comments on that page yet — or none that these relays hold.');
        const n = view.count + (view.count === 1 ? ' comment' : ' comments');
        status(done ? n + ' on ' + url : n + ' so far — checking votes and names…');
    }, (i, total) => { if (run === current) status(`Checking signatures… ${i} of ${total}`); });
}

$('f').onsubmit = e => { e.preventDefault(); show($('u').value); };

const fromQuery = new URLSearchParams(location.search).get('url');
if (fromQuery) { $('u').value = fromQuery; show(fromQuery); }
})();
