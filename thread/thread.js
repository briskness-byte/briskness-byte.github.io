// The /thread/ page: a form, a status line and a list. Reading, checking and the extension's rules
// for what is shown live in ../lib/read.js, drawing in ../lib/draw.js, both shared with the embed.
(function () {
'use strict';
const { normalizeUrl, RELAYS, readThread, canVerify } = window.NCRead;
const { drawThread } = window.NCDraw;

const $ = id => document.getElementById(id);
const status = msg => { $('status').textContent = msg; };

let current = 0;
async function show(raw, altRaw) {
    const url = normalizeUrl(raw);
    if (!url) return status('That does not look like a web address.');
    if (!canVerify()) return status('This page needs https to check signatures, so it shows nothing without it.');
    history.replaceState(null, '', location.pathname + '?url=' + encodeURIComponent(url));
    $('thread').textContent = '';
    const run = ++current;
    status('Asking ' + RELAYS.length + ' relays…');
    // Only from the embed's link: the canonical address of the page it sat in, read alongside.
    const alt = altRaw ? [normalizeUrl(altRaw)].filter(a => a && a !== url && /^https?:/.test(a)) : [];
    await readThread(url, alt, (view, done) => {
        if (run !== current) return;
        drawThread($('thread'), view);
        if (!view.items.length) return status(view.total
            ? 'The comments on that page were deleted by their authors.'
            : 'No comments on that page yet — or none that these relays hold.');
        const n = view.count + (view.count === 1 ? ' comment' : ' comments');
        status(done ? n + ' on ' + url : n + ' so far — checking votes and names…');
    }, (i, total) => { if (run === current) status(`Checking signatures… ${i} of ${total}`); });
}

$('f').onsubmit = e => { e.preventDefault(); show($('u').value); };

// The embed links here with the address in the fragment, which is never sent to the server.
const fromHash = new URLSearchParams(location.hash.slice(1));
const fromQuery = new URLSearchParams(location.search).get('url') || fromHash.get('url');
if (fromQuery) { $('u').value = fromQuery; show(fromQuery, fromHash.get('alt')); }
})();
