// The comment box inside the iframe. Reads the page address from the fragment, reads the thread by
// the extension's rules, draws at most MAX items, and tells the page around it how tall it is.
(function () {
'use strict';
const { normalizeUrl, readThread, canVerify, findAltPageUrls } = window.NCRead;
const { drawThread } = window.NCDraw;

// A box under an article, not the whole conversation: the rest is one click away at /thread/.
const MAX = 50;

const $ = id => document.getElementById(id);
const status = msg => { $('status').textContent = msg; };
const params = new URLSearchParams(location.hash.slice(1));

const theme = params.get('theme');
if (theme === 'light' || theme === 'dark') document.documentElement.className = theme;

// The page around us cannot see in, so it learns the height from us: one number, nothing else.
// Sent to any parent ('*') because the box cannot know which site it is on, and the number tells
// that site nothing it could not see by looking.
let lastHeight = 0;
function reportHeight() {
    const h = Math.ceil(document.documentElement.scrollHeight);
    if (h === lastHeight || window.parent === window) return;
    lastHeight = h;
    window.parent.postMessage({ nostrcomments: 'height', height: h }, '*');
}
if (typeof ResizeObserver === 'function') new ResizeObserver(reportHeight).observe(document.body);
reportHeight();

const raw = params.get('url') || '';
const pageUrl = /^https?:\/\//i.test(raw) ? normalizeUrl(raw) : '';

function start() {
    if (!pageUrl) return status('— this box was not given a web page address.');
    if (!canVerify()) return status('— comments can only be checked on https pages, so none are shown here.');
    const alt = findAltPageUrls(pageUrl, params.get('alt'), raw);
    const full = new URLSearchParams({ url: pageUrl });
    if (alt.length) full.set('alt', alt[0]);
    $('full').href = '../thread/#' + full;

    status('— loading…');
    readThread(pageUrl, alt, (view, done) => {
        const left = drawThread($('thread'), view, MAX);
        if (left > 0) $('full').textContent = `Read ${left} more in the full thread`;
        if (!view.items.length) {
            return status(view.total ? '— the comments here were deleted by their authors.'
                                     : '— none yet. Install NostrComments to write the first.');
        }
        const n = view.count + (view.count === 1 ? ' comment' : ' comments');
        status('— ' + n + (done ? '' : ', checking votes and names…'));
        reportHeight();
    }, (i, total) => status(`— checking signatures, ${i} of ${total}…`)).then(reportHeight, reportHeight);
}
start();
})();
