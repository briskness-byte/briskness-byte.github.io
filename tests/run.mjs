// Offline checks for the reader pages. No network, no browser, no dependencies:
//
//     node tests/run.mjs
//
// What a browser would catch only by breaking — an inline script the policy blocks, a relay the
// policy forgets — is checked here from the files themselves. The rendering checks use a fake DOM
// that records what was built, which is enough to prove that stranger text never becomes markup:
// the renderer has no way to produce an element other than through createElement, and the fake
// only knows text nodes and anchors.
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import crypto from 'crypto';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const read = f => fs.readFileSync(path.join(ROOT, f), 'utf8');

let failed = 0;
const ok = (cond, what) => { console.log((cond ? '✓ ' : '✗ ') + what); if (!cond) failed++; };

const sandbox = { URL };
vm.runInNewContext(read('lib/read.js'), sandbox);
const { RELAYS, renderText } = sandbox.NCRead;

// ---- the pages and their policy --------------------------------------------------------------
// The two reader pages talk to the relays and to nothing else. The instructions page talks to no
// one; it runs the snippet as a demo, allowed by the snippet's hash and nothing looser, and frames
// the box from this same site.
const scriptHash = js => "'sha256-" + crypto.createHash('sha256').update(js).digest('base64') + "'";
const inlineScripts = html => [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const PAGES = {
    'thread/index.html': { connect: RELAYS, frame: null, inline: 0 },
    'embed/frame.html':  { connect: RELAYS, frame: null, inline: 0 },
    'embed/index.html':  { connect: null, frame: ["'self'"], inline: 1 },
};
for (const [page, want] of Object.entries(PAGES)) {
    const html = read(page);
    const csp = (html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/) || [])[1];
    ok(!!csp, `${page}: has a Content-Security-Policy`);
    if (!csp) continue;
    const dir = Object.fromEntries(csp.split(';').map(d => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v]));
    const inline = inlineScripts(html);
    ok(inline.length === want.inline, `${page}: ${want.inline ? 'exactly one inline script (the demo)' : 'no inline <script>'}`);
    ok(dir['default-src']?.join(' ') === "'none'", `${page}: default-src 'none'`);
    ok(dir['script-src']?.join(' ') === ["'self'", ...inline.map(scriptHash)].join(' '),
       `${page}: script-src 'self'${want.inline ? ' plus the hash of that one script' : ' only'}`);
    ok(dir['style-src']?.join(' ') === "'self'", `${page}: style-src 'self' only`);
    ok(dir['img-src']?.join(' ') === "'self'", `${page}: img-src 'self' only (no remote images)`);
    ok(dir['base-uri']?.join(' ') === "'none'" && dir['form-action']?.join(' ') === "'none'", `${page}: base-uri and form-action 'none'`);
    ok(want.connect ? [...(dir['connect-src'] || [])].sort().join(' ') === [...want.connect].sort().join(' ') : !dir['connect-src'],
       `${page}: ${want.connect ? 'connect-src is exactly the relay list in lib/read.js' : 'no connect-src: it connects to nothing'}`);
    ok(want.frame ? dir['frame-src']?.join(' ') === want.frame.join(' ') : !dir['frame-src'], `${page}: frame-src ${want.frame ? want.frame.join(' ') : 'not allowed'}`);
    // The meta tag only governs what comes after it.
    ok(html.indexOf('Content-Security-Policy') < Math.min(...['<script', '<link rel="stylesheet"', '<style']
       .map(t => html.indexOf(t)).filter(i => i >= 0)), `${page}: policy comes before any script or style`);
    ok(!/<style[\s>]/i.test(html) && !/\sstyle=/i.test(html), `${page}: no inline style`);
    ok(!/<[a-z][^>]*\son[a-z]+\s*=/i.test(html), `${page}: no inline event handlers`);
    for (const src of [...html.matchAll(/<script src="([^"]+)"/g)].map(m => m[1]))
        ok(!/^(https?:)?\/\//.test(src) && fs.existsSync(path.join(ROOT, path.dirname(page), src)), `${page}: script ${src} is local and exists`);
    for (const href of [...html.matchAll(/<link rel="stylesheet" href="([^"]+)"/g)].map(m => m[1]))
        ok(fs.existsSync(path.join(ROOT, path.dirname(page), href)), `${page}: stylesheet ${href} exists`);
}
const SCRIPTS = ['lib/read.js', 'lib/draw.js', 'thread/thread.js', 'embed/frame.js', 'embed/page.js'];
for (const js of SCRIPTS) {
    const src = read(js);
    ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/.test(src), `${js}: no HTML-from-string or eval`);
    ok(!/fetch\(|XMLHttpRequest|sendBeacon|localStorage|sessionStorage|indexedDB|document\.cookie/.test(src), `${js}: no fetch, beacons, storage or cookies`);
}

// ---- rendering stranger text -----------------------------------------------------------------
function fakeDoc() {
    const doc = {
        createTextNode: text => ({ kind: 'text', text }),
        createElement: tag => {
            if (tag !== 'a') throw new Error('renderer made a <' + tag + '>');
            return { kind: 'a', tag, href: '', textContent: '', target: '', rel: '', referrerPolicy: '' };
        },
    };
    return { ownerDocument: doc, children: [], appendChild(n) { this.children.push(n); } };
}
const render = text => { const el = fakeDoc(); renderText(el, text); return el.children; };
const asText = nodes => nodes.map(n => n.kind === 'text' ? n.text : n.textContent).join('');

const hostile = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<a href="javascript:alert(1)">click</a>',
    '"><svg onload=alert(1)>',
    '<iframe src="https://example.com"></iframe>',
    '&lt;b&gt;entities stay literal&lt;/b&gt;',
];
for (const h of hostile) {
    const nodes = render(h);
    ok(asText(nodes) === h && nodes.every(n => n.kind === 'text' || /^https?:\/\/[^\s<>"']+$/.test(n.href)),
       'shown as text: ' + h);
}

const nodes = render('see https://example.com/a?b=1 and javascript:alert(1) or <a href="https://example.org">x</a>');
const links = nodes.filter(n => n.kind === 'a');
ok(asText(nodes) === 'see https://example.com/a?b=1 and javascript:alert(1) or <a href="https://example.org">x</a>', 'mixed text: every character survives as text');
ok(links.length === 2 && links[0].href === 'https://example.com/a?b=1' && links[1].href === 'https://example.org',
   'only http(s) addresses become links, and an href cannot carry a quote out');
ok(links.every(a => a.rel === 'nofollow ugc noopener noreferrer' && a.referrerPolicy === 'no-referrer' && a.target === '_blank'),
   'links carry rel="nofollow ugc noopener noreferrer" and no referrer');

// ---- signatures --------------------------------------------------------------------------------
const { BIP340 } = await import('./bip340-vectors.mjs');
const crypt = { URL, TextEncoder, crypto: globalThis.crypto, setTimeout, clearTimeout };
const V = (() => { const s = { ...crypt }; vm.runInNewContext(read('lib/read.js'), s); return s.NCRead; })();
const h2b = h => new Uint8Array((h.match(/.{2}/g) || []).map(b => parseInt(b, 16)));
for (const v of BIP340) {
    let got; try { got = await V._secp.verify(v.pub, h2b(v.msg), v.sig); } catch (e) { got = 'threw'; }
    ok(got === v.ok, `BIP-340 vector #${v.i} ${v.ok ? 'verifies' : 'is rejected'}${v.note ? ' — ' + v.note : ''}`);
}
const FX = JSON.parse(read('tests/fixtures.json'));
const E = FX.events;
ok(await V.verifyEvent(E.plain), 'a genuine event verifies');
ok(!(await V.verifyEvent({ ...E.plain, content: 'changed' })), 'changed content is rejected');
ok(!(await V.verifyEvent({ ...E.plain, pubkey: FX.pubkeys.mallory })), 'another author\'s key is rejected');
ok(!(await V.verifyEvent({ ...E.plain, sig: E.hostile.sig })), 'another event\'s signature is rejected');
ok(!(await V.verifyEvent({ ...E.plain, tags: 'I' })) && !(await V.verifyEvent({ ...E.plain, content: 5 })), 'a malformed event is rejected');
{
    const s = { URL, TextEncoder, setTimeout, clearTimeout };   // no WebCrypto, as on a plain-http page
    vm.runInNewContext(read('lib/read.js'), s);
    ok(s.NCRead.canVerify() === false && V.canVerify() === true, 'without WebCrypto the reader knows it cannot verify');
}

// ---- reading a thread by the extension's rules, against fake relays ----------------------------
// Five honest relays hold every fixture. The first relay is hostile: it answers first, with forged
// copies of real events, forged votes, a forged deletion and a forged profile, and it ignores the
// filters and sends events that belong to other pages.
const honest = Object.values(E);
const fake = (pub, n) => ({ id: crypto.randomUUID().replace(/-/g, '').padEnd(64, '0'), pubkey: pub, created_at: 1760001000 + n,
                            kind: 7, tags: [['e', E.forgedTarget.id]], content: '-', sig: 'ab'.repeat(64) });
const hostileRelay = [
    { ...E.plain, content: 'forged text, same id and signature' },
    { ...E.deleteByAuthor, tags: [['e', E.plain.id]] },
    { ...E.aliceNew, id: 'cd'.repeat(32), created_at: E.aliceNew.created_at + 100, content: JSON.stringify({ name: 'Mallory pretending' }) },
    ...[1, 2, 3, 4].map(n => fake(String(n).repeat(64), n)),
    ...honest,
];
const requests = [];
class FakeWS {
    constructor(url) { this.url = url; requests.push({ url, reqs: [] }); this.log = requests.at(-1); setTimeout(() => this.onopen && this.onopen(), 0); }
    close() {}
    send(msg) {
        const [type, sub, filter] = JSON.parse(msg);
        if (type !== 'REQ') return;
        this.log.reqs.push(filter);
        const hostile = this.url === RELAYS[0];
        const match = ev => (!filter.kinds || filter.kinds.includes(ev.kind)) && (!filter.authors || filter.authors.includes(ev.pubkey)) &&
            Object.entries(filter).filter(([k]) => k.startsWith('#')).every(([k, vals]) => ev.tags.some(t => t[0] === k.slice(1) && vals.includes(t[1])));
        const out = hostile ? hostileRelay.filter(ev => !filter.kinds || filter.kinds.includes(ev.kind)) : honest.filter(match);
        setTimeout(() => {
            out.forEach(ev => this.onmessage({ data: JSON.stringify(['EVENT', sub, ev]) }));
            this.onmessage({ data: JSON.stringify(['EOSE', sub]) });
        }, 0);
    }
}
const S = { ...crypt, WebSocket: FakeWS };
vm.runInNewContext(read('lib/read.js'), S);
const updates = [];
await S.NCRead.readThread(FX.PAGE, [], (view, done) => updates.push({ view, done }));
const view = updates.at(-1).view;
const comments = view.items.filter(i => i.type === 'comment');
const byText = Object.fromEntries(comments.map(i => [i.ev.content, i]));
const has = name => comments.some(i => i.ev.id === E[name].id);
const item = name => comments.find(i => i.ev.id === E[name].id);

ok(updates.at(-1).done && updates.length >= 2, 'the thread is drawn before the votes are checked, and again when done');
ok(requests.every(r => RELAYS.includes(r.url)), 'nothing is contacted but the listed relays');
ok(requests.flatMap(r => r.reqs).some(f => f.kinds[0] === 1111 && f['#I']?.[0] === FX.PAGE) &&
   !requests.flatMap(r => r.reqs).some(f => f['#i']), 'comments are asked for by uppercase I, as the extension does');
ok(has('plain') && item('plain').ev.content === E.plain.content && !byText['forged text, same id and signature'],
   'a forged copy that arrives first does not replace or hide the genuine comment');
ok(has('hostile') && item('hostile').ev.content === E.hostile.content, 'a comment containing HTML is kept as its exact text');
ok(!has('otherPage'), 'a validly signed comment for another page is dropped (tag re-check)');
ok(!has('lowercaseOnly'), 'a comment with only a lowercase i tag is not shown, as in the extension');
ok(has('legacyNote') && item('legacyNote').legacy && !has('legacyNoTag'), 'a kind 1 note with the page in an r tag is shown as a note; one without is not');
ok(has('replyNoPageTag') && item('replyNoPageTag').depth === 1 &&
   comments.indexOf(item('replyNoPageTag')) === comments.indexOf(item('plain')) + 1, 'a reply without a page tag is found by its parent\'s id and drawn under it');
ok(!has('deletedByAuthor'), 'a comment deleted by its author is gone');
ok(has('deleteAttempted') && !item('deleteAttempted').deleted, 'a deletion signed by somebody else is ignored');
ok(has('deletedParent') && item('deletedParent').deleted && has('replyToDeleted') && item('replyToDeleted').depth === 1,
   'a deleted comment with an answer stays as a placeholder, and the answer stays');
ok(!item('plain').deleted, 'a forged deletion is ignored');
const folds = view.items.filter(i => i.type === 'fold');
ok(folds.length === 1 && folds[0].rest.length === 2 && has('same3') && !has('same1') && !has('same2'),
   'three near-identical comments from one key fold into one with "2 more"');
ok(has('pair1') && has('pair2'), 'two near-identical comments are both shown');
ok(item('downvoted').hidden && item('downvoted').sc.down === 5, 'five down-votes collapse a comment');
ok(!item('fourDown').hidden, 'four down-votes do not');
ok(!item('mindChanged').hidden && item('mindChanged').sc.down === 4, 'a voter\'s newer up-vote replaces their down-vote');
ok(item('forgedTarget').sc.down === 1 && !item('forgedTarget').hidden, 'forged down-votes are not counted');
ok(item('plain').name === 'Alice', 'the newest verified profile gives the name; a forged newer one is ignored');
ok(item('hostile').name === 'Bob <b>bold</b>', 'display_name is the fallback, and stays text');
ok(comments[0].ev.id === E.forgedTarget.id, 'newest first, as the extension\'s default');
ok(view.count === comments.filter(i => !i.deleted).length + 2 && view.total === view.count + 2,
   'the count is what a reader could see: folded comments counted, deleted ones not');

// ---- the snippet a site owner pastes -----------------------------------------------------------
const { fakeDocument, lines } = await import('./fakedom.mjs');
const howto = read('embed/index.html');
const unescape = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const shown = unescape((howto.match(/<pre id="snippet">([\s\S]*?)<\/pre>/) || [])[1] || '');
const demo = inlineScripts(howto)[0] || '';
ok(shown === '<div data-nostrcomments></div>\n<script>' + demo + '</script>', 'the snippet shown is exactly the one the demo runs');
ok(howto.includes(`<code class="hash">${scriptHash(demo)}</code>`), 'the hash given for site policies is the snippet\'s own');
ok(!/<script[^>]*\ssrc=/.test(shown) && !/import\(|fetch\(|XMLHttpRequest/.test(demo), 'the snippet loads no remote script');

// Runs the snippet in a fake page and returns what it did. Anything that could reach the network
// is a trap that records being touched.
function runSnippet({ href = 'https://blog.example/post?utm_source=x', attrs = {}, canonical = null } = {}) {
    const doc = fakeDocument();
    const box = doc.make('div');
    Object.entries(attrs).forEach(([k, v]) => box.setAttribute(k, v));
    const script = doc.make('script');
    doc.body.append(box, script);
    if (canonical) { doc.canonical = doc.make('link'); doc.canonical.setAttribute('href', canonical); }
    doc.currentScript = script;
    const touched = [], listeners = [];
    const trap = name => function () { touched.push(name); };
    const win = { document: doc, location: { href }, URLSearchParams, Math, Number,
                  fetch: trap('fetch'), WebSocket: trap('WebSocket'), XMLHttpRequest: trap('XMLHttpRequest'), Image: trap('Image'),
                  addEventListener: (type, fn) => listeners.push({ type, fn }) };
    win.window = win;
    vm.runInNewContext(demo, win);
    return { doc, box, touched, listeners, win };
}
{
    const { box, touched, listeners } = runSnippet();
    ok(box.children.length === 1 && box.children[0].tag === 'button' && box.children[0].textContent === 'Show comments from Nostr',
       'before the click: one button, and no frame');
    ok(!touched.length && !listeners.length, 'before the click: nothing loaded, nothing listened for');
}
{
    const { box, touched, listeners } = runSnippet({ canonical: '/canonical-post', attrs: { 'data-theme': 'dark' } });
    box.children[0].onclick();
    const frame = box.children[0];
    ok(frame && frame.tag === 'iframe' && box.children.length === 1, 'after the click: the button is replaced by the frame');
    const [base, frag] = (frame.src || '').split('#');
    ok(base === 'https://briskness-byte.github.io/embed/frame.html', 'the frame is this site\'s, with no query string for the server to see');
    const p = new URLSearchParams(frag);
    ok(p.get('url') === 'https://blog.example/post?utm_source=x' && p.get('alt') === '/canonical-post' && p.get('theme') === 'dark',
       'the page address, canonical link and theme travel in the fragment');
    ok(frame.attrs.sandbox === 'allow-scripts allow-popups allow-popups-to-escape-sandbox', 'the frame is sandboxed, without allow-same-origin');
    ok(frame.attrs.referrerpolicy === 'no-referrer', 'the frame is loaded without a Referer');
    ok(!touched.length, 'the snippet itself contacts nothing; only the frame does');
    frame.contentWindow = {};
    const onMessage = listeners.find(l => l.type === 'message').fn;
    onMessage({ source: {}, data: { nostrcomments: 'height', height: 999 } });
    ok(frame.style.height === undefined, 'a message from anywhere but the frame is ignored');
    onMessage({ source: frame.contentWindow, data: { nostrcomments: 'height', height: 640 } });
    ok(frame.style.height === '640px', 'the frame\'s height message sets its height');
    onMessage({ source: frame.contentWindow, data: { nostrcomments: 'height', height: 1e9 } });
    const big = frame.style.height;
    onMessage({ source: frame.contentWindow, data: { nostrcomments: 'height', height: 'x' } });
    ok(big === '20000px' && frame.style.height === '80px', 'heights are clamped, and junk becomes the minimum');
}
{
    const { box } = runSnippet({ attrs: { 'data-url': 'https://blog.example/chosen' } });
    box.children[0].onclick();
    ok(new URLSearchParams(box.children[0].src.split('#')[1]).get('url') === 'https://blog.example/chosen', 'data-url chooses the address');
}

// ---- the box inside the frame ------------------------------------------------------------------
async function runFrame(hash, { https = true } = {}) {
    const doc = fakeDocument();
    const status = doc.make('span', 'status'), list = doc.make('ol', 'thread'), full = doc.make('a', 'full');
    full.textContent = 'Read the full thread';
    const posted = [];
    const win = { ...crypt, crypto: https ? globalThis.crypto : undefined, WebSocket: FakeWS, document: doc, URLSearchParams,
                  location: { hash }, parent: { postMessage: (m, o) => posted.push([m, o]) } };
    win.window = win;
    vm.createContext(win);
    for (const f of ['lib/read.js', 'lib/draw.js', 'embed/frame.js']) vm.runInContext(read(f), win);
    for (let i = 0; i < 400 && !/comment|none yet|deleted|not given|https/.test(status.textContent.replace('checking', '')); i++) await new Promise(r => setTimeout(r, 10));
    for (let i = 0; i < 400 && /checking|loading/.test(status.textContent); i++) await new Promise(r => setTimeout(r, 10));
    return { doc, status, list, full, posted };
}
{
    const f = await runFrame('#url=' + encodeURIComponent(FX.BUSY + '?utm_source=news'));
    ok(f.list.children.length === 50, 'the box draws at most 50 items');
    ok(f.status.textContent === '— 60 comments', 'and says how many there are');
    ok(f.full.textContent === 'Read 10 more in the full thread' &&
       f.full.href === '../thread/#' + new URLSearchParams({ url: FX.BUSY }), 'the rest are behind a link to /thread/, address in the fragment, tracking removed');
    ok(f.posted.length > 0 && f.posted.every(([m, o]) => o === '*' && Object.keys(m).join() === 'nostrcomments,height' && Number.isInteger(m.height)),
       'it tells the page its height, and nothing else');
}
{
    const f = await runFrame('#url=' + encodeURIComponent(FX.PAGE) + '&theme=dark');
    ok(f.doc.documentElement.className === 'dark', 'data-theme reaches the box');
    const text = lines(f.list).join('\n');
    ok(text.includes('<script>alert(1)</script><img src=x onerror=alert(1)>') &&
       f.list.all().every(e => ['li', 'div', 'span', 'button', 'a', '#text'].includes(e.tag)),
       'a comment containing HTML is drawn as text: no element but the box\'s own');
    ok(f.list.all().filter(e => e.tag === 'a').every(a => a.rel === 'nofollow ugc noopener noreferrer' && /^https?:/.test(a.href)),
       'links in comments carry rel="nofollow ugc noopener noreferrer"');
    ok(f.list.all().every(e => e.tag !== 'img'), 'no pictures or avatars are loaded');
    ok(text.includes('[tomb] Comment deleted by its author') && text.includes('Hidden (5 downvotes) — show') &&
       text.includes('and 2 more like this from the same key — show'), 'deletions, collapsed and folded comments are drawn as in /thread/');
    ok(/Alicenpub1\w+…\w{4}/.test(text), 'a name is always drawn with its key beside it');
    const hidden = f.list.children.find(li => li.textContent.startsWith('Hidden'));
    hidden.children[0].onclick();
    ok(lines(f.list).some(l => l.includes('Five people voted this down.')) && !lines(f.list).some(l => l.startsWith('[tomb] Hidden')),
       'a collapsed comment opens in place');
}
{
    const f = await runFrame('#url=' + encodeURIComponent('https://example.com/nobody-commented'));
    ok(f.status.textContent === '— none yet. Install NostrComments to write the first.', 'an empty thread invites the first comment');
    ok((await runFrame('#url=javascript%3Aalert(1)')).status.textContent === '— this box was not given a web page address.', 'a non-web address is refused');
    ok((await runFrame('')).status.textContent === '— this box was not given a web page address.', 'no address, no read');
    const plain = await runFrame('#url=' + encodeURIComponent(FX.PAGE), { https: false });
    ok(plain.status.textContent === '— comments can only be checked on https pages, so none are shown here.' && !plain.list.children.length,
       'on a page that cannot verify, nothing is shown');
}
{
    const S2 = { ...crypt };
    vm.runInNewContext(read('lib/read.js'), S2);
    const alt = S2.NCRead.findAltPageUrls;
    ok(alt('https://blog.example/post', '/post?utm_source=x', 'https://blog.example/post').length === 0 &&
       alt('https://blog.example/post', '/canonical', 'https://blog.example/post?a=1')[0] === 'https://blog.example/canonical' &&
       alt('https://blog.example/post', 'javascript:alert(1)', 'https://blog.example/post').length === 0,
       'a canonical link is resolved against the page, normalised, and only http(s) is read');
}

// ---- what the pages promise ---------------------------------------------------------------------
const publicText = ['embed/index.html', 'embed/frame.html', 'thread/index.html'].map(read).join('\n');
ok(!/permanent|uncensor|censorship[- ]?(proof|resistant)|forever|can ?not be (removed|deleted)|impossible to (remove|delete)/i.test(publicText),
   'no page claims comments are permanent or uncensorable');
ok(howto.includes('href="https://github.com/briskness-byte/NostrComments/blob/main/ABUSE.md"'), 'the instructions point to ABUSE.md');
ok(/You cannot moderate it/.test(howto) && /cannot remove or hide a comment/.test(howto), 'the instructions say plainly that the site owner cannot moderate');
ok(/site owner, cannot remove a comment, and no single party can remove every copy/.test(howto), 'the claim is worded as agreed');
ok(RELAYS.every(r => howto.includes('<code>' + r.slice(6) + '</code>')) && /IP address/.test(howto) && /Nothing loads until/.test(howto),
   'the privacy notice names every relay, the IP address, and that nothing loads before the click');

console.log(failed ? `\n✗ ${failed} check(s) failed` : '\n✓ all checks passed');
process.exit(failed ? 1 : 0);
