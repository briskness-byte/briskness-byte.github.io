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
const PAGES = ['thread/index.html'];
for (const page of PAGES) {
    const html = read(page);
    const csp = (html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/) || [])[1];
    ok(!!csp, `${page}: has a Content-Security-Policy`);
    if (!csp) continue;
    const dir = Object.fromEntries(csp.split(';').map(d => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v]));
    ok(dir['default-src']?.join(' ') === "'none'", `${page}: default-src 'none'`);
    ok(dir['script-src']?.join(' ') === "'self'", `${page}: script-src 'self' only`);
    ok(dir['style-src']?.join(' ') === "'self'", `${page}: style-src 'self' only`);
    ok(dir['img-src']?.join(' ') === "'self'", `${page}: img-src 'self' only (no remote images)`);
    ok(dir['base-uri']?.join(' ') === "'none'" && dir['form-action']?.join(' ') === "'none'", `${page}: base-uri and form-action 'none'`);
    ok([...(dir['connect-src'] || [])].sort().join(' ') === [...RELAYS].sort().join(' '),
       `${page}: connect-src is exactly the relay list in lib/read.js`);
    // The meta tag only governs what comes after it.
    ok(html.indexOf('Content-Security-Policy') < Math.min(...['<script', '<link rel="stylesheet"', '<style']
       .map(t => html.indexOf(t)).filter(i => i >= 0)), `${page}: policy comes before any script or style`);
    ok(!/<script(?![^>]*\ssrc=)[^>]*>/i.test(html), `${page}: no inline <script>`);
    ok(!/<style[\s>]/i.test(html) && !/\sstyle=/i.test(html), `${page}: no inline style`);
    ok(!/\son[a-z]+\s*=/i.test(html), `${page}: no inline event handlers`);
    for (const src of [...html.matchAll(/<script src="([^"]+)"/g)].map(m => m[1]))
        ok(!/^(https?:)?\/\//.test(src) && fs.existsSync(path.join(ROOT, path.dirname(page), src)), `${page}: script ${src} is local and exists`);
}
for (const js of ['lib/read.js', 'thread/thread.js']) {
    const src = read(js);
    ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/.test(src), `${js}: no HTML-from-string or eval`);
    ok(!/fetch\(|XMLHttpRequest|sendBeacon|localStorage|document\.cookie/.test(src), `${js}: no fetch, beacons, storage or cookies`);
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

console.log(failed ? `\n✗ ${failed} check(s) failed` : '\n✓ all checks passed');
process.exit(failed ? 1 : 0);
