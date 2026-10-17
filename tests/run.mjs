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

console.log(failed ? `\n✗ ${failed} check(s) failed` : '\n✓ all checks passed');
process.exit(failed ? 1 : 0);
