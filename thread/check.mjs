// Does the reader still agree with the extension, and does it still find a real thread?
//
//     node thread/check.mjs [url]
//
// Two pieces of index.html are copied from NostrComments-Chrome/content.js — normalizeUrl and
// toBech32 — and a thread is filed under the normalised URL. If those drift, this page quietly
// looks under a key nothing was published to: no error, no comments, nothing to debug. So the
// check compares them against the shipped source when the extension repo is next door, and then
// runs the reader's own query against a page known to have comments.
import fs from 'fs';
import path from 'path';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const html = fs.readFileSync(path.join(HERE, 'index.html'), 'utf8');
const slice = (from, to) => { const a = html.indexOf(from); return html.slice(a, html.indexOf(to, a + 1)); };
const normalizeUrl = eval(slice('const _TRACKING', 'function toBech32') + '; normalizeUrl');
const toBech32 = eval(slice('function toBech32(hrp, hex)', '// ------------') + '; toBech32');

const EXT = path.resolve(HERE, '../../NostrComments/tests/harness.mjs');
if (fs.existsSync(EXT)) {
    const { extensionCode } = await import(EXT);
    const ext = extensionCode();
    const cases = ['https://www.nature.com/articles/d41586-026-02763-3',
                   'https://example.com/a?utm_source=x&b=2&a=1#frag',
                   'https://example.com/a?fbclid=zz',
                   'https://example.com/spa#/route'];
    const bad = cases.filter(c => normalizeUrl(c) !== ext.normalizeUrl(c));
    for (const c of bad) console.log('MISMATCH', c, '\n  here:', normalizeUrl(c), '\n  ext :', ext.normalizeUrl(c));
    console.log(bad.length ? `✗ normalizeUrl has drifted on ${bad.length} case(s)` : '✓ normalizeUrl matches the extension');
    const pk = 'cb8db3a901199d6b94029f784c934c71b4a36561870d108e7b6b6c4cb3b0ead1';
    console.log(toBech32('npub', pk) === ext.toBech32('npub', pk) ? '✓ toBech32 matches' : '✗ toBech32 has drifted');
} else {
    console.log('· extension repo not next door — skipping the drift check');
}

const RELAYS = ['wss://nos.lol','wss://relay.damus.io','wss://relay.primal.net',
                'wss://nostr.oxtr.dev','wss://nostr.mom','wss://relay.nostr.net'];
const ask = (relay, filters, ms = 8000) => new Promise(res => {
    const out = []; let ws, done = () => { done = () => {}; try { ws.close(); } catch {} res(out); };
    const t = setTimeout(done, ms);
    try { ws = new WebSocket(relay); } catch { clearTimeout(t); return done(); }
    let open = filters.length;
    ws.onopen = () => filters.forEach((f, i) => ws.send(JSON.stringify(['REQ', 'q' + i, f])));
    ws.onerror = () => { clearTimeout(t); done(); };
    ws.onmessage = m => {
        let f; try { f = JSON.parse(m.data); } catch { return; }
        if (f[0] === 'EVENT') out.push(f[2]);
        if (f[0] === 'EOSE' && --open <= 0) { clearTimeout(t); done(); }
    };
});

const url = normalizeUrl(process.argv[2] || 'https://www.nature.com/articles/d41586-026-02763-3');
const filters = [{ kinds: [1111], '#I': [url], limit: 200 }, { kinds: [1111], '#i': [url], limit: 200 }];
const seen = new Map();
await Promise.all(RELAYS.map(r => ask(r, filters).then(evs => evs.forEach(e => seen.set(e.id, e)))));
const evs = [...seen.values()].sort((a, b) => a.created_at - b.created_at);
console.log(`\n${evs.length} comment(s) for ${url}`);
for (const e of evs) console.log('  ·', toBech32('npub', e.pubkey).slice(0, 12) + '…', '|', e.content.replace(/\s+/g, ' ').slice(0, 70));
process.exit(0);
