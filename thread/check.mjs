// Does the reader still agree with the extension, and does it still find a real thread?
//
//     node thread/check.mjs [url]
//
// lib/read.js reads threads by the extension's rules, and those rules are copied, not shared: the
// extension cannot load a file from this site. Copies drift, and drift here is silent — a reader
// that looks under a different key, or shows what the extension hides, still looks like it works.
// So when the extension repo is next door this fails (exit 1) on any of:
//
//   - a block marked "// content.js: <name>" in read.js that no longer appears in content.js,
//     ignoring only indentation and line breaks — or an expected block that has gone missing;
//   - the relay list differing from the extension's defaults;
//   - read.js and the extension's own code giving different answers: normalizeUrl, toBech32, and
//     signature checks on the official BIP-340 vectors and on events signed and tampered with by
//     the extension itself.
//
// Then, either way, it runs the reader's whole read against a page known to have comments.
import fs from 'fs';
import path from 'path';
import vm from 'vm';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const readSrc = fs.readFileSync(path.join(HERE, '../lib/read.js'), 'utf8');
const sandbox = { URL, TextEncoder, crypto: globalThis.crypto, WebSocket: globalThis.WebSocket, setTimeout, clearTimeout };
vm.runInNewContext(readSrc, sandbox);
const R = sandbox.NCRead;

let failed = 0;
const ok = (cond, what) => { console.log((cond ? '✓ ' : '✗ ') + what); if (!cond) failed++; };

const EXPECTED = ['normalizeUrl', 'toBech32', 'secp', 'verifyEvent', 'limits', 'kinds', 'pageFilters',
    'profileAt', 'deletions', 'recount', 'shape', 'pageTag', 'deletionTargets', 'deletionApply',
    'voteValue', 'voteApply', 'profile', 'render', 'fold', 'hitLimit'];

const EXT_DIR = path.resolve(HERE, '../../NostrComments');
const CONTENT = path.join(EXT_DIR, 'NostrComments-Chrome/content.js');
if (fs.existsSync(CONTENT)) {
    const content = fs.readFileSync(CONTENT, 'utf8');
    const flat = s => s.split('\n').map(l => l.trim()).filter(Boolean).join('\n');
    const haystack = flat(content);

    const blocks = [...readSrc.matchAll(/^[ \t]*\/\/ content\.js: (\w+)\n([\s\S]*?)^[ \t]*\/\/ content\.js: end$/gm)]
        .map(m => ({ name: m[1], body: m[2] }));
    const names = blocks.map(b => b.name);
    ok(EXPECTED.every(n => names.includes(n)) && names.length === EXPECTED.length,
       `read.js has the ${EXPECTED.length} expected copied blocks` +
       (EXPECTED.filter(n => !names.includes(n)).length ? ' — missing: ' + EXPECTED.filter(n => !names.includes(n)).join(', ') : ''));
    for (const b of blocks) ok(haystack.includes(flat(b.body)), `block "${b.name}" is still in content.js unchanged`);

    const ext = content.match(/const DEFAULT_RELAYS = (\[[^\]]*\]);/);
    ok(!!ext && JSON.stringify(eval(ext[1])) === JSON.stringify([...R.RELAYS]), 'relay list matches the extension\'s DEFAULT_RELAYS');

    const { extensionCode } = await import(path.join(EXT_DIR, 'tests/harness.mjs'));
    const X = extensionCode();
    const cases = ['https://www.nature.com/articles/d41586-026-02763-3',
                   'https://example.com/a?utm_source=x&b=2&a=1#frag',
                   'https://example.com/a?fbclid=zz&UTM_Medium=y&ga_x=1',
                   'https://example.com/spa#/route', 'https://example.com/spa#!/route',
                   'https://EXAMPLE.com:443/a%20b?q=%C3%A9', 'http://example.com/?a=1&a=0'];
    const bad = cases.filter(c => R.normalizeUrl(c) !== X.normalizeUrl(c));
    for (const c of bad) console.log('  MISMATCH', c, '\n    here:', R.normalizeUrl(c), '\n    ext :', X.normalizeUrl(c));
    ok(!bad.length, `normalizeUrl matches the extension on ${cases.length} addresses`);
    const pk = 'cb8db3a901199d6b94029f784c934c71b4a36561870d108e7b6b6c4cb3b0ead1';
    ok(R.toBech32('npub', pk) === X.toBech32('npub', pk), 'toBech32 matches the extension');

    const { BIP340 } = await import('../tests/bip340-vectors.mjs');
    const h2b = h => new Uint8Array((h.match(/.{2}/g) || []).map(b => parseInt(b, 16)));
    let agree = 0;
    for (const v of BIP340) if ((await R._secp.verify(v.pub, h2b(v.msg), v.sig)) === (await X._secp.verify(v.pub, h2b(v.msg), v.sig))) agree++;
    ok(agree === BIP340.length, `signature checks agree with the extension on all ${BIP340.length} BIP-340 vectors`);

    const key = X.newKey();
    const evs = [];
    for (let i = 0; i < 6; i++) evs.push(await X.sign(key, { kind: 1111, created_at: 1760000000 + i, tags: [['I', 'https://example.com/']], content: 'drift ' + i }));
    const tampered = evs.flatMap(e => [{ ...e, content: e.content + '!' }, { ...e, sig: e.sig.slice(0, -1) + (e.sig.endsWith('0') ? '1' : '0') },
                                       { ...e, created_at: e.created_at + 1 }]);
    let same = 0;
    for (const e of [...evs, ...tampered]) if ((await R.verifyEvent(e)) === (await X.verify(e))) same++;
    ok(same === evs.length + tampered.length, `verifyEvent agrees with the extension on ${evs.length} signed and ${tampered.length} tampered events`);
} else {
    console.log('· extension repo not next door (' + EXT_DIR + ') — skipping the drift check');
}

// The reader's own read, end to end, against the real relays.
const url = R.normalizeUrl(process.argv[2] || 'https://www.nature.com/articles/d41586-026-02763-3');
let last = null;
await R.readThread(url, [], view => { last = view; });
const shown = last ? last.items.filter(i => i.type === 'comment') : [];
console.log(`\n${last ? last.count : 0} verified comment(s) for ${url}`);
for (const i of shown) console.log('  ·', (i.name ? String(i.name).slice(0, 16) + ' ' : '') + R.toBech32('npub', i.ev.pubkey).slice(0, 12) + '…',
                                     '|', i.deleted ? '(deleted)' : i.hidden ? '(collapsed)' : i.ev.content.replace(/\s+/g, ' ').slice(0, 60));

console.log(failed ? `\n✗ ${failed} drift check(s) failed` : '');
process.exit(failed ? 1 : 0);
