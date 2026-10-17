// The reading layer shared by /thread/ and (later) /embed/. A plain script, not a module: the embed
// runs in a sandboxed frame with an opaque origin, where a module would be fetched with CORS.
// Everything hangs off one global, NCRead, so the page scripts and the Node checks load the same
// file the same way. No build step, no dependencies.
(function (root) {
'use strict';

// ---------------------------------------------------------------------------------------------
// Copied verbatim from NostrComments-Chrome/content.js. Keep identical: a thread is filed under
// the normalised URL, so any difference here means looking in the wrong place. thread/check.mjs
// compares this against the extension.
const _TRACKING = new Set(['gclid','gbraid','wbraid','dclid','fbclid','msclkid','yclid','twclid','igshid','mc_eid','mc_cid','_ga','_gl','mkt_tok','ref_src','ref_url','si','spm','scm','vero_id','oly_anon_id','oly_enc_id','_openstat','wickedid']);
function normalizeUrl(href) {
    try {
        const u = new URL(href);
        const p = u.searchParams;
        const del = [];
        p.forEach((_v, k) => { const kl = k.toLowerCase(); if (_TRACKING.has(kl) || kl.startsWith('utm_') || kl.startsWith('ga_')) del.push(k); });
        del.forEach(k => p.delete(k));
        p.sort();
        const qs = p.toString();
        const hash = (u.hash.startsWith('#/') || u.hash.startsWith('#!')) ? u.hash : '';
        return u.origin + u.pathname + (qs ? '?' + qs : '') + hash;
    } catch(_) { return ''; }
}
function toBech32(hrp, hex) {
    const CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    const GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];
    const pm = v => { let c=1; for (const d of v){const t=c>>25;c=(c&0x1ffffff)<<5^d;for(let i=0;i<5;i++)if((t>>i)&1)c^=GEN[i];} return c; };
    const ex = h => [...h].map(c=>c.charCodeAt(0)>>5).concat(0,...[...h].map(c=>c.charCodeAt(0)&31));
    const bytes = hex.match(/.{2}/g).map(b=>parseInt(b,16));
    const w=[]; let acc=0,bits=0;
    for(const b of bytes){acc=(acc<<8)|b;bits+=8;while(bits>=5){bits-=5;w.push((acc>>bits)&31);}}
    if(bits)w.push((acc<<(5-bits))&31);
    const chk=pm([...ex(hrp),...w,0,0,0,0,0,0])^1;
    return hrp+'1'+[...w,...Array.from({length:6},(_,i)=>(chk>>(5*(5-i)))&31)].map(d=>CS[d]).join('');
}
// ---------------------------------------------------------------------------------------------

// The pages' Content-Security-Policy lists exactly these in connect-src; tests/run.mjs checks that
// the two agree, so adding a relay here without adding it there fails the tests.
const RELAYS = ['wss://nos.lol','wss://relay.damus.io','wss://relay.primal.net',
                'wss://nostr.oxtr.dev','wss://nostr.mom','wss://relay.nostr.net'];

// Ask every relay in parallel and keep the union. No single relay has the whole thread — that is
// the entire point of there being several — so a page that asked only one would under-report and
// look broken in a way nobody could diagnose.
function ask(relay, filters, ms = 6000) {
    return new Promise(resolve => {
        const out = [];
        let ws, settle = () => { settle = () => {}; try { ws.close(); } catch (e) {} resolve(out); };
        const timer = setTimeout(settle, ms);
        try { ws = new WebSocket(relay); } catch (e) { clearTimeout(timer); return settle(); }
        let open = filters.length;
        ws.onopen = () => filters.forEach((f, i) => ws.send(JSON.stringify(['REQ', 'q' + i, f])));
        ws.onerror = () => { clearTimeout(timer); settle(); };
        ws.onmessage = m => {
            let f; try { f = JSON.parse(m.data); } catch (e) { return; }
            if (f[0] === 'EVENT') out.push(f[2]);
            if (f[0] === 'EOSE' && --open <= 0) { clearTimeout(timer); settle(); }
        };
    });
}

// Text arrives from strangers, so it is never handled as markup: every part becomes a text node,
// and a link becomes an anchor built by hand. Only http and https, and never with the referrer.
function renderText(el, text) {
    const doc = el.ownerDocument;
    const parts = String(text).split(/(https?:\/\/[^\s<>"']+)/g);
    for (const part of parts) {
        if (/^https?:\/\//.test(part)) {
            const a = doc.createElement('a');
            a.href = part;
            a.textContent = part;
            a.target = '_blank';
            a.rel = 'nofollow ugc noopener noreferrer';
            a.referrerPolicy = 'no-referrer';
            el.appendChild(a);
        } else if (part) {
            el.appendChild(doc.createTextNode(part));
        }
    }
}

root.NCRead = { normalizeUrl, toBech32, RELAYS, ask, renderText };
})(typeof window !== 'undefined' ? window : globalThis);
