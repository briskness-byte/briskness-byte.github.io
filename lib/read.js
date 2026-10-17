// The reading layer shared by /thread/ and (later) /embed/. A plain script, not a module: the embed
// runs in a sandboxed frame with an opaque origin, where a module would be fetched with CORS.
// Everything hangs off one global, NCRead, so the page scripts and the Node checks load the same
// file the same way. No build step, no dependencies.
//
// The rules for reading a thread are the extension's, not this file's. Every block between
//     // content.js: <name>        and        // content.js: end
// is copied line for line from NostrComments-Chrome/content.js, and thread/check.mjs fails when
// any of them no longer appears there unchanged. When the extension changes a rule, the check says
// so, and the block is copied again. What sits between the blocks is plumbing: the state those
// lines expect, the relay round-trips, and turning the result into something a page can draw.
(function (root) {
'use strict';

// ---------------------------------------------------------------------------------------------
// The thread key. A thread is filed under the normalised URL, so any difference from the extension
// here means looking in the wrong place.
// content.js: normalizeUrl
const _TRACKING = new Set(['gclid','gbraid','wbraid','dclid','fbclid','msclkid','yclid','twclid','igshid','mc_eid','mc_cid','_ga','_gl','mkt_tok','ref_src','ref_url','si','spm','scm','vero_id','oly_anon_id','oly_enc_id','_openstat','wickedid']);
function normalizeUrl(href) {
    try {
        const u = new URL(href);
        const p = u.searchParams;
        // NB: collect keys via forEach — spreading the searchParams keys() iterator
        // is not supported in Firefox content scripts and would throw and abort init.
        const del = [];
        p.forEach((_v, k) => { const kl = k.toLowerCase(); if (_TRACKING.has(kl) || kl.startsWith('utm_') || kl.startsWith('ga_')) del.push(k); });
        del.forEach(k => p.delete(k));
        p.sort();
        const qs = p.toString();
        const hash = (u.hash.startsWith('#/') || u.hash.startsWith('#!')) ? u.hash : '';
        return u.origin + u.pathname + (qs ? '?' + qs : '') + hash;
    } catch(_) {
// content.js: end
        // The extension falls back to the address of the page it runs on. This page has none of
        // its own to offer, so a malformed address is reported as one.
        return '';
    }
}
// content.js: toBech32
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
// content.js: end

// ---------------------------------------------------------------------------------------------
// Verification, verify-only. The extension's secp256k1 also signs; nothing here ever holds a key,
// so pubKey and sign are left out and only the lines verify needs are copied. This is the
// extension's own hand-rolled code, due to be replaced by an audited library; the check makes this
// copy follow when it is.
const _secp = (() => {
    // content.js: secp
    const P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
    const N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    const G=[0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n];
    const m=(a,b=P)=>((a%b)+b)%b;
    const inv=a=>{a=m(a);let old_r=a,r=P,old_s=1n,s=0n;while(r!==0n){const q=old_r/r;[old_r,r]=[r,old_r-q*r];[old_s,s]=[s,old_s-q*s];}return m(old_s);};
    const pa=(A,B)=>{
        if(!A)return B;if(!B)return A;
        const[ax,ay]=A,[bx,by]=B;
        if(ax===bx){if(ay!==by)return null;const l=m(3n*ax*ax*inv(2n*ay));const x=m(l*l-2n*ax);return[x,m(l*(ax-x)-ay)];}
        const l=m((by-ay)*inv(bx-ax));const x=m(l*l-ax-bx);return[x,m(l*(ax-x)-ay)];
    };
    // Scalar multiplication in Jacobian coordinates, which need one inversion at the end rather than
    // one for every addition. Verifying a signature is the dearest thing this extension does and it
    // does it for every event in a thread, so the affine version — an extended-Euclid inversion per
    // step, some eight hundred of them — was twenty milliseconds an event. tests/secp-differential
    // holds this against a plain affine implementation.
    const jd=Pt=>{if(!Pt)return null;const[X,Y,Z]=Pt;if(Y===0n)return null;
        const A=X*X%P,B=Y*Y%P,C=B*B%P,D=m(2n*((X+B)*(X+B)-A-C)),E=3n*A,F=E*E%P,X3=m(F-2n*D);
        return[X3,m(E*(D-X3)-8n*C),2n*Y*Z%P];};
    const ja=(p1,p2)=>{if(!p1)return p2;if(!p2)return p1;
        const[X1,Y1,Z1]=p1,[X2,Y2,Z2]=p2,Z1Z1=Z1*Z1%P,Z2Z2=Z2*Z2%P;
        const U1=X1*Z2Z2%P,U2=X2*Z1Z1%P,S1=Y1*Z2%P*Z2Z2%P,S2=Y2*Z1%P*Z1Z1%P;
        if(U1===U2)return S1===S2?jd(p1):null;
        const H=m(U2-U1),R=m(S2-S1),HH=H*H%P,HHH=H*HH%P,V=U1*HH%P,X3=m(R*R-HHH-2n*V);
        return[X3,m(R*(V-X3)-S1*HHH),H*Z1%P*Z2%P];};
    const pm=(k,Pt)=>{if(!Pt)return null;let R=null,Q=[Pt[0],Pt[1],1n];
        while(k>0n){if(k&1n)R=ja(R,Q);Q=jd(Q);k>>=1n;}
        if(!R)return null;const zi=inv(R[2]),z2=zi*zi%P;return[R[0]*z2%P,R[1]*z2%P*zi%P];};
    const h2b=h=>{const b=new Uint8Array(h.length/2);for(let i=0;i<h.length;i+=2)b[i/2]=parseInt(h.slice(i,i+2),16);return b;};
    const b2h=b=>Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
    const n2h=(n,l=32)=>n.toString(16).padStart(l*2,'0');
    const h2n=h=>BigInt('0x'+h);
    const sha=async(...a)=>{const c=new Uint8Array(a.reduce((s,b)=>s+b.length,0));let o=0;for(const b of a){c.set(b,o);o+=b.length;}return new Uint8Array(await crypto.subtle.digest('SHA-256',c));};
    const th=async(tag,...ms)=>{const t=await sha(new TextEncoder().encode(tag));return sha(t,t,...ms);};
    const mpow=(b,e,n)=>{let r=1n;b=((b%n)+n)%n;while(e>0n){if(e&1n)r=r*b%n;b=b*b%n;e>>=1n;}return r;};
    const liftX=x=>{const y2=m(x*x*x+7n);const y=mpow(y2,(P+1n)/4n,P);return m(y*y)===y2?[x,y%2n===0n?y:P-y]:null;};
    const verify=async(pubHex,msgBytes,sigHex)=>{try{const r=h2n(sigHex.slice(0,64)),s=h2n(sigHex.slice(64));if(r>=P||s>=N)return false;const Pt=liftX(h2n(pubHex));if(!Pt)return false;const e=m(h2n(b2h(await th('BIP0340/challenge',h2b(n2h(r)),h2b(pubHex),msgBytes))),N);const R=pa(pm(s,G),pm(N-e,Pt));return!!R&&R[1]%2n===0n&&R[0]===r;}catch(_){return false;}};
    // content.js: end
    return{b2h,verify};
})();
// content.js: verifyEvent
function wellFormed(ev) {
    return !!ev && typeof ev === 'object'
        && typeof ev.id === 'string' && typeof ev.pubkey === 'string'
        && Number.isInteger(ev.kind) && Number.isInteger(ev.created_at)
        && typeof ev.content === 'string' && ev.content.length <= 100000
        && Array.isArray(ev.tags) && ev.tags.length <= 2000
        && ev.tags.every(t => Array.isArray(t) && t.length <= 20 && t.every(x => typeof x === 'string'));
}
// The id is a claim about the content, so it is checked against the content every time — one
// SHA-256, which is cheap. Only the signature check is remembered, and under the id, key and
// signature together: a cache on the id alone answered "valid" for any later event that merely
// repeated the id of one that had been, and "invalid" for the genuine event after a forged
// copy had been seen first.
const _verifyCache = new Map(); // id|pubkey|sig -> boolean | Promise<boolean>
async function verifyEvent(ev) {
    if (!wellFormed(ev)) return false;
    if (!/^[0-9a-f]{64}$/i.test(ev.id) || !/^[0-9a-f]{64}$/i.test(ev.pubkey)) return false;
    if (typeof ev.sig !== 'string' || !/^[0-9a-f]{128}$/i.test(ev.sig)) return false;
    let idBytes;
    try {
        const serial = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
        idBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(serial)));
        if (_secp.b2h(idBytes) !== ev.id.toLowerCase()) return false;
    } catch(_) { return false; }
    const key = ev.id + '|' + ev.pubkey + '|' + ev.sig;
    const hit = _verifyCache.get(key);
    if (hit !== undefined) return hit;
    if (_verifyCache.size > 5000) _verifyCache.clear();
    const pr = (async () => { try { return await _secp.verify(ev.pubkey, idBytes, ev.sig); } catch(_) { return false; } })();
    _verifyCache.set(key, pr);
    const ok = await pr;
    _verifyCache.set(key, ok);
    return ok;
}
// content.js: end

// ---------------------------------------------------------------------------------------------
// The pages' Content-Security-Policy lists exactly these in connect-src; tests/run.mjs checks that
// the two agree, and check.mjs that they are the extension's defaults.
const RELAYS = ['wss://nos.lol','wss://relay.damus.io','wss://relay.primal.net',
                'wss://nostr.oxtr.dev','wss://nostr.mom','wss://relay.nostr.net'];

// A relay can send anything and as much of it as it likes. The extension's own filters ask for at
// most 4500 events, so a relay sending more than this is not answering the question.
const MAX_PER_RELAY = 5000;

// Ask one relay and collect what it sends until it says it is done, or until it has had long
// enough. Every relay is asked in parallel and the union is kept: no single relay has the whole
// thread — that is the entire point of there being several.
function ask(relay, filters, ms = 6000) {
    return new Promise(resolve => {
        const out = [];
        let ws, settle = () => { settle = () => {}; try { ws.close(); } catch (e) {} resolve(out); };
        const timer = setTimeout(settle, ms);
        try { ws = new WebSocket(relay); } catch (e) { clearTimeout(timer); return settle(); }
        let open = filters.length;
        const sub = 'r' + Math.random().toString(36).slice(2, 8);
        ws.onopen = () => filters.forEach((f, i) => ws.send(JSON.stringify(['REQ', sub + i, f])));
        ws.onerror = () => { clearTimeout(timer); settle(); };
        ws.onmessage = m => {
            let f; try { f = JSON.parse(m.data); } catch (e) { return; }
            if (!Array.isArray(f)) return;
            if (f[0] === 'EVENT' && out.length < MAX_PER_RELAY) out.push(f[2]);
            if ((f[0] === 'EOSE' || f[0] === 'CLOSED') && --open <= 0) { clearTimeout(timer); settle(); }
        };
    });
}
const askAll = filters => Promise.all(RELAYS.map(r => ask(r, filters))).then(lists => lists.flat());

// ---------------------------------------------------------------------------------------------
// One thread: everything read for one address, and the extension's rules for what of it is shown.
//
// The state carries the extension's names so the copied lines run unchanged. Some of it belongs to
// features a reader without a key does not have — muting, search, its own votes — and is simply
// empty here, which makes those lines do nothing.
function createThread(pageUrl, altPageUrls = []) {
    const myPub = null;
    const mutedPubkeys = new Set();
    const muteWords = [];
    const q = '';
    const linkedEntity = null;
    const sort = { value: 'newest' };    // the extension's default order

    // content.js: limits
    const COMMENT_LIMIT = 500, REACTION_LIMIT = 3000;
    // content.js: end
    // content.js: kinds
    const COMMENT_KIND = 1111;
    // Kind 1 notes carrying an r tag for this page are read as well, and never written.
    //
    // Not for our own history — that is tiny — but because an r-tagged note is how the rest of
    // Nostr talks about a URL, from any client, and asking only for 1111 made all of it
    // invisible. It also closed a gap the notifications could not: they listen on kind 1 too,
    // so a mention in an ordinary note lit the badge while the thread had nowhere to show it.
    //
    // Read-only is not squeamishness. NIP-22: "Comments MUST NOT be used to reply to kind 1
    // notes." So a 1111 may not hang off one of these, and replying in kind would put the reply
    // back in everybody's feed, which is the thing kind 1111 exists to stop.
    const LEGACY_KIND = 1;
    const isLegacy = ev => ev.kind === LEGACY_KIND;
    // content.js: end
    // content.js: pageFilters
    const pageFilters = () => {
        const urls = [pageUrl, ...altPageUrls];
        const filters = [
            {kinds:[COMMENT_KIND], "#I":urls, limit: COMMENT_LIMIT},
            {kinds:[LEGACY_KIND], "#r":urls, limit: COMMENT_LIMIT},
            {kinds:[5], "#r":urls, limit: COMMENT_LIMIT},
            {kinds:[7], "#r":urls, limit: REACTION_LIMIT},
        ];
        // NIP-22: an addressable event is root-scoped with an A tag, a regular one with E — never
        // I, which is for external identifiers like a URL. Comments only: a legacy kind-1 note or
        // a reaction naming a native Nostr entity already reaches its audience the ordinary way,
        // through that entity's own id, not through this page.
        if (linkedEntity?.addr) filters.push({kinds:[COMMENT_KIND], "#A":[linkedEntity.addr], limit: COMMENT_LIMIT});
        else if (linkedEntity?.id) filters.push({kinds:[COMMENT_KIND], "#E":[linkedEntity.id], limit: COMMENT_LIMIT});
        return filters;
    };
    const refetchFilters = ids => [
        {kinds:[COMMENT_KIND], "#e": ids, limit: COMMENT_LIMIT},
        {kinds:[LEGACY_KIND], "#e": ids, limit: COMMENT_LIMIT},
        {kinds:[5], "#e": ids, limit: COMMENT_LIMIT},
        {kinds:[7], "#e": ids, limit: REACTION_LIMIT},
    ];
    // content.js: end

    const comments = [];
    const scores = new Map();
    const votes = new Map();
    const profiles = new Map();
    // content.js: profileAt
    const profileAt = new Map();       // pubkey -> created_at of the kind 0 currently applied
    // content.js: end
    // content.js: deletions
    const deletionRequests = new Map();
    const isDeleted = ev => deletionRequests.get(ev.id)?.has(ev.pubkey) === true;
    // content.js: end
    // content.js: recount
    function recount(id) {
        const m = votes.get(id);
        if (!m) return;
        let up = 0, down = 0;
        m.forEach(v => { if (v.val === 1) up++; else down++; });
        scores.set(id, {up, down, my: myPub ? m.get(myPub)?.val : undefined});
    }
    // content.js: end

    // An id counts as seen once an event carrying it has passed verification, never on arrival:
    // a forged copy that arrives first must not use the id up for the genuine one. Same rule as
    // the extension's queueVerify, without its queue — offer() is awaited one event at a time.
    const _seenEv = new Set();
    async function verifyOnce(ev) {
        if (_seenEv.has(ev.id)) return false;
        if (!(await verifyEvent(ev)) || _seenEv.has(ev.id)) return false;
        _seenEv.add(ev.id);
        return true;
    }

    // Hand one event from a relay to the thread. Shape first, then the extension's tag rules, then
    // the signature; only an event that passes all three changes anything.
    async function offer(ev) {
        // content.js: shape
        if (!wellFormed(ev)) return;
        if (typeof ev.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(ev.pubkey)) return;
        if (typeof ev.id !== 'string' || !/^[0-9a-f]{64}$/i.test(ev.id)) return;
        // content.js: end
        if (ev.kind === COMMENT_KIND || ev.kind === LEGACY_KIND) {
            if (comments.find(c => c.id === ev.id) || _seenEv.has(ev.id)) return false;
            // content.js: pageTag
            const commentIds = new Set(comments.map(c => c.id));
            // 1111 is scoped by the uppercase I tag; a kind 1 has no such thing and
            // uses the r tag the old versions wrote, which is also what any other
            // client uses to link a note to a URL.
            const pageTag = ev.kind === COMMENT_KIND ? "I" : "r";
            const hasPageTag = ev.tags?.some(t => t[0]===pageTag && (t[1]===pageUrl || altPageUrls.includes(t[1])));
            const hasLinkedTag = ev.kind === COMMENT_KIND && !!linkedEntity && ev.tags?.some(t =>
                (linkedEntity.addr && t[0] === 'A' && t[1] === linkedEntity.addr) ||
                (linkedEntity.id && t[0] === 'E' && t[1] === linkedEntity.id));
            const isReply = ev.tags?.some(t => t[0]==="e" && commentIds.has(t[1]));
            // content.js: end
            if (!(hasPageTag || hasLinkedTag || isReply)) return false;
            if (!(await verifyOnce(ev))) return false;
            comments.push(ev);
            return true;
        }
        if (ev.kind === 5) {
            const delEv = ev;
            // content.js: deletionTargets
            const targets = (delEv.tags || []).filter(t => t[0] === 'e' && /^[0-9a-f]{64}$/i.test(t[1] || '')).map(t => t[1]);
            if (!targets.length) return;
            // content.js: end
            if (!(await verifyOnce(delEv))) return false;
            let changed = false;
            // content.js: deletionApply
            for (const id of targets) {
                if (!deletionRequests.has(id)) deletionRequests.set(id, new Set());
                if (!deletionRequests.get(id).has(delEv.pubkey)) { deletionRequests.get(id).add(delEv.pubkey); changed = true; }
            }
            // content.js: end
            return changed;
        }
        if (ev.kind === 7) {
            // content.js: voteValue
            const e = ev.tags?.find(t => t[0]==="e")?.[1];
            if (e) {
                const val = ev.content === '+' || ev.content === '' ? 1 : ev.content === '-' ? -1 : 0;
            // content.js: end
                if (!val || !(await verifyOnce(ev))) return false;
                if (!votes.has(e)) votes.set(e, new Map());
                // content.js: voteApply
                const prev = votes.get(e).get(ev.pubkey);
                if (prev && prev.at > ev.created_at) return;
                votes.get(e).set(ev.pubkey, {val, at: ev.created_at});
                // content.js: end
                recount(e);
                return true;
            }
            return false;
        }
        if (ev.kind === 0) {
            if (!(await verifyOnce(ev))) return false;
            try {
                // content.js: profile
                const seenAt = profileAt.get(ev.pubkey);
                if (seenAt !== undefined && ev.created_at <= seenAt) return;
                const p = JSON.parse(ev.content);
                profileAt.set(ev.pubkey, ev.created_at);
                // name first, display_name only as a fallback. NIP-24 says name
                // should always be set; reading display_name first would mean a
                // name published here changed nothing on screen for the third of
                // profiles whose two fields differ.
                profiles.set(ev.pubkey, p.name || p.display_name || null);
                // content.js: end
            } catch (e) {}
            return true;
        }
        return false;
    }

    // What to draw, in order. Each item is a comment with its depth and score, flagged when the
    // extension would collapse it or show it as deleted; a fold carries the near-identical comments
    // it stands for. The extension builds its DOM inside these same lines, so `list` and `makeItem`
    // here collect plain records for the page to draw instead.
    function layout() {
        const items = [];
        const list = { appendChild: item => items.push(item) };
        const makeItem = (ev, sc, hidden, depth) => ({ type: 'comment', ev, sc, hidden, depth, deleted: isDeleted(ev),
                                                       legacy: isLegacy(ev), name: profiles.get(ev.pubkey) || null });
        // content.js: render
        const hitsMuteWord = ev => { const cl = ev.content.toLowerCase(); return muteWords.some(w => cl.includes(w)); };
        // What this reader could see, before the search box narrows it. The badge counts this
        // rather than the raw list, so it cannot promise a discussion that turns out to be one
        // deleted comment and two people you muted.
        const visible = c => !mutedPubkeys.has(c.pubkey) && !isDeleted(c) && !hitsMuteWord(c);
        let shown = comments.filter(c => visible(c) && c.content.toLowerCase().includes(q));

        // A reply is only ever drawn from its parent, so dropping a hidden comment used to drop
        // everything hanging off it — replies written by other people, which nobody asked to
        // hide and which simply vanished. Keep such a comment as a placeholder so the thread
        // survives — whether it went because its author deleted it, because the reader muted
        // them, or because it tripped a muted word. When nothing hangs off it there is nothing
        // to preserve and it stays gone. The search box is deliberately not in this list:
        // filtering is a question you asked, and it ends when you clear the box.
        {
            const byId = new Map(comments.map(c => [c.id, c]));
            const parentIdOf = ev => ev.tags?.find(t => t[0] === 'e' && byId.has(t[1]))?.[1];
            const keep = new Set();
            for (const c of shown) {
                // Same depth cap as appendWithReplies: a relay can send anything, and walking
                // parent links from untrusted events should not be able to spin forever.
                let p = parentIdOf(c);
                for (let d = 0; p && d <= 10; d++, p = parentIdOf(byId.get(p))) {
                    const parent = byId.get(p);
                    if (isDeleted(parent) || mutedPubkeys.has(parent.pubkey) || hitsMuteWord(parent)) keep.add(p);
                }
            }
            if (keep.size) shown = shown.concat(comments.filter(c => keep.has(c.id)));
        }

        if (sort.value === 'oldest') shown.sort((a,b) => a.created_at - b.created_at);
        if (sort.value === 'newest') shown.sort((a,b) => b.created_at - a.created_at);
        if (sort.value === 'upvotes') shown.sort((a,b) => (scores.get(b.id)?.up||0) - (scores.get(a.id)?.up||0));

        const total = Array.from(scores.values()).reduce((a,sc)=>a+sc.up+sc.down,0);
        const hide = Math.max(5, Math.round(0.1 * total));

        const commentIds = new Set(comments.map(c => c.id));
        const getParentId = ev => ev.tags?.find(t => t[0]==='e' && commentIds.has(t[1]))?.[1];
        // A reply is only ever drawn from its parent, so while a search was running a reply
        // that matched it was invisible whenever its parent did not — the one comment on the
        // page containing what you searched for, hidden because the comment above it did not
        // contain it. Keeping the parent as a placeholder was the other option and it is
        // worse: it puts text on screen that the reader has just asked not to see. So a search
        // returns a flat list of matches instead, which is what a search elsewhere does.
        const flat = !!q;
        const topLevel = flat ? shown : shown.filter(ev => !getParentId(ev));
        // content.js: end
        // content.js: fold
        const SAME_MIN = 3;
        const sameKey = ev => ev.pubkey + '\u0000' + (ev.content || '').toLowerCase()
            .replace(/https?:\/\/\S+/g, ' ').replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
        const sameGroups = new Map();
        for (const ev of topLevel) {
            const k = sameKey(ev);
            if (!sameGroups.has(k)) sameGroups.set(k, []);
            sameGroups.get(k).push(ev);
        }
        // One entry per thing that gets drawn, in the order the thread already had.
        const entries = [];
        const folded = new Set();
        for (const ev of topLevel) {
            if (folded.has(ev.id)) continue;
            const g = sameGroups.get(sameKey(ev));
            if (g && g.length >= SAME_MIN && g[0].id === ev.id) {
                g.slice(1).forEach(x => folded.add(x.id));
                entries.push({ lead: ev, rest: g.slice(1) });
            } else {
                entries.push({ lead: ev, rest: [] });
            }
        }
        const replies = flat ? [] : shown.filter(ev => !!getParentId(ev));

        const visited = new Set();
        function appendWithReplies(ev, depth) {
            if (visited.has(ev.id) || depth > 10) return;
            visited.add(ev.id);
            const sc = scores.get(ev.id) || {up:0,down:0};
            list.appendChild(makeItem(ev, sc, sc.down >= hide, depth));
            replies.filter(r => getParentId(r) === ev.id)
                   .forEach(r => appendWithReplies(r, depth + 1));
        }
        // content.js: end
        // content.js: hitLimit
        const hitLimit = k => comments.reduce((n, c) => n + (c.kind === k ? 1 : 0), 0) >= COMMENT_LIMIT;
        // content.js: end
        entries.forEach(e => {
            appendWithReplies(e.lead, 0);
            if (e.rest.length) items.push({ type: 'fold', rest: e.rest.map(r => makeItem(r, scores.get(r.id) || {up:0,down:0}, false, 0)) });
        });
        return { items, capped: hitLimit(COMMENT_KIND) || hitLimit(LEGACY_KIND),
                 count: comments.filter(visible).length, total: comments.length, limit: COMMENT_LIMIT };
    }

    return { pageFilters, refetchFilters, offer, layout, comments, authors: () => [...new Set(comments.map(c => c.pubkey))] };
}

// The extension reads a page's <link rel="canonical"> itself. The embed cannot see the page it
// sits in, so the snippet passes the attribute's raw value and the page's own address, and the
// extension's lines run on those here. Like there, this only widens what is read.
function findAltPageUrls(pageUrl, href, pageHref) {
    const location = { href: pageHref };
    const out = [];
    try {
        // content.js: altPageUrls
        if (href) {
            const abs = new URL(href, location.href);
            // Same restriction as safeLink and for the same reason: this becomes a relay
            // filter value, and there is no reason for it to be anything but a web page.
            if (abs.protocol === 'http:' || abs.protocol === 'https:') {
                const norm = normalizeUrl(abs.href);
                if (norm && norm !== pageUrl) out.push(norm);
            }
        }
        // content.js: end
    } catch(_) {}
    return out;
}

// Several relays hold the same event, and a dishonest one can send a different event under the
// same id. Every distinct copy is kept so the genuine one still gets its turn; only one can pass.
function distinct(events) {
    const byId = new Map();
    for (const ev of events) {
        if (!ev || typeof ev !== 'object' || typeof ev.id !== 'string') continue;
        const copies = byId.get(ev.id) || [];
        const key = JSON.stringify([ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content, ev.sig]);
        if (copies.length < 4 && !copies.some(c => c.key === key)) copies.push({ key, ev });
        byId.set(ev.id, copies);
    }
    return [...byId.values()].flat().map(c => c.ev);
}

// Offer a batch, oldest first so a parent is known before its replies, yielding now and then so
// a big thread does not freeze the page while its signatures are checked.
async function offerAll(thread, events, kinds, onProgress) {
    const batch = distinct(events).filter(e => kinds.includes(e.kind))
        .sort((a, b) => (a.created_at || 0) - (b.created_at || 0));
    for (let i = 0; i < batch.length; i++) {
        await thread.offer(batch[i]);
        if (i % 25 === 24) { onProgress && onProgress(i + 1, batch.length); await new Promise(r => setTimeout(r, 0)); }
    }
}

// The whole read, in the extension's order: the page's own events, then a second round by the ids
// of the comments found, then the authors' profiles. Comments are checked and drawn first; the
// votes, the slowest part to verify, come last and only change what is collapsed.
async function readThread(pageUrl, altPageUrls, onUpdate, onProgress) {
    const thread = createThread(pageUrl, altPageUrls);
    const first = await askAll(thread.pageFilters());
    await offerAll(thread, first, [1111, 1, 5], onProgress);
    const ids = thread.comments.map(c => c.id);
    const second = ids.length ? await askAll(thread.refetchFilters(ids)) : [];
    await offerAll(thread, second, [1111, 1, 5], onProgress);
    onUpdate(thread.layout(), false);
    if (!thread.comments.length) return thread;
    const authors = thread.authors();
    await offerAll(thread, await askAll([{ kinds: [0], authors }]), [0], onProgress);
    onUpdate(thread.layout(), false);
    await offerAll(thread, first.concat(second), [7], onProgress);
    onUpdate(thread.layout(), true);
    return thread;
}

// ---------------------------------------------------------------------------------------------
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

// Verifying needs SHA-256 from WebCrypto, which browsers only offer on https pages.
const canVerify = () => !!(root.crypto && root.crypto.subtle);

root.NCRead = { normalizeUrl, toBech32, RELAYS, ask, renderText, verifyEvent, wellFormed, _secp,
                createThread, readThread, distinct, canVerify, findAltPageUrls };
})(typeof window !== 'undefined' ? window : globalThis);
