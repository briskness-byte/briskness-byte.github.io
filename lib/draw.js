// Drawing a thread, shared by /thread/ and the embed. lib/read.js decides what is shown and in what
// order; this turns its records into list items. Everything that came from a stranger — text, a
// name — goes in as text, never as markup.
(function (root) {
'use strict';
const { toBech32, renderText } = root.NCRead;

const when = ts => {
    const s = Math.floor(Date.now() / 1000) - ts;
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    if (s < 86400 * 30) return Math.floor(s / 86400) + 'd ago';
    return new Date(ts * 1000).toLocaleDateString();
};

function el(doc, tag, cls, text) {
    const e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
}

// A placeholder item that is replaced by the real thing when its button is pressed. A button
// rather than a clickable item, so it can be reached and pressed from the keyboard.
function placeholder(doc, cls, label, open) {
    const li = el(doc, 'li', cls);
    const b = el(doc, 'button', 'opener', label);
    b.type = 'button';
    b.onclick = () => li.replaceWith(open());
    li.appendChild(b);
    return li;
}

function drawComment(doc, item, reveal) {
    const { ev, sc, depth } = item;
    const li = el(doc, 'li', depth > 0 ? 'reply d' + Math.min(depth, 6) : '');
    // Only reached for a deleted comment with replies under it. No name: the author asked for it
    // to be gone, and what is left marks that something was here.
    if (item.deleted) { li.className = (li.className + ' tomb').trim(); li.textContent = 'Comment deleted by its author'; return li; }
    if (item.hidden && !reveal) {
        return placeholder(doc, (li.className + ' tomb').trim(), `Hidden (${sc.down} downvotes) — show`, () => drawComment(doc, item, true));
    }

    const who = el(doc, 'div', 'who');
    // The name is whatever its owner chose, so it could say anything — "Site owner", or another
    // person's name. The key it belongs to is always shown beside it.
    const npub = toBech32('npub', ev.pubkey);
    if (item.name) who.appendChild(el(doc, 'span', 'name', String(item.name).slice(0, 40)));
    who.appendChild(el(doc, 'span', 'npub', npub.slice(0, 12) + '…' + npub.slice(-4)));
    who.appendChild(el(doc, 'span', 'when', when(ev.created_at)));
    if (item.legacy) {
        const tag = el(doc, 'span', 'tag', 'note');
        tag.title = 'An ordinary Nostr note that links to this page, rather than a comment written on it.';
        who.appendChild(tag);
    }

    const body = el(doc, 'div', 'text');
    renderText(body, ev.content);
    li.append(who, body);
    return li;
}

// Draws the view into a list. With `max`, stops after that many items and returns how many were
// left out, so the page can point to the rest.
function drawThread(list, view, max = Infinity) {
    const doc = list.ownerDocument;
    list.textContent = '';
    if (view.capped) list.appendChild(el(doc, 'li', 'tomb', `Showing the newest ${view.limit} comments — this thread has more than one request can carry.`));
    let drawn = 0;
    for (const item of view.items) {
        if (drawn >= max) break;
        drawn++;
        if (item.type === 'fold') {
            list.appendChild(placeholder(doc, 'fold', `and ${item.rest.length} more like this from the same key — show`, () => {
                const frag = doc.createDocumentFragment();
                item.rest.forEach(r => frag.appendChild(drawComment(doc, r)));
                return frag;
            }));
        } else {
            list.appendChild(drawComment(doc, item));
        }
    }
    return view.items.length - drawn;
}

root.NCDraw = { drawThread, drawComment };
})(typeof window !== 'undefined' ? window : globalThis);
