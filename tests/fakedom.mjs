// Just enough of a DOM to run the page scripts in Node: elements that record their children,
// attributes and text. It only knows what the scripts here use, and it throws on anything else,
// so a script that starts doing more than expected fails the tests rather than passing quietly.
export function fakeDocument() {
    class El {
        constructor(tag) {
            this.tag = tag; this.children = []; this.parent = null; this.attrs = {}; this._text = '';
            this.className = ''; this.style = {}; this.ownerDocument = doc;
        }
        set textContent(t) { this.children.forEach(c => { c.parent = null; }); this.children = []; this._text = String(t); }
        get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
        appendChild(c) {
            if (c.tag === '#fragment') { [...c.children].forEach(x => this.appendChild(x)); c.children = []; return c; }
            if (c.parent) c.parent.children.splice(c.parent.children.indexOf(c), 1);
            c.parent = this; this.children.push(c); return c;
        }
        append(...cs) { cs.forEach(c => this.appendChild(c)); }
        replaceChild(n, old) { const i = this.children.indexOf(old); if (i < 0) throw new Error('not a child'); n.parent = this; old.parent = null; this.children[i] = n; return old; }
        replaceWith(n) {
            const p = this.parent, i = p.children.indexOf(this);
            const add = n.tag === '#fragment' ? n.children.splice(0) : [n];
            add.forEach(x => { x.parent = p; }); this.parent = null; p.children.splice(i, 1, ...add);
        }
        setAttribute(k, v) { this.attrs[k] = String(v); }
        getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
        get previousElementSibling() { const p = this.parent; return p ? p.children[p.children.indexOf(this) - 1] || null : null; }
        // Every element in the tree below, depth first.
        all() { return this.children.flatMap(c => [c, ...c.all()]); }
    }
    const text = t => { const n = new El('#text'); n._text = String(t); return n; };
    const doc = {
        createElement: tag => new El(tag),
        createTextNode: text,
        createDocumentFragment: () => new El('#fragment'),
        querySelector: sel => { if (sel === 'link[rel~="canonical"]') return doc.canonical || null; throw new Error('querySelector ' + sel); },
        getElementById: id => doc.ids[id] || null,
        ids: {},
        canonical: null,
        documentElement: { className: '', scrollHeight: 400 },
        body: null,
    };
    doc.body = new El('body');
    doc.make = (tag, id) => { const e = new El(tag); if (id) doc.ids[id] = e; return e; };
    return doc;
}

// The visible text of a list, one line per item, with its classes — what a reader would see.
export const lines = list => list.children.map(li => `[${li.className}] ${li.textContent}`);
