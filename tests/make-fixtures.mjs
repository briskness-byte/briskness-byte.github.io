// Writes tests/fixtures.json: signed events for the reading tests in tests/run.mjs.
//
//     node tests/make-fixtures.mjs
//
// Signed with the extension's own code (it needs the NostrComments repo next door), because this
// site only ever verifies and has no signing code of its own. The fixtures are committed, so the
// tests run without the extension and without a network. Rerun this only to add a scenario.
// Every key here is a throwaway derived from a label, never anybody's real key.
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const { extensionCode } = await import(path.resolve(HERE, '../../NostrComments/tests/harness.mjs'));
const X = extensionCode();

const PAGE = 'https://example.com/article';
const OTHER = 'https://example.com/another-article';
const T0 = 1760000000;
const key = label => crypto.createHash('sha256').update('nc-reader-fixture:' + label).digest('hex');
const K = Object.fromEntries(['alice', 'bob', 'carol', 'spammer', 'mallory', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6'].map(n => [n, key(n)]));
const pub = n => X._secp.pubKey(K[n]);

const events = {};
let t = T0;
const make = async (name, who, ev) => { events[name] = await X.sign(K[who], { created_at: t++, tags: [], content: '', ...ev }); return events[name]; };
const comment = (name, who, content, extra = []) => make(name, who, { kind: 1111, content, tags: [['I', PAGE], ['K', 'web'], ['i', PAGE], ['k', 'web'], ...extra] });

await comment('plain', 'alice', 'A plain comment on the article.');
await comment('hostile', 'bob', '<script>alert(1)</script><img src=x onerror=alert(1)> see https://example.org/x');
await make('lowercaseOnly', 'carol', { kind: 1111, content: 'Only a lowercase i tag.', tags: [['i', PAGE], ['k', 'web']] });
await make('otherPage', 'carol', { kind: 1111, content: 'About another page.', tags: [['I', OTHER], ['K', 'web']] });
await make('legacyNote', 'carol', { kind: 1, content: 'An ordinary note linking the article.', tags: [['r', PAGE]] });
await make('legacyNoTag', 'carol', { kind: 1, content: 'A note with no r tag.', tags: [] });
// A reply that carries no page tag at all: reachable only through the second round, by the id of
// the comment it answers.
await make('replyNoPageTag', 'carol', { kind: 1111, content: 'A reply found only by its parent.', tags: [['e', events.plain.id], ['k', '1111']] });

// Deletions.
await comment('deletedByAuthor', 'alice', 'Alice will delete this.');
await make('deleteByAuthor', 'alice', { kind: 5, tags: [['e', events.deletedByAuthor.id], ['k', '1111'], ['r', PAGE]] });
await comment('deleteAttempted', 'bob', 'Mallory will try to delete this.');
await make('deleteByOther', 'mallory', { kind: 5, tags: [['e', events.deleteAttempted.id], ['k', '1111'], ['r', PAGE]] });
await comment('deletedParent', 'bob', 'Bob will delete this, but somebody answered it.');
await comment('replyToDeleted', 'carol', 'An answer to the deleted comment.', [['e', events.deletedParent.id]]);
await make('deleteParent', 'bob', { kind: 5, tags: [['e', events.deletedParent.id], ['k', '1111'], ['r', PAGE]] });

// Repeats: three near-identical from one key fold; two from another key do not.
await comment('same1', 'spammer', 'Buy now!! https://shop.example/a?c=1');
await comment('same2', 'spammer', 'buy NOW https://shop.example/a?c=2');
await comment('same3', 'spammer', 'Buy now.');
await comment('pair1', 'carol', 'Thanks for this.');
await comment('pair2', 'carol', 'thanks for this!');

// Votes. Five down-votes collapse a comment (the threshold is max(5, 10% of all votes)); four do
// not. A voter whose newer reaction is an up-vote has changed their mind.
await comment('downvoted', 'mallory', 'Five people voted this down.');
await comment('fourDown', 'mallory', 'Four people voted this down.');
for (const v of ['v1', 'v2', 'v3', 'v4', 'v5']) await make('down_' + v, v, { kind: 7, content: '-', tags: [['e', events.downvoted.id], ['p', pub('mallory')], ['r', PAGE]] });
for (const v of ['v1', 'v2', 'v3', 'v4']) await make('four_' + v, v, { kind: 7, content: '-', tags: [['e', events.fourDown.id], ['p', pub('mallory')], ['r', PAGE]] });
await comment('mindChanged', 'mallory', 'Five down-votes, but one voter changed their mind.');
for (const v of ['v1', 'v2', 'v3', 'v4', 'v5']) await make('mc_' + v, v, { kind: 7, content: '-', tags: [['e', events.mindChanged.id], ['r', PAGE]] });
await make('mc_v5_up', 'v5', { kind: 7, content: '+', tags: [['e', events.mindChanged.id], ['r', PAGE]] });

// Profiles: the newest kind 0 wins, and name is read before display_name.
await make('aliceOld', 'alice', { kind: 0, content: JSON.stringify({ name: 'alice-old' }) });
await make('aliceNew', 'alice', { kind: 0, content: JSON.stringify({ name: 'Alice', display_name: 'Alice D.' }) });
await make('bobProfile', 'bob', { kind: 0, content: JSON.stringify({ display_name: 'Bob <b>bold</b>' }) });

// A sixth voter makes one forged down-vote count only if signatures are ignored.
await comment('forgedTarget', 'carol', 'One real down-vote and four forged ones.');
await make('ft_v6', 'v6', { kind: 7, content: '-', tags: [['e', events.forgedTarget.id], ['r', PAGE]] });

fs.writeFileSync(path.join(HERE, 'fixtures.json'), JSON.stringify({ PAGE, OTHER, pubkeys: Object.fromEntries(Object.keys(K).map(n => [n, pub(n)])), events }, null, 1) + '\n');
console.log(`wrote ${Object.keys(events).length} events to tests/fixtures.json`);
