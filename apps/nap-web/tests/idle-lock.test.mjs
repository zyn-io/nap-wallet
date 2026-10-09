// The extension's idle lock is the holder's (audit, 9 Oct 2026): a site
// asking Nap — however often — never pushes it out, and a public question
// never reads the session or brings Nap's window up. Only the holder's own
// actions do: opening the popup or the wallet, unlocking, a click on a card.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';

// session.js reads its build mode through origin.js (import.meta.env, set by
// Vite); here it is the plain web build.
registerHooks({
  load(url, context, nextLoad) {
    const r = nextLoad(url, context);
    if (!url.endsWith('/src/origin.js')) return r;
    return { ...r, format: 'module', source: String(r.source).replace(/import\.meta\.env/g, '({})') };
  },
});
globalThis.location = { origin: 'https://nap.zyn-network.com', search: '' };
const held = new Map();
globalThis.chrome = {
  storage: {
    session: {
      get: async (k) => (held.has(k) ? { [k]: structuredClone(held.get(k)) } : {}),
      set: async (o) => { for (const [k, v] of Object.entries(o)) held.set(k, structuredClone(v)); },
      remove: async (k) => { held.delete(k); },
    },
  },
};

const { IDLE_MS, loadSession, peekSession, saveSession, touchSession } = await import('../src/session.js');
const { deriveIdentity } = await import('../src/core.js');
const { METHODS } = await import('../src/connect-ops.js');

const src = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const identity = deriveIdentity(`${'abandon '.repeat(23)}art`);
const until = () => held.get('nap.session')?.until;
const backdate = (ms) => held.set('nap.session', { ...held.get('nap.session'), until: Date.now() + ms });

test('a site\'s look at the session does not push the idle lock out', async () => {
  await saveSession(identity);
  backdate(60_000);
  const before = until();
  for (let i = 0; i < 5; i++) assert.equal((await peekSession()).identity.accountHex, identity.accountHex);
  assert.equal(until(), before, 'polling keeps nothing unlocked');
});

test('the holder\'s own actions do push it out', async () => {
  await saveSession(identity);
  backdate(60_000);
  await touchSession();
  assert.ok(until() > Date.now() + IDLE_MS - 5_000, 'a click on a card');
  backdate(60_000);
  await loadSession();
  assert.ok(until() > Date.now() + IDLE_MS - 5_000, 'opening the popup or the wallet');
});

test('a lapsed session stays lapsed: a look ends it, a touch does not revive it', async () => {
  await saveSession(identity);
  backdate(-1);
  await touchSession();
  assert.ok(until() < Date.now(), 'not revived');
  assert.equal(await peekSession(), null);
  assert.equal(held.has('nap.session'), false);
});

test('the connect window answers public questions without the session, and looks rather than extends', () => {
  const app = src('../src/connect-app.js');
  assert.doesNotMatch(app, /loadSession/, 'nothing a site asks extends the session');
  const handle = app.slice(app.indexOf('async function handle('), app.indexOf('// Unlocking.'));
  const pub = handle.indexOf("if (m.kind === 'public') return m.run({ config, identity: null");
  assert.ok(pub > 0, 'public questions get no wallet');
  assert.ok(pub < handle.indexOf('peekSession()'), 'and are answered before the session is read');
  // The holder's clicks are what keep it open.
  assert.match(app, /yes\.onclick = \(\) => \{ void touchSession\(\);/);
  assert.match(app, /no\.onclick = \(\) => \{ void touchSession\(\);/);
});

test('the extension never opens Nap\'s window for a public question', () => {
  const content = src('../../extension/src/content.js');
  const listed = [...content.match(/const PUBLIC = new Set\(\[([^\]]*)\]\)/)[1].matchAll(/'([a-zA-Z_]+)'/g)].map((m) => m[1]).sort();
  const pub = Object.entries(METHODS).filter(([, m]) => m.kind === 'public').map(([n]) => n).sort();
  assert.deepEqual(listed, pub, 'content.js lists exactly the public methods');
  assert.match(content, /const quiet = method === 'nap_session' \|\| method === 'nap_disconnect' \|\| PUBLIC\.has\(method\);/);
  assert.match(content, /const p = await reach\(!quiet\);/);
});
