// A connected site reads private-channel notes and lending positions only
// with the holder's leave, given once per site, network and wallet on a card
// naming what goes — and taken back with the connection (audit, 9 Oct 2026).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };

const { allowed, connectedTo, SCOPES, scopesOf, withConnection, withScope, without } = await import('../src/connect-grants.js');
const { METHODS, siteNotes } = await import('../src/connect-ops.js');

const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
const SITE = 'https://lend.zyn-network.com';
const ME = 'aa'.repeat(32);
const OTHER = 'bb'.repeat(32);

test('notes and positions wait for the holder\'s leave', () => {
  assert.equal(METHODS.zyn_poolNotes.scope, 'notes');
  assert.equal(METHODS.zyn_lendPositions.scope, 'positions');
  for (const [name, m] of Object.entries(METHODS)) {
    if (m.scope) assert.ok(SCOPES[m.scope], `${name} names a scope with a card`);
    if (m.scope) assert.equal(m.kind, 'read', `${name}: a scope gates a read`);
  }
  // Every card says what goes and what the site can learn from it.
  for (const s of Object.values(SCOPES)) assert.ok(s.what && s.shows && s.risk);
});

test('a connection allows no scope until the holder does, and only for that site, network and wallet', () => {
  let list = withConnection({}, SITE, 'testnet', ME, 1);
  assert.ok(connectedTo(list, SITE, 'testnet', ME));
  assert.equal(allowed(list, SITE, 'testnet', ME, 'notes'), false);
  list = withScope(list, SITE, 'testnet', ME, 'notes');
  assert.ok(allowed(list, SITE, 'testnet', ME, 'notes'));
  assert.equal(allowed(list, SITE, 'testnet', ME, 'positions'), false, 'one scope is not the other');
  assert.equal(allowed(list, 'https://evil.example', 'testnet', ME, 'notes'), false, 'another site');
  assert.equal(allowed(list, SITE, 'mainnet', ME, 'notes'), false, 'another network');
  assert.equal(allowed(list, SITE, 'testnet', OTHER, 'notes'), false, 'another wallet');
  assert.equal(allowed(list, SITE, 'testnet', null, 'notes'), false, 'no wallet open');
  assert.deepEqual(scopesOf(list, SITE, 'testnet', ME), ['notes']);
  // Allowing twice keeps one entry; an unknown scope is not kept.
  list = withScope(withScope(list, SITE, 'testnet', ME, 'notes'), SITE, 'testnet', ME, 'everything');
  assert.deepEqual(list[SITE].scopes, ['notes']);
});

test('disconnecting, or connecting again elsewhere, takes the leave back', () => {
  let list = withScope(withConnection({}, SITE, 'testnet', ME), SITE, 'testnet', ME, 'positions');
  assert.equal(allowed(without(list, SITE), SITE, 'testnet', ME, 'positions'), false);
  list = withConnection(list, SITE, 'mainnet', ME);
  assert.equal(allowed(list, SITE, 'mainnet', ME, 'positions'), false, 'a new connection starts with nothing');
  // A scope is not added to another network's or wallet's connection.
  assert.equal(withScope(list, SITE, 'testnet', ME, 'notes'), list);
  assert.equal(withScope(withConnection({}, SITE, 'testnet', OTHER), SITE, 'testnet', ME, 'notes')[SITE].scopes.length, 0);
});

test('a connection kept before accounts were (the phone app\'s) takes the account with the leave', () => {
  const list = withScope({ [SITE]: { network: 'testnet', at: 1 } }, SITE, 'testnet', ME, 'notes');
  assert.ok(allowed(list, SITE, 'testnet', ME, 'notes'));
  assert.equal(allowed({ [SITE]: { network: 'testnet', at: 1, scopes: ['notes'] } }, SITE, 'testnet', ME, 'notes'), false, 'no account, no leave');
});

test('a site gets no relayer signature and no spent note\'s commitment', () => {
  const c = (i) => String(i).repeat(64);
  const notes = [
    { i: 0, ch: 'sol', size: 100000000n, kind: 'in', commitment: c(1), state: 'in pool', at: 1, signature: 'sig0' },
    { i: 1, ch: 'eth', size: '10000000000000000', kind: 'in', commitment: c(2), state: 'to zyn', at: 2, signature: 'sig1' },
    { i: 2, ch: 'sol', size: '100000000', kind: 'out', commitment: c(3), state: 'sent', at: 3, signature: 'sig2' },
    { i: 3, ch: 'sol', size: '100000000', kind: 'note', commitment: c(4), state: 'spent', at: null },
    { i: 4, ch: 'mzbtc', size: '1000000000000000', kind: 'in', commitment: c(5), state: 'new', at: 5 },
    { i: 5, ch: 'sol', size: '1000000000', kind: 'out', commitment: c(6), state: 'burned', at: 6 },
  ];
  const out = siteNotes(notes);
  assert.ok(out.every((n) => !('signature' in n)), 'no relayer signature');
  assert.deepEqual(out.map((n) => n.commitment), [c(1), undefined, undefined, undefined, c(5), c(6)]);
  // What Zyn Lend's bridge and portfolio read stays: channel, size, kind, state.
  assert.deepEqual(out[0], { ch: 'sol', size: '100000000', kind: 'in', state: 'in pool', commitment: c(1) });
  assert.deepEqual(out.map((n) => n.state), notes.map((n) => n.state));
  assert.match(String(METHODS.zyn_poolNotes.run), /siteNotes\(/);
});

test('the connect window asks for a scope before the read runs, and its cards say so', () => {
  const app = src('connect-app.js');
  const handle = app.slice(app.indexOf('async function handle('), app.indexOf('// Unlocking.'));
  const gate = handle.indexOf('m.scope && !isAllowed(site, config.id, m.scope)');
  assert.ok(gate > 0, 'the scope is checked');
  assert.ok(gate < handle.indexOf("if (m.kind === 'read')"), 'before any read runs');
  assert.match(handle, /show\(scopeCard\(m\.scope\)\)[\s\S]*?decide\(\)[\s\S]*?allow\(site, config\.id, m\.scope\)/);
  assert.match(app, /Only if you allow it/);
  assert.match(app, /Disconnecting the site takes it back/);
  // Disconnecting drops the record, scopes and all.
  assert.match(app, /function forget\(origin\) \{ write\(CONNECTED_KEY, JSON\.stringify\(without\(/);
});

test('the phone app\'s browser asks for a scope too', () => {
  const b = src('nap-browser.js');
  const gate = b.indexOf('m.scope && !allowed(read(), origin, config.id, identity.accountHex, m.scope)');
  assert.ok(gate > 0 && gate < b.indexOf("if (m.kind === 'read' || m.kind === 'auto') return m.run"));
  assert.match(b, /function forget\(origin\) \{ keep\(without\(/);
});
