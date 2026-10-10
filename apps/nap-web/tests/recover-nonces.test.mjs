// Restoring a wallet (audit, 10 Oct 2026): the nonce walk asks a few
// lookups at a time, not thirty at once, and a lookup that fails is never
// read as "nothing here" — the count is kept only when every page answered.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

let store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

const ledger = await import('../src/ledger.js');
const { deriveIdentity, hex } = await import('../src/core.js');
const mk = await import('../src/market.js');

const CONFIG = JSON.parse(readFileSync(new URL('../public/config.json', import.meta.url), 'utf8'));
const testnet = CONFIG.networks.find((n) => n.id === 'testnet');
const config = { ...testnet, rpcUrl: 'http://chain.test/' };
const identity = deriveIdentity(`${'abandon '.repeat(23)}art`);
const countKey = `nap.market.n.${config.chain}.${identity.accountHex}`;

// A sale ticket bought under nonce 70: on the second page of the walk.
const ticket = hex(mk.ticketId(identity.account, mk.marketNonce(identity.secretKey, 70), 0));
let inFlight = 0, most = 0, failNext = 0;
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  inFlight++;
  most = Math.max(most, inFlight);
  await new Promise((r) => setTimeout(r, 2));
  inFlight--;
  const answer = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), { status: 200 });
  if (body.method === 'zyn_market') return answer({ curves: [] });
  if (body.method === 'zyn_bridged') return answer([]);
  if (failNext > 0 && body.method === 'zyn_tickets') {
    failNext--;
    return new Response('broken', { status: 500 });
  }
  if (body.method === 'zyn_tickets') return answer(String(body.ids).split(',').filter((t) => t === ticket).map((t) => ({ ticket: t })));
  return answer([]);
};

test('the walk finds a nonce past the first page, a few lookups at a time', async () => {
  store = new Map(); most = 0;
  const count = await ledger.recoverNonces(config, identity);
  assert.equal(count, 71);
  assert.equal(store.get(countKey), '71', 'kept: every page answered');
  assert.ok(most <= 6, `at most six lookups in flight (saw ${most})`);
});

test('a lookup that fails keeps no count, so the next refresh walks again', async () => {
  store = new Map();
  failNext = 1;
  await ledger.recoverNonces(config, identity);
  assert.equal(store.get(countKey), undefined, 'not kept after a failed lookup');
  const again = await ledger.ensureNonces(config, identity);
  assert.equal(again, 71);
  assert.equal(store.get(countKey), '71');
});
