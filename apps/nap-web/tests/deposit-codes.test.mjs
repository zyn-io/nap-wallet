// Deposit codes (audit, 9 Oct 2026): a fresh code per request, never one
// code for two kinds of deposit, a bounded number waiting unused — and every
// code one this wallet, or a restore of its phrase, still finds and claims.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

let store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

const ledger = await import('../src/ledger.js');
const { bridgesOf } = await import('../src/bridges.js');
const { METHODS } = await import('../src/connect-ops.js');
const { deriveIdentity, hex, unhex } = await import('../src/core.js');
const mk = await import('../src/market.js');

const CONFIG = JSON.parse(readFileSync(new URL('../public/config.json', import.meta.url), 'utf8'));
const testnet = CONFIG.networks.find((n) => n.id === 'testnet');
const config = { ...testnet, rpcUrl: 'http://chain.test/' };
const identity = deriveIdentity(`${'abandon '.repeat(23)}art`);
const ctx = { config, identity };
const SOL = bridgesOf(config).find((b) => b.key === 'sol').asset;
const ETH = bridgesOf(config).find((b) => b.key === 'eth').asset;
const countKey = `nap.market.n.${config.chain}.${identity.accountHex}`;

/// The chain: deposits waiting under their keys, and nothing else held.
let waiting = new Map(); // deposit key -> { asset, amount }
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const answer = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), { status: 200 });
  switch (body.method) {
    case 'zyn_bridged': return answer([{ asset: SOL, network: 'solana-devnet', decimals: 9 }, { asset: ETH, network: 'eip155:11155111', decimals: 18 }]);
    case 'zyn_market': return answer({ curves: [] });
    case 'zyn_waiting': return answer(String(body.ids).split(',').filter((k) => waiting.has(k)).map((k) => ({ key: k, ...waiting.get(k) })));
    case 'zyn_depositWatch': return answer(true);
    default: return answer([]);
  }
};
/// Someone deposits `asset` with the code `commitment` on the other chain.
const deposit = (commitment, asset = SOL) => waiting.set(hex(mk.depositKey(unhex(commitment, 32), unhex(asset, 32))), { asset, amount: '1000000000000000000' });
const fresh = () => { store = new Map(); waiting = new Map(); store.set(countKey, '3'); };
const code = async (kind) => (await ledger.bridgeMemo(config, identity, { kind })).commitment;

test('every request gets its own code, and each lands where this wallet looks', async () => {
  fresh();
  const a = await code('sol');
  const b = await code('sol');
  assert.notEqual(a, b, 'two requests before a credit no longer share a code');
  assert.equal(ledger.nonceCount(config, identity), 5, 'each took a nonce, below the count');
  deposit(a);
  deposit(b);
  const found = await ledger.loadWaiting(config, identity);
  assert.deepEqual(found.map((w) => hex(mk.depositCommitment(identity.account, w.secret))).sort(), [a, b].sort());
});

test('a code is never handed to two kinds of deposit', async () => {
  fresh();
  const seen = new Map();
  for (let i = 0; i < 2 * ledger.DEPOSIT_OUTSTANDING + 2; i++) {
    for (const kind of ['sol', 'eth', 'bold', 'btc']) {
      const c = await code(kind);
      assert.ok(!seen.has(c) || seen.get(c) === kind, `${kind} got ${seen.get(c)}'s code`);
      seen.set(c, kind);
    }
  }
});

test('past the bound, the code waiting longest of that kind comes back — not a new nonce', async () => {
  fresh();
  const first = [];
  for (let i = 0; i < ledger.DEPOSIT_OUTSTANDING; i++) first.push(await code('sol'));
  assert.equal(new Set(first).size, ledger.DEPOSIT_OUTSTANDING);
  const count = ledger.nonceCount(config, identity);
  // Round the line: oldest first, each once, and no nonce spent.
  for (let i = 0; i < ledger.DEPOSIT_OUTSTANDING; i++) assert.equal(await code('sol'), first[i]);
  assert.equal(await code('sol'), first[0]);
  assert.equal(ledger.nonceCount(config, identity), count, 'no unbounded run of unused nonces');
  // Another kind still gets fresh codes of its own.
  assert.ok(!first.includes(await code('eth')));
  assert.equal(ledger.nonceCount(config, identity), count + 1);
});

test('a code whose deposit landed leaves the line, so the next one is fresh', async () => {
  fresh();
  const line = [];
  for (let i = 0; i < ledger.DEPOSIT_OUTSTANDING; i++) line.push(await code('sol'));
  deposit(line[0]);
  const next = await code('sol');
  assert.ok(!line.includes(next), 'not a code already used on the other chain');
  // Claimed here (claimWaiting marks it), its waiting row gone: out of the
  // line too. The codes took nonces 3, 4, 5, 6; line[1] is nonce 4.
  waiting = new Map();
  store.set(`nap.bridge.used.${config.chain}.${identity.accountHex}`, JSON.stringify([4]));
  const count = ledger.nonceCount(config, identity);
  const after = await code('sol');
  assert.ok(![...line, next].includes(after));
  assert.equal(ledger.nonceCount(config, identity), count + 1);
});

test('a private note into Zyn always gets a fresh code, whatever is waiting', async () => {
  fresh();
  for (let i = 0; i < ledger.DEPOSIT_OUTSTANDING; i++) await code('sol');
  const before = ledger.nonceCount(config, identity);
  const seen = new Set();
  for (let i = 0; i < ledger.DEPOSIT_OUTSTANDING + 2; i++) seen.add(await code('to-zyn'));
  assert.equal(seen.size, ledger.DEPOSIT_OUTSTANDING + 2);
  assert.equal(ledger.nonceCount(config, identity), before + ledger.DEPOSIT_OUTSTANDING + 2);
  // And it is never in the line a transparent deposit draws from.
  for (let i = 0; i < 2 * ledger.DEPOSIT_OUTSTANDING; i++) assert.ok(!seen.has(await code('sol')));
});

test('the one code kept before is not handed out again', async () => {
  fresh();
  const legacy = `nap.bridge.${config.chain}.${identity.accountHex}`;
  store.set(legacy, '1');
  const old = hex(mk.depositCommitment(identity.account, mk.marketNonce(identity.secretKey, 1)));
  assert.notEqual(await code('sol'), old);
  assert.equal(store.has(legacy), false);
  // A deposit already made with it is still found: its nonce is below the count.
  deposit(old);
  assert.equal((await ledger.loadWaiting(config, identity)).length, 1);
});

test('a restore from the phrase finds deposits made with every code issued', async () => {
  fresh();
  const codes = [];
  for (const kind of ['sol', 'eth', 'bold', 'btc']) for (let i = 0; i < ledger.DEPOSIT_OUTSTANDING; i++) codes.push(await code(kind));
  deposit(codes.at(-1), ETH);
  const chain = waiting;
  // A new device: nothing kept, the same phrase.
  store = new Map();
  waiting = chain;
  const found = await ledger.loadWaiting(config, identity);
  assert.equal(found.length, 1);
  assert.equal(hex(mk.depositCommitment(identity.account, found[0].secret)), codes.at(-1));
});

test('every bridge\'s waiting codes together stay inside what another device looks ahead', () => {
  for (const net of CONFIG.networks) {
    assert.ok(bridgesOf(net).length * ledger.DEPOSIT_OUTSTANDING <= ledger.LOOKAHEAD, `${net.id}: ${bridgesOf(net).length} bridges`);
  }
});

test('zyn_bridgeDeposit: a fresh SOL memo, ETH call and BTC address each time', async () => {
  fresh();
  const s1 = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'sol' });
  const s2 = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'sol' });
  assert.match(s1.memo, /^zyn:[0-9a-f]{64}$/);
  assert.notEqual(s1.memo, s2.memo);
  const e1 = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'eth' });
  const e2 = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'eth' });
  assert.notEqual(e1.data, e2.data);
  for (const s of [s1, s2]) assert.ok(!e1.data.includes(s.memo.slice(4)) && !e2.data.includes(s.memo.slice(4)), 'the ETH call carries no SOL code');
  const b1 = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'btc' });
  const b2 = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'btc' });
  assert.match(b1.address, /^tb1p/);
  assert.notEqual(b1.address, b2.address);
});
