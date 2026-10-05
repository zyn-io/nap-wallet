// Coins priced in other bridged coins (§166) in connect-ops.js, against a
// stand-in chain: Nap creates a coin only in an asset the ledger launches
// coins in, says what it is priced in and what it raises, and holds buys to
// the curve's own size.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

const { METHODS } = await import('../src/connect-ops.js');
const { deriveIdentity } = await import('../src/core.js');
const mk = await import('../src/market.js');

const ZEC = '0e212262cb35bf6e88bc7d0a52b60a5cc70c2859b65966a2557229d2ea469201';
const ETH = '56737e143259c754d165074ad15058139bc0b116f5a22b2f3d50129a2a7a24a6';
const config = { id: 'testnet', chain: 212, rpcUrl: 'http://chain.test/', zecAsset: ZEC, collections: [], bridges: {} };
const identity = deriveIdentity('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art');
const ctx = { config, identity };
store.set(`nap.market.n.${config.chain}.${identity.accountHex}`, '1');

const ETH_UNIT = mk.curveUnitFor(23n * mk.WAD);
const quote = (asset, unit) => ({ asset, unit: String(unit), bond: '0', graduation_mc: String(unit * mk.GRADUATION_MC_UNITS) });
const meta = Buffer.from(mk.encodeMeta({ symbol: 'ETHC', name: 'An ETH coin' })).toString('hex');
const ethCurve = {
  token: 'ab'.repeat(32), quote: ETH, meta, created_at: 1, fee_bps: 100, sold: 1000, reserve: '0', graduation: '0', creator_fees: '0', bond: '0',
  price_per_token: String(mk.curvePricePerToken(0, ETH_UNIT)), graduated: false, pool: '', pending: 0, unit: String(ETH_UNIT),
};
let market;
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const answer = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), { status: 200 });
  switch (body.method) {
    case 'zyn_market': return answer(market);
    case 'zyn_bridged': return answer([{ asset: ETH, network: 'eip155:11155111', decimals: 18 }]);
    default: return answer([]);
  }
};
const zecCurve = { ...ethCurve, token: 'cd'.repeat(32), quote: ZEC, unit: String(mk.ZAT), price_per_token: String(mk.curvePricePerToken(0)), sold: 100 };
const EZ = mk.compareBytes(Buffer.from(ETH, 'hex'), Buffer.from(ZEC, 'hex')) < 0;
const ethZec = { id: 'ee'.repeat(32), a: EZ ? ETH : ZEC, b: EZ ? ZEC : ETH, lp: 'ff'.repeat(32), reserve_a: String(20n * mk.WAD), reserve_b: String(40n * mk.WAD), fee_bps: 30 };
const named = (quotes) => { market = { epoch: 5, epoch_seconds: 15, pools: [ethZec], curves: [ethCurve, zecCurve], curve_terms: { set: true, fee_bps: 100, bond: '0' }, curve_quotes: quotes }; };

test('a coin in ETH says it is priced in ETH and raises ~8.3 ETH', async () => {
  named([quote(ZEC, mk.ZAT), quote(ETH, ETH_UNIT)]);
  const plan = await METHODS.zyn_curveCreate.prepare(ctx, { symbol: 'ethc', name: 'An ETH coin', quote: ETH });
  const rows = Object.fromEntries(plan.rows);
  assert.match(rows['Priced in'], /^ETH/);
  assert.match(rows.Graduates, /about 8\.31 ETH/);
});

test('a coin is refused in an asset the ledger does not launch coins in', async () => {
  named([quote(ZEC, mk.ZAT)]);
  await assert.rejects(METHODS.zyn_curveCreate.prepare(ctx, { symbol: 'x', name: 'x', quote: ETH }), /not launched in that asset/);
  // None named (a node before §166): ZEC.zy only, at ZEC's size.
  named([]);
  const plan = await METHODS.zyn_curveCreate.prepare(ctx, { symbol: 'z', name: 'z' });
  assert.match(Object.fromEntries(plan.rows).Graduates, /about 17 ZEC\.zy raised/);
  await assert.rejects(METHODS.zyn_curveCreate.prepare(ctx, { symbol: 'x', name: 'x', quote: ETH }), /not launched in that asset/);
});

test('a buy is held to the curve\'s own smallest buy', async () => {
  named([quote(ZEC, mk.ZAT), quote(ETH, ETH_UNIT)]);
  // 0.0001 ETH is below an ETH-sized curve's smallest buy (~0.00049 ETH).
  await assert.rejects(METHODS.zyn_curveBuy.prepare(ctx, { token: ethCurve.token, amount: '0.0001' }), /A buy is at least 0\.000488/);
});

test('a route from an ETH coin to a ZEC coin is checked hop by hop before Nap asks', async () => {
  named([quote(ZEC, mk.ZAT), quote(ETH, ETH_UNIT)]);
  const e2z = ethZec.a === ETH;
  const good = [{ curveSell: ethCurve.token }, { pool: ethZec.id, sellA: e2z }, { curveBuy: zecCurve.token }];
  // A valid route gets as far as the balance check: this wallet holds nothing.
  await assert.rejects(METHODS.zyn_route.prepare(ctx, { hops: good, amount: '125000', minOut: '1' }), /does not hold enough/);
  const cases = [
    [[], /one to four/],
    [[{ pool: ethZec.id, sellA: e2z }, { curveSell: ethCurve.token }], /can only start/],
    [[{ curveBuy: zecCurve.token }, { pool: ethZec.id, sellA: !e2z }], /can only end/],
    [[{ curveSell: ethCurve.token }, { pool: ethZec.id, sellA: !e2z }], /take what the hop before/],
    [[{ pool: ethZec.id, sellA: e2z }, { pool: ethZec.id, sellA: !e2z }], /each venue once/],
    [[{ pool: 'aa'.repeat(32), sellA: true }], /gone or empty/],
  ];
  for (const [hops, why] of cases) await assert.rejects(METHODS.zyn_route.prepare(ctx, { hops, amount: '1', minOut: '0' }), why);
  await assert.rejects(METHODS.zyn_route.prepare(ctx, { hops: good, amount: '100', minOut: '1' }), /whole lots/);
});
