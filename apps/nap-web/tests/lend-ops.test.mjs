// Zyn Lend's approvals in connect-ops.js, against a stand-in chain: what Nap
// refuses before asking, what it shows when it asks, and that a site is only
// ever handed this account's positions.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

const { METHODS } = await import('../src/connect-ops.js');
const { deriveIdentity } = await import('../src/core.js');

const W = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 12n).toString();
const ZEC = '0e212262cb35bf6e88bc7d0a52b60a5cc70c2859b65966a2557229d2ea469201';
const ETH = '56737e143259c754d165074ad15058139bc0b116f5a22b2f3d50129a2a7a24a6';
const SOL = '9204324e0511b4d1a90d0ff36242f044e894e1b71489d47abd824df273092ad1';
const config = { id: 'testnet', chain: 212, rpcUrl: 'http://chain.test/', zecAsset: ZEC, collections: [], bridges: {} };
const identity = deriveIdentity('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art');
const ctx = { config, identity };
store.set(`nap.market.n.${config.chain}.${identity.accountHex}`, '1');

const pool = (asset, o = {}) => ({
  asset, receipt: asset.replace(/^../, 'aa'), cash: W(10), borrowed: W(0), supplied: W(10), share_price: W(1), borrow_rate: '0', supply_rate: '0', utilization: '0',
  max_ltv_bps: 7200, liquidation_bps: 7700, penalty_bps: 500, min_borrow_usd: W(1), ...o,
});
let markets;
let position;
const reset = () => {
  markets = {
    epoch: 5, time: 1000, rules: 2, prices_fresh: true,
    prices: { [ETH]: W(2000), [SOL]: W(100), [ZEC]: W(50) },
    auction: { start_bps: 10200, step_bps: 100, step_secs: 60, floor_bps: 8500, backstop_min_bps: 7000 },
    pools: [pool(ETH), pool(SOL), pool(ZEC)],
    pairs: [{ collateral_asset: ETH, borrow_asset: SOL, pool_reserve: W(1), depth_limit: W(0.25), room: W(0.2), prices_agree: true }],
    lots: [],
  };
  position = { state: 'open', collateral_asset: ETH, collateral: W(1), borrow_asset: SOL, owed: W(10), health: W(1.54) };
};
reset();

globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const answer = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), { status: 200 });
  switch (body.method) {
    case 'zyn_lendMarkets': return answer(markets);
    case 'zyn_market': return answer({ epoch: 5, epoch_seconds: 10, pools: [], curves: [] });
    case 'zyn_bridged': return answer([{ asset: ETH, network: 'eip155:11155111', decimals: 18 }, { asset: SOL, network: 'solana-devnet', decimals: 9 }]);
    case 'zyn_lendPositions': {
      const [first] = String(body.ids).split(',');
      // Ours, and one the node should never have sent: not this account's.
      return answer([{ id: first, ...position }, { id: 'ff'.repeat(32), ...position }]);
    }
    default: return answer([]);
  }
};

const mine = async () => (await METHODS.zyn_lendPositions.run(ctx)).positions;

test('a site is handed this account\'s positions only', async () => {
  const p = await mine();
  assert.equal(p.length, 1);
  assert.notEqual(p[0].id, 'ff'.repeat(32));
});

test('taking collateral out shows health and the liquidation price after it', async () => {
  reset();
  const [p] = await mine();
  const plan = await METHODS.zyn_lendRemoveCollateral.prepare(ctx, { position: p.id, amount: '0.1' });
  const rows = Object.fromEntries(plan.rows);
  assert.equal(rows['Collateral after'], '0.9 ETH.zy');
  // 0.9 ETH at $2000 against 10 SOL at $100: (1800 × 0.77) / 1000.
  assert.match(rows['Health after'], /^1\.38 /);
  assert.match(rows['Liquidated if (after)'], /ETH\.zy falls to \$1,443/);
  // Leaving it over the 72% maximum is refused before anything is signed.
  await assert.rejects(METHODS.zyn_lendRemoveCollateral.prepare(ctx, { position: p.id, amount: '0.4' }), /over the 72%/);
  // With debt, a held price or a disagreeing pool pauses it.
  markets.pools[0].price_held = true;
  await assert.rejects(METHODS.zyn_lendRemoveCollateral.prepare(ctx, { position: p.id, amount: '0.1' }), /held price/);
  reset();
  markets.pairs[0].prices_agree = false;
  await assert.rejects(METHODS.zyn_lendRemoveCollateral.prepare(ctx, { position: p.id, amount: '0.1' }), /disagree/);
});

test('a partial repayment may not leave a debt under the smallest loan', async () => {
  reset();
  const [p] = await mine();
  // Rules v2: the chain says the most a partial payment may be.
  position.repay_max_partial = W(9.99);
  await assert.rejects(METHODS.zyn_lendRepay.prepare(ctx, { position: p.id, amount: '9.995' }), /at most 9\.99 SOL\.zy/);
  position.repay_max_partial = '0';
  await assert.rejects(METHODS.zyn_lendRepay.prepare(ctx, { position: p.id, amount: '1' }), /repay all of it/);
  // Before v2, from the pool's $1 minimum: 9.995 SOL leaves $0.50.
  delete position.repay_max_partial;
  await assert.rejects(METHODS.zyn_lendRepay.prepare(ctx, { position: p.id, amount: '9.995' }), /under the \$1 smallest loan/);
  await assert.rejects(METHODS.zyn_lendRepay.prepare(ctx, { position: p.id, amount: '10' }), /Repay and close/);
});

test('borrowing is checked against what is surely free, the pair\'s room and its prices', async () => {
  reset();
  const open = (o) => METHODS.zyn_lendOpen.prepare(ctx, { collateral: ETH, borrow: SOL, collateralAmount: '0.1', amount: '1', ...o });
  // Published cash 10, rounded to two figures of 10 supplied (a step of 1):
  // only 9.5 is surely there.
  await assert.rejects(open({ amount: '9.7' }), /about 9\.5 surely free/);
  // Rules v2: the pair's depth room (0.2 ETH) and the asset's cap room.
  await assert.rejects(open({ collateralAmount: '0.3' }), /At most 0\.2 more ETH\.zy/);
  markets.pools[0].collateral_room = W(0.05);
  await assert.rejects(open({ collateralAmount: '0.1' }), /At most 0\.05 more ETH\.zy/);
  reset();
  markets.pairs[0].prices_agree = false;
  await assert.rejects(open({}), /paused/);
  reset();
  markets.pools[1].price_fresh = false;
  await assert.rejects(open({}), /stale/);
});

test('pools that wait say so before the holder is asked', async () => {
  reset();
  markets.pools[1].withdraw_paused = true;
  await assert.rejects(METHODS.zyn_lendWithdraw.prepare(ctx, { asset: SOL, shares: '1' }), /wait for a held price/);
  markets.pools[1].supply_paused = true;
  await assert.rejects(METHODS.zyn_lendSupply.prepare(ctx, { asset: SOL, amount: '1' }), /wait while an auction recovers/);
  // Insurance opens only under rules v2.
  reset();
  markets.rules = 1;
  await assert.rejects(METHODS.zyn_lendInsure.prepare(ctx, { asset: SOL, amount: '1' }), /rules v2/);
});

test('a bid under the lot\'s smallest, or not over a full book\'s smallest, is refused', async () => {
  reset();
  const lot = 'ab'.repeat(32);
  markets.lots = [{ lot, collateral_asset: ETH, borrow_asset: SOL, collateral: W(1), price: W(20), owed: W(10), min_bid: W(0.1) }];
  await assert.rejects(METHODS.zyn_lendBid.prepare(ctx, { lot, pay: '0.05' }), /smallest bid on this lot is 0\.1 SOL\.zy/);
  Object.assign(markets.lots[0], { bids_full: true, outbid_above: W(0.5) });
  await assert.rejects(METHODS.zyn_lendBid.prepare(ctx, { lot, pay: '0.5' }), /more than 0\.5 SOL\.zy/);
});
