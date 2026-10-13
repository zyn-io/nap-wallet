// The market, from the browser: pools, batch swaps, liquidity, launches.
//
// Every intent here is encoded exactly as `ObjectVm::encode_intent` reads it,
// and every id exactly as `objectvm::market` derives it. The shared fixture
// (`tests/object-vectors.json`, section `market`) holds both sides to the same
// bytes; a drift is an intent the VM refuses, or runs under the wrong rule.
//
// What the VM owes a trader — swap proceeds, refunds, pool shares, a sale's
// allocation — is a *claim*, and a claim's id is derived from a nonce only the
// trader holds. So the nonce is the receipt: lose it and the claim still
// exists, but nothing points this wallet at it. Nonces are therefore derived
// from the identity key and a counter, not drawn at random, so a restored
// wallet can walk the counter and find everything it is owed again.

import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { x25519 } from '@noble/curves/ed25519.js';
import {
  commitment,
  concatBytes,
  hex,
  i128Bytes,
  leaf,
  nullifierOf,
  sealNote,
  u32be,
  u64be,
  unhex,
} from './object.js';

const te = new TextEncoder();
export const WAD = 10n ** 18n;
export const BPS = 10_000n;
export const MINIMUM_LIQUIDITY = 1000n;

/// Program ids, derived here exactly as `zyn-vm/src/program.rs` names them:
/// `leaf("zyn.program.named.v1" ‖ u32 len ‖ name)`. Derived rather than
/// pasted, and checked against the fixture, so neither can drift alone.
const named = (name) => leaf(te.encode('zyn.program.named.v1'), u32be(name.length), te.encode(name));
export const MARKET_PROGRAM = Object.freeze(Object.fromEntries([
  ['ammSwap', 'amm-swap'],
  ['addLiquidity', 'add-liquidity'],
  ['removeLiquidity', 'remove-liquidity'],
  ['claim', 'claim'],
  ['launchCreate', 'launch-create'],
  ['launchCommit', 'launch-commit'],
  ['curveCreate', 'curve-create'],
  ['curveTrade', 'curve-trade'],
  ['saleTickets', 'sale-tickets'],
  ['saleClaim', 'sale-claim'],
  ['saleMint', 'sale-mint'],
  ['lendSupply', 'lend-supply'],
  ['lendWithdraw', 'lend-withdraw'],
  ['lendOpen', 'lend-open'],
  ['lendRepay', 'lend-repay'],
  ['lendCollateral', 'lend-collateral'],
  ['lendInsure', 'lend-insure'],
  ['lendBid', 'lend-bid'],
  ['route', 'route'],
  ['dao', 'dao'],
].map(([k, name]) => [k, hex(named(name))])));

const TAG = { createPool: 10, addLiquidity: 11, removeLiquidity: 12, swap: 13, claim: 14, createLaunch: 15, commit: 16, createCurve: 23, curveTrade: 24, buyTickets: 27, claimItems: 30, mintOpen: 32, claimVoucherItems: 35, claimDeposit: 38, fundSaleCredit: 65, redeemCredit: 67, lendSupply: 41, lendWithdraw: 42, lendOpen: 43, lendRepay: 44, lendAddCollateral: 45, lendRemoveCollateral: 46, lendBid: 47, lendInsure: 51, route: 53, memberPass: 57, propose: 58, vote: 59, proposeZyn: 63 };

const id = (domain, ...parts) => leaf(te.encode(domain), ...parts);

/// Byte order, as Rust compares `[u8; 32]`.
export function compareBytes(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export const poolId = (a, b) => (compareBytes(a, b) <= 0 ? id('objectvm.pool.v1', a, b) : id('objectvm.pool.v1', b, a));
export const lpAsset = (pool) => id('objectvm.lp.v1', pool);
export const tokenOf = (creator, nonce) => id('objectvm.token.v1', creator, nonce);
export const launchSource = (creator, nonce) => id('objectvm.launch.v1', creator, nonce);
export const orderId = (trader, nonce) => id('objectvm.order.v1', trader, nonce);
/// A route's id (§167): where what it delivers, or its refund, waits.
export const routeId = (trader, nonce) => id('objectvm.route.v1', trader, nonce);
/// An account's place on a gated sale's list (§168), blinded: `sale::allow_key`.
export const saleAllowKey = (collection, account) => id('objectvm.sale-allow.v1', collection, account);

// A collection's DAO (objectvm::dao, DECISIONS §172): a member pass, a
// proposal, a vote — each proved by one of the holder's live items.
export const DAO_BACK = 0;
export const DAO_YES = 1;
export const DAO_NO = 2;
/// The pass hash a token makes: what the members' chat is shown.
export const daoPass = (token) => id('objectvm.dao-pass.v1', token);
/// A member pass's token, derived rather than drawn: the same wallet and item
/// give the same token on every device, so the same pass (and chat name)
/// comes back without a new registration. A new holder of the item, whose
/// note is new, gets a new one.
export const passToken = (secretKey, collection, itemCommitment) => id('nap.dao-pass-token.v1', secretKey, collection, itemCommitment);
/// Where a passed proposal's payment waits as a claim.
export const daoPaymentSource = (collection, proposal) => id('objectvm.dao-pay.v1', collection, u32be(proposal));
export const memberPassIntent = (o) => concatBytes(new Uint8Array([TAG.memberPass]), o.holder, prog('dao'), o.collection, o.item, o.pass);
export const proposeIntent = (o) => concatBytes(
  new Uint8Array([TAG.propose]), o.proposer, prog('dao'), o.collection, o.item, o.text,
  o.pay ? concatBytes(new Uint8Array([1]), o.pay.asset, i128Bytes(o.pay.amount), o.pay.to) : new Uint8Array([0]),
);
/// A proposal on the Zyn track (§176): members vote on Zyn's issues; it pays nothing.
export const proposeZynIntent = (o) => concatBytes(new Uint8Array([TAG.proposeZyn]), o.proposer, prog('dao'), o.collection, o.item, o.text);
export const voteIntent = (o) => concatBytes(
  new Uint8Array([TAG.vote]), o.voter, prog('dao'), o.collection, u32be(o.proposal), new Uint8Array([o.choice]),
  u32be(o.items.length), ...o.items,
);
/// What a listed account's `n`th ticket (from 1) costs: the ticket price up to
/// `base`, then one more ticket price per ticket — `sale::gated_price`.
export const gatedPrice = (price, base, n) => BigInt(price) * BigInt(n <= base ? 1 : n - base + 1);
/// Tickets `bought+1 ..= bought+count` together — `sale::gated_total`.
export function gatedTotal(price, base, bought, count) {
  let t = 0n;
  for (let n = bought + 1; n <= bought + count; n++) t += gatedPrice(price, base, n);
  return t;
}
export const routeLegId = (route, hop) => id('objectvm.route-leg.v1', route, new Uint8Array([hop]));
export const commitId = (buyer, nonce) => id('objectvm.commit.v1', buyer, nonce);
export const liquidityId = (provider, nonce) => id('objectvm.liquidity.v1', provider, nonce);
export const claimId = (source, k) => id('objectvm.claim.v1', source, new Uint8Array([k]));

function inputs(list) {
  const parts = [u32be(list.length)];
  for (const i of list) parts.push(i.commitment, i.nullifier);
  return concatBytes(...parts);
}

function outputs(list) {
  const parts = [u32be(list.length)];
  for (const o of list) {
    parts.push(o.note.asset, i128Bytes(o.note.amount), o.note.owner, o.note.nonce, o.enc.epk, u32be(o.enc.ciphertext.length), o.enc.ciphertext);
  }
  return concatBytes(...parts);
}

const u32bytes = (n) => u32be(Number(n));
const bool = (b) => new Uint8Array([b ? 1 : 0]);
const prog = (k) => unhex(MARKET_PROGRAM[k]);

export const createPoolIntent = (o) => concatBytes(
  new Uint8Array([TAG.createPool]), o.provider, prog('addLiquidity'), o.assetA, o.assetB,
  i128Bytes(o.amountA), i128Bytes(o.amountB), u32bytes(o.feeBps), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const addLiquidityIntent = (o) => concatBytes(
  new Uint8Array([TAG.addLiquidity]), o.provider, prog('addLiquidity'), o.pool,
  i128Bytes(o.amountA), i128Bytes(o.amountB), i128Bytes(o.minShares), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const removeLiquidityIntent = (o) => concatBytes(
  new Uint8Array([TAG.removeLiquidity]), o.provider, prog('removeLiquidity'), o.pool,
  i128Bytes(o.shares), i128Bytes(o.minA), i128Bytes(o.minB), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const swapIntent = (o) => concatBytes(
  new Uint8Array([TAG.swap]), o.trader, prog('ammSwap'), o.pool, bool(o.sellA),
  i128Bytes(o.amountIn), i128Bytes(o.minOut), o.nonce, inputs(o.inputs), outputs(o.change),
);

/// One order through up to four venues, all or nothing (§167). A hop is
/// `{ pool, sellA }`, `{ curveSell: token }` (first only) or
/// `{ curveBuy: token }` (last only).
export function routeIntent(o) {
  const hops = o.hops.map((h) => (h.pool ? concatBytes(new Uint8Array([0]), h.pool, bool(h.sellA))
    : h.curveSell ? concatBytes(new Uint8Array([1]), h.curveSell) : concatBytes(new Uint8Array([2]), h.curveBuy)));
  return concatBytes(
    new Uint8Array([TAG.route]), o.trader, prog('route'), new Uint8Array([o.hops.length]), ...hops,
    i128Bytes(o.amountIn), i128Bytes(o.minOut), o.nonce, inputs(o.inputs), outputs(o.change),
  );
}

export function claimIntent(o) {
  const ids = [u32be(o.claims.length), ...o.claims];
  return concatBytes(new Uint8Array([TAG.claim]), o.owner, prog('claim'), ...ids, outputs(o.outputs));
}

export const createLaunchIntent = (o) => concatBytes(
  new Uint8Array([TAG.createLaunch]), o.creator, prog('launchCreate'), o.nonce, o.quote,
  i128Bytes(o.totalSupply), i128Bytes(o.saleSupply), i128Bytes(o.poolSupply),
  i128Bytes(o.softCap), i128Bytes(o.hardCap), u32bytes(o.poolBps), u32bytes(o.feeBps),
  u64be(o.closesAtEpoch), o.meta,
);

export const commitIntent = (o) => concatBytes(
  new Uint8Array([TAG.commit]), o.buyer, prog('launchCommit'), o.launch,
  i128Bytes(o.amount), o.nonce, inputs(o.inputs), outputs(o.change),
);

// ---------------------------------------------------------------------------
// Bonding curves (objectvm::curve, DECISIONS §141). Every token has the same
// curve: 80,000 lots of 12,500 tokens, lot i costs 7,721 + i zatoshi, and it
// graduates at lot 51,098 into a pool whose shares nobody holds.
// ---------------------------------------------------------------------------

export const CURVE = Object.freeze({
  lots: 80_000,
  lotTokens: 12_500n,
  baseZat: 7_721n,
  slopeZat: 1n,
  graduateAt: 51_098,
  poolFeeBps: 30,
});
/// One zatoshi, in the ledger's units: a ZEC-sized curve's unit. A curve
/// priced in another coin (§166) has its own unit, the ledger amount one
/// "zatoshi" of the same shape stands for (`unit` in `zyn_market`).
export const ZAT = 10_000_000_000n;
/// One lot, in the ledger's units (1e18 per token).
export const LOT = CURVE.lotTokens * WAD;
/// The smallest buy: 0.001 of the quote asset on a ZEC-sized curve.
export const MIN_CURVE_BUY = 100_000n * ZAT;
/// A curve's smallest buy at its size.
export const curveMinBuy = (unit = ZAT) => 100_000n * BigInt(unit);
/// Fully diluted value at graduation, in units (`GRADUATION_MC_UNITS`).
export const GRADUATION_MC_UNITS = (CURVE.baseZat + CURVE.slopeZat * BigInt(CURVE.graduateAt)) * BigInt(CURVE.lots);
/// The unit that makes a curve graduate at `mc` fully diluted (`QuoteTerms::unit_for`).
export const curveUnitFor = (mc) => BigInt(mc) / GRADUATION_MC_UNITS;

export const curveSource = (creator, nonce) => id('objectvm.curve.v1', creator, nonce);
export const curveOrderId = (trader, nonce) => id('objectvm.curve-order.v1', trader, nonce);

/// What lots `[q, q+d)` cost, in the ledger's units, on a curve of size
/// `unit` — `objectvm::curve::cost_at`.
export function curveCost(q, d, unit = ZAT) {
  const Q = BigInt(q), D = BigInt(d);
  return (CURVE.baseZat * D + CURVE.slopeZat * ((D * (2n * Q + D - 1n)) / 2n)) * BigInt(unit);
}

/// The most lots `budget` buys from lot `q`, at most `cap`.
export function lotsFor(q, budget, cap, unit = ZAT) {
  let lo = 0, hi = cap;
  while (lo < hi) {
    const mid = lo + Math.ceil((hi - lo) / 2);
    if (curveCost(q, mid, unit) <= budget) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/// A buy of `amountIn` alone in its batch: lots, what they cost, the fee.
/// Other buyers in the same epoch share the price, so this is what a buy
/// gets at best when nobody else buys — a preview, never a promise.
export function previewCurveBuy(sold, amountIn, feeBps, unit = ZAT) {
  const budget = (BigInt(amountIn) * BPS) / (BPS + BigInt(feeBps));
  const lots = lotsFor(sold, budget, Math.max(0, CURVE.graduateAt - sold), unit);
  const paid = curveCost(sold, lots, unit);
  const fee = (paid * BigInt(feeBps)) / BPS;
  return { lots, tokens: BigInt(lots) * LOT, paid, fee, refund: BigInt(amountIn) - paid - fee };
}

/// Selling `lots` alone: gross from the curve, the fee, what arrives.
export function previewCurveSell(sold, lots, feeBps, unit = ZAT) {
  const n = Math.min(lots, sold);
  const gross = n ? curveCost(sold - n, n, unit) : 0n;
  const fee = (gross * BigInt(feeBps)) / BPS;
  return { lots: n, gross, fee, net: gross - fee };
}

/// Price of the next lot, per token, in the ledger's units.
export const curvePricePerToken = (sold, unit = ZAT) => curveCost(sold, 1, unit) / CURVE.lotTokens;

export const createCurveIntent = (o) => concatBytes(
  new Uint8Array([TAG.createCurve]), o.creator, prog('curveCreate'), o.nonce, o.quote, o.meta,
  inputs(o.inputs || []), outputs(o.change || []),
);

export const curveTradeIntent = (o) => concatBytes(
  new Uint8Array([TAG.curveTrade]), o.trader, prog('curveTrade'), o.token, bool(o.buy),
  i128Bytes(o.amountIn), i128Bytes(o.minOut), o.nonce, inputs(o.inputs), outputs(o.change),
);

// ---------------------------------------------------------------------------
// Pricing, as the VM clears it. Previews only — the batch price is set at the
// seal by everybody's orders together — but computed with the same floors so
// a quote never promises more than the ledger could pay.
// ---------------------------------------------------------------------------

export const netOfFee = (amount, feeBps) => (amount * (BPS - BigInt(feeBps))) / BPS;

/// What `amountIn` would buy if it were the only order in the batch:
/// `net · (y) / (x + 2·net)` for a seller of A. Other orders on the same side
/// lower it and orders on the other side raise it, which is why the trade
/// carries a minimum rather than a promise.
export function quoteAlone(pool, sellA, amountIn) {
  const x = BigInt(pool.reserve_a);
  const y = BigInt(pool.reserve_b);
  const net = netOfFee(amountIn, pool.fee_bps);
  if (net <= 0n) return 0n;
  return sellA ? (net * y) / (x + 2n * net) : (net * x) / (y + 2n * net);
}

/// What a route delivers if it is alone in its venues' batches: each hop's
/// preview fed by the one before. `venues` resolves a hop to its pool or
/// curve as `zyn_market` lists them; `null` if a hop delivers nothing.
export function previewRoute(hops, amountIn, venues) {
  let amount = BigInt(amountIn);
  const steps = [];
  for (const h of hops) {
    if (h.pool) {
      amount = quoteAlone(venues.pool(h.pool), h.sellA, amount);
    } else {
      const c = venues.curve(h.curveSell || h.curveBuy);
      // Only a plain positive integer is a unit; anything else is a ZEC-sized curve.
      const unit = typeof c.unit === 'string' && /^[1-9]\d{0,39}$/.test(c.unit) ? BigInt(c.unit) : ZAT;
      amount = h.curveSell ? previewCurveSell(c.sold, Number(amount / LOT), c.fee_bps, unit).net : previewCurveBuy(c.sold, amount, c.fee_bps, unit).tokens;
    }
    steps.push(amount);
    if (amount <= 0n) return null;
  }
  return { out: amount, steps };
}

/// The minimum to sign for, `slippageBps` below the quote.
export const withSlippage = (quote, slippageBps) => (quote * (BPS - BigInt(slippageBps))) / BPS;

/// Shares `amountA`/`amountB` would earn in an existing pool, and what of each
/// it would actually take (the rest comes back as a claim).
export function liquidityPreview(pool, amountA, amountB) {
  const x = BigInt(pool.reserve_a), y = BigInt(pool.reserve_b), s = BigInt(pool.shares);
  const sa = (amountA * s) / x, sb = (amountB * s) / y;
  const shares = sa < sb ? sa : sb;
  const ceil = (n, d) => (n + d - 1n) / d;
  return { shares, usedA: ceil(shares * x, s), usedB: ceil(shares * y, s) };
}

/// `floor(√(a·b))` in WAD — the shares a new pool opens with. Newton from
/// above (a power of two past the root), so it only ever walks down and takes
/// a handful of steps for any size — starting from a float estimate below the
/// root used to walk up one by one and could freeze the page.
export function geometricMean(a, b) {
  const n = a * b;
  if (n <= 0n) return 0n;
  let x = 1n << BigInt((n.toString(2).length >> 1) + 1);
  for (;;) {
    const y = (x + n / x) >> 1n;
    if (y >= x) break;
    x = y;
  }
  while (x * x > n) x -= 1n;
  return x;
}

// ---------------------------------------------------------------------------
// The wallet's side: funding an intent from held notes, change to self,
// nonces that can be found again.
// ---------------------------------------------------------------------------

const NONCE_DOMAIN = te.encode('nap.market.nonce.v1');

/// The `counter`th market nonce for this identity. Derived rather than random
/// so a wallet restored from its phrase can find its claims again.
export const marketNonce = (secretKey, counter) => sha256(concatBytes(NONCE_DOMAIN, secretKey, u64be(counter)));

const random32 = () => crypto.getRandomValues(new Uint8Array(32));

/// A note to this wallet, sealed so it can find it. Fresh ephemeral key and
/// fresh nonce every time: reusing either links notes.
export function selfNote(identity, asset, amount) {
  const note = { asset, amount, owner: identity.account, nonce: random32() };
  const enc = sealNote(x25519.getPublicKey(identity.viewing), random32(), note);
  return { note, enc };
}

/// Pick held notes of `asset` covering `amount`, largest first, and the
/// change note for the rest. `held` is `scan(...).held`.
export function fund(identity, held, asset, amount, taken = new Set()) {
  const a = hex(asset);
  const mine = held
    .filter((h) => h.asset === a && !taken.has(h.commitment))
    .sort((p, q) => (q.amount > p.amount ? 1 : q.amount < p.amount ? -1 : 0));
  const picked = [];
  let sum = 0n;
  for (const h of mine) {
    if (sum >= amount) break;
    picked.push(h);
    taken.add(h.commitment);
    sum += h.amount;
  }
  if (sum < amount) throw new Error('Not enough to cover that');
  if (picked.length > 16) throw new Error('That needs too many notes at once; merge some first');
  const ins = picked.map((h) => {
    const c = unhex(h.commitment);
    return { commitment: c, nullifier: nullifierOf(identity.nullifier, c) };
  });
  const change = sum > amount ? [selfNote(identity, asset, sum - amount)] : [];
  return { inputs: ins, change };
}

/// Every claim id a source can produce (see the table in `objectvm::market`).
export const claimIds = (source) => [0, 1, 2].map((k) => claimId(source, k));

/// Redemption outputs: one note to self per claim, same asset and amount.
export function redeem(identity, claims) {
  return {
    owner: identity.account,
    claims: claims.map((c) => unhex(c.id)),
    outputs: claims.map((c) => selfNote(identity, unhex(c.asset), BigInt(c.amount))),
  };
}

export { commitment };

// ---------------------------------------------------------------------------
// A launch's name. The VM commits 32 opaque bytes of `meta`; this wallet reads
// them as an 8-byte symbol and a 24-byte name, printable ASCII, zero padded —
// on chain and public, so every wallet shows the same name without a server
// to ask. Anything that does not decode as that is shown as a bare id.
// ---------------------------------------------------------------------------

const PRINTABLE = /^[\x20-\x7e]*$/;

export function encodeMeta({ symbol, name }) {
  const s = String(symbol || '').trim().toUpperCase();
  const n = String(name || '').trim();
  if (!/^[A-Z0-9]{1,8}$/.test(s)) throw new Error('A symbol is 1–8 letters or digits');
  if (!n || n.length > 24 || !PRINTABLE.test(n)) throw new Error('A name is 1–24 plain characters');
  const out = new Uint8Array(32);
  out.set(te.encode(s), 0);
  out.set(te.encode(n), 8);
  return out;
}

export function decodeMeta(meta) {
  const bytes = typeof meta === 'string' ? unhex(meta) : meta;
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return null;
  const text = (b) => {
    const end = b.indexOf(0);
    return new TextDecoder().decode(end === -1 ? b : b.subarray(0, end));
  };
  const symbol = text(bytes.subarray(0, 8));
  const name = text(bytes.subarray(8));
  if (!/^[A-Z0-9]{1,8}$/.test(symbol) || !name || !PRINTABLE.test(name)) return null;
  // Padding must be zeros all the way: otherwise two different metas would
  // show the same name, and a copycat could wear someone else's.
  const tail = (from, to) => bytes.subarray(from, to).every((b) => b === 0);
  if (!tail(symbol.length, 8) || !tail(8 + name.length, 32)) return null;
  return { symbol, name };
}

// ---------------------------------------------------------------------------
// NFTs: every item is its own asset, `item_address(collection, serial)`, so
// its identity survives every sale and send. A listing names no seller: the
// proceeds wait as a claim only the seller's nonce finds.
// ---------------------------------------------------------------------------

const DERIVE_DOMAIN = te.encode('zyn.derive.v1');
const ADDRESS_SCOPE_V1 = new Uint8Array([...te.encode('zynzap'), 0x00, 0x02]);

/// `zyn_vm::derive`: sha256 over the domain and length-prefixed parts.
function deriveAddress(program, namespace, seeds) {
  const parts = [DERIVE_DOMAIN, u32be(program.length), program, u32be(namespace.length), namespace, u32be(seeds.length)];
  for (const s of seeds) parts.push(u32be(s.length), s);
  return sha256(concatBytes(...parts));
}

// Bridged assets beside ZEC (§146): an address from public facts about the
// origin, deposits that carry a commitment instead of an account, and exits
// that commit to `keccak(address ‖ salt)` on the destination chain.
export const bridgedAsset = (network, origin = new Uint8Array(0)) => deriveAddress(ADDRESS_SCOPE_V1, te.encode('bridged'), [te.encode(network), origin]);
export const depositCommitment = (account, secret) => id('objectvm.deposit.v1', account, secret);
export const depositKey = (commitment, asset) => id('objectvm.deposit-claim.v1', commitment, asset);
export const exitCommitment = (address, salt) => keccak_256(concatBytes(address, salt));
export const claimDepositIntent = (o) => concatBytes(
  new Uint8Array([TAG.claimDeposit]), o.owner, prog('claim'), o.secret, o.asset, outputs([o.output]),
);

// ---- Zyn Lend (objectvm/src/lend.rs) ----------------------------------------
//
// Everything lending pays — receipt shares, withdrawals, borrowed coins,
// auction fills, refunds — is a claim under `lendSource(owner, nonce)` (k 0,
// and k 1 for a refund), collected like any other. A position's id is the
// source of the intent that opened it; what a liquidation leaves is claimable
// under `leftoverSource(position)`, and bidders see only `lotSource(position)`.

/// The receipt asset for lending `underlying`: lZEC, lETH, lSOL.
export const lendAsset = (underlying) => id('objectvm.lend.v1', underlying);
export const lendSource = (owner, nonce) => id('objectvm.lend-src.v1', owner, nonce);
export const lotSource = (position) => id('objectvm.lend-lot.v1', position);
// A liquidation's leftovers: not the lot's public id, so nobody can watch the
// owner collect them.
export const leftoverSource = (position) => id('objectvm.lend-left.v1', position);

export const lendSupplyIntent = (o) => concatBytes(
  new Uint8Array([TAG.lendSupply]), o.lender, prog('lendSupply'), o.asset, i128Bytes(o.amount), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const lendWithdrawIntent = (o) => concatBytes(
  new Uint8Array([TAG.lendWithdraw]), o.lender, prog('lendWithdraw'), o.asset, i128Bytes(o.shares), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const lendOpenIntent = (o) => concatBytes(
  new Uint8Array([TAG.lendOpen]), o.borrower, prog('lendOpen'), o.collateralAsset, i128Bytes(o.collateral),
  o.borrowAsset, i128Bytes(o.amount), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const lendRepayIntent = (o) => concatBytes(
  new Uint8Array([TAG.lendRepay]), o.borrower, prog('lendRepay'), o.position, i128Bytes(o.amount), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const lendAddCollateralIntent = (o) => concatBytes(
  new Uint8Array([TAG.lendAddCollateral]), o.borrower, prog('lendCollateral'), o.position, i128Bytes(o.amount), inputs(o.inputs), outputs(o.change),
);

export const lendRemoveCollateralIntent = (o) => concatBytes(
  new Uint8Array([TAG.lendRemoveCollateral]), o.borrower, prog('lendCollateral'), o.position, i128Bytes(o.amount), o.nonce,
);

/// Anyone adding to a pool's insurance (§160): no shares, no claim back.
export const lendInsureIntent = (o) => concatBytes(
  new Uint8Array([TAG.lendInsure]), o.donor, prog('lendInsure'), o.asset, i128Bytes(o.amount), inputs(o.inputs), outputs(o.change),
);

export const lendBidIntent = (o) => concatBytes(
  new Uint8Array([TAG.lendBid]), o.bidder, prog('lendBid'), o.lot, i128Bytes(o.pay), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const itemAsset = (collection, serial) => deriveAddress(ADDRESS_SCOPE_V1, te.encode('item'), [collection, u32be(serial)]);
export const listingSource = (seller, nonce) => id('objectvm.listing.v1', seller, nonce);
export const saleFeeSource = (item) => id('objectvm.sale-fee.v1', item);
export const redemptionSource = (firstItem) => id('objectvm.redeem.v1', firstItem);
/// One item is one unit of its own asset.
export const ITEM_UNIT = WAD;

const PLACE_OFFER = hex(leaf(te.encode('zyn.program.named.v1'), u32be(11), te.encode('place-offer')));
const CANCEL_OFFER = hex(leaf(te.encode('zyn.program.named.v1'), u32be(12), te.encode('cancel-offer')));
const TAKE_OFFER = hex(leaf(te.encode('zyn.program.named.v1'), u32be(10), te.encode('take-offer')));
const REDEEM_ITEM = hex(leaf(te.encode('zyn.program.named.v1'), u32be(11), te.encode('redeem-item')));

export const listIntent = (o) => concatBytes(
  new Uint8Array([21]), o.seller, unhex(PLACE_OFFER), o.item, o.itemNullifier, o.priceAsset,
  i128Bytes(o.priceAmount), u64be(o.expiresAtEpoch), o.nonce,
);

export const cancelOfferIntent = (o) => concatBytes(new Uint8Array([4]), o.seller, unhex(CANCEL_OFFER), o.item);

/// `Op::TakeOffer`: the listed item's nullifier (from `zyn_offers`), the
/// buyer's payment, and outputs that are the item and the buyer's change.
export function takeOfferIntent(o) {
  const payment = [];
  for (const p of o.payment) payment.push(p.commitment, p.nullifier);
  const outs = [];
  for (const x of o.outputs) outs.push(x.note.asset, i128Bytes(x.note.amount), x.note.owner, x.note.nonce, x.enc.epk, u32be(x.enc.ciphertext.length), x.enc.ciphertext);
  return concatBytes(
    new Uint8Array([5]), o.buyer, unhex(TAKE_OFFER), o.item, o.itemNullifier,
    u32be(o.payment.length), u32be(o.outputs.length), ...payment, ...outs,
  );
}

export const redeemIntent = (o) => concatBytes(new Uint8Array([20]), o.holder, unhex(REDEEM_ITEM), o.collection, inputs(o.inputs));

// ---------------------------------------------------------------------------
// Primary sales (objectvm::sale, DECISIONS §144): lottery tickets bought in
// ZEC.zy, a draw posted as a Merkle root, and claims proved against it.
// ---------------------------------------------------------------------------

/// One ticket's id — only its buyer can derive it.
export const ticketId = (buyer, nonce, k) => id('objectvm.ticket.v1', buyer, nonce, u32be(k));
/// Burn tickets (§145): the memo commitment binds this account and a secret,
/// so a claim that reveals the secret helps nobody else.
export const voucherCommitment = (account, secret) => id('objectvm.voucher.v1', account, secret);
export const voucherTicketId = (commitment, k) => id('objectvm.voucher-ticket.v1', commitment, u32be(k));
/// Where the treasury's share of one sale payment is claimable.
export const treasurySource = (collection, payment) => id('objectvm.sale-treasury.v1', collection, payment);
/// One leaf of a posted draw: a ticket and the serials it won.
export const drawLeaf = (ticket, serials) => leaf(te.encode('objectvm.draw-leaf.v1'), ticket, u32be(serials.length), ...serials.map((x) => u32be(x)));
/// One leaf of the open-mint order.
export const openLeaf = (position, serial) => leaf(te.encode('objectvm.open-leaf.v1'), u32be(position), u32be(serial));

/// `zyn_vm::commit::hash_node`: SHA-256 over a node prefix and both children.
const hashNode = (l, r) => sha256(concatBytes(new Uint8Array([0x01]), l, r));

/// The same tree as `zyn_vm::commit::merkle_root`: an odd node is promoted.
export function merkleRoot(leaves) {
  if (!leaves.length) return new Uint8Array(32);
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(hashNode(level[i], level[i + 1]));
    if (level.length % 2) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

/// `zyn_vm::commit::merkle_proof`: the siblings from a leaf to the root.
export function merkleProof(leaves, index) {
  const path = [];
  let level = leaves.slice();
  let idx = index;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) {
      if (idx === i) path.push({ sibling: level[i + 1], nodeIsRight: false });
      else if (idx === i + 1) path.push({ sibling: level[i], nodeIsRight: true });
      next.push(hashNode(level[i], level[i + 1]));
    }
    if (level.length % 2) next.push(level[level.length - 1]);
    idx = Math.floor(idx / 2);
    level = next;
  }
  return path;
}

export function verifyProof(leafHash, path, root) {
  let node = leafHash;
  for (const s of path) node = s.nodeIsRight ? hashNode(s.sibling, node) : hashNode(node, s.sibling);
  return hex(node) === hex(root);
}

function proofBytes(path) {
  return concatBytes(u32be(path.length), ...path.flatMap((s) => [s.sibling, bool(s.nodeIsRight)]));
}

export const buyTicketsIntent = (o) => concatBytes(
  new Uint8Array([TAG.buyTickets]), o.buyer, prog('saleTickets'), o.collection, u32bytes(o.count), o.nonce,
  inputs(o.inputs), outputs(o.change),
);

export const claimItemsIntent = (o) => concatBytes(
  new Uint8Array([TAG.claimItems]), o.buyer, prog('saleClaim'), o.collection, o.nonce, u32bytes(o.k),
  u32be(o.serials.length), ...o.serials.map((x) => u32be(x)), proofBytes(o.proof),
  outputs(o.items), inputs(o.inputs), outputs(o.change),
);

export const claimVoucherItemsIntent = (o) => concatBytes(
  new Uint8Array([TAG.claimVoucherItems]), o.buyer, prog('saleClaim'), o.collection, o.secret, u32bytes(o.k),
  u32be(o.serials.length), ...o.serials.map((x) => u32be(x)), proofBytes(o.proof),
  outputs(o.items), inputs(o.inputs), outputs(o.change),
);

// Sale credit (§182): a burn's credit waits under the burner's commitment
// until they take it up from their account; then it pays before any note.
export const creditPendingKey = (collection, commitment) => id('objectvm.sale-credit-pending.v1', collection, commitment);
export const creditKey = (collection, account) => id('objectvm.sale-credit.v1', collection, account);
export const creditFunding = (funder, nonce) => id('objectvm.sale-credit-fund.v1', funder, nonce);

export const fundSaleCreditIntent = (o) => concatBytes(
  new Uint8Array([TAG.fundSaleCredit]), o.funder, prog('saleTickets'), o.collection, i128Bytes(o.amount), o.nonce, inputs(o.inputs), outputs(o.change),
);

export const redeemCreditIntent = (o) => concatBytes(new Uint8Array([TAG.redeemCredit]), o.buyer, prog('saleClaim'), o.collection, o.secret);

export const mintOpenIntent = (o) => concatBytes(
  new Uint8Array([TAG.mintOpen]), o.buyer, prog('saleMint'), o.collection, u32bytes(o.serial), proofBytes(o.proof),
  outputs([o.item]), o.nonce, inputs(o.inputs), outputs(o.change),
);

