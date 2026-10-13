// What a connected site may ask Nap for, and what each costs.
//
// The same names and shapes the extension serves (`apps/extension`), so a
// site written against one works against the other. Four kinds:
//
//   public   the market's own public data; no connection needed
//   read     this holder's data, for a site the holder connected
//   write    moves something; the holder approves each one
//   connect  nap_connect itself
//
// Every write is *prepared* before it is shown: the approval describes what
// the chain says — the listed price, the item, the recipient — not what the
// site claims, and the site's claim is checked against it.

import { forgetIdentity, parseAmount, WAD } from './core.js';
import { contentHash, contentProof, hex, nullifierOf, unhex } from './object.js';
import * as mk from './market.js';
import * as ledger from './ledger.js';
import * as bridges from './bridges.js';
import * as pool from './pool.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { parsePaymentRequest, zatoshiOf } from './zip321.js';
import { CAVE_Z, itemName } from './items.js';

export { itemName };

/// EIP-1193's error codes, so a site handles Nap the way it handles any wallet.
export const ERR = Object.freeze({ REJECTED: 4001, UNAUTHORIZED: 4100, UNSUPPORTED: 4200, PARAMS: -32602 });
export class ProviderError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const bad = (m) => new ProviderError(ERR.PARAMS, m);

/// The private channel a request names (SOL when it names none).
function channelOf(ctx, p) {
  try { return pool.channel(ctx.config, String(p?.channel || 'sol')); } catch (e) { throw bad(e.message); }
}
function sizeIn(c, size) {
  try { return pool.sizeOf(c, size); } catch (e) { throw bad(e.message); }
}

const ZAT = 100_000_000n;
const zecText = (zat) => { const v = BigInt(zat); const f = (v % ZAT).toString().padStart(8, '0').replace(/0+$/, ''); return `${v / ZAT}${f ? `.${f}` : ''}`; };
/// A ledger amount in full: an approval shows exactly what is signed, never
/// a rounded figure.
const wadText = (raw) => { const v = BigInt(raw); const f = (v % WAD).toString().padStart(18, '0').replace(/0+$/, ''); return `${v / WAD}${f ? `.${f}` : ''}`; };
/// An amount a site sent, or a parameter error that says which.
const amountOf = (v, what) => { try { return parseAmount(String(v ?? '')); } catch (e) { throw bad(`${what}: ${e.message}`); } };
const NO_ZEC = 'This wallet has no Zcash keys on this device yet. Open Nap, choose Zcash, add your Zcash wallet, then try again.';
const isHex = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);

/// The sale a site asks about: Collection Z unless it names another.
function saleCollection(p) {
  const c = p?.collection ?? CAVE_Z;
  if (!isHex(c)) throw bad('collection must be 64 hex characters');
  return c;
}

/// What the site learns on connecting: the account, and a Zcash address. Not
/// a balance, not a note, not a viewing key.
export async function session(ctx) {
  let zcash = null;
  // The Zcash address is a courtesy: if its wallet cannot open here, the
  // site still gets the account rather than a connection that never works.
  if (ctx.zec) {
    try { const view = await ctx.zec(); zcash = { network: view.network, address: view.address }; } catch { zcash = null; }
  }
  return { account: ctx.identity.accountHex, network: ctx.config.id, chain: ctx.config.chain, zcash };
}

async function holdings(ctx) {
  const offers = await ledger.loadOffers(ctx.config);
  const mine = await ledger.loadHoldings(ctx.config, ctx.identity, offers);
  return { offers, ...mine };
}

/// Refuse before asking the holder to approve something they cannot pay for.
async function mustHold(ctx, asset, amount, name) {
  const h = await holdings(ctx);
  const have = h.held.filter((x) => x.asset === asset).reduce((a, x) => a + BigInt(x.amount), 0n);
  // The refusal reaches the site, so it says what was asked, never what this
  // wallet holds: the connect card promises the site the account ID only.
  if (have < amount) throw bad(`This wallet does not hold enough ${name} (that needs ${wadText(amount)})`);
}

/// What an approval calls the coin a payment is made in.
async function quoteName(ctx, asset) {
  return (await namer(ctx, await ledger.call(ctx.config, 'zyn_market')))(asset);
}

const shortHex = (h) => `${String(h).slice(0, 8)}…${String(h).slice(-6)}`;
const collectionLabel = (c) => (c === CAVE_Z ? 'Cave, batch one (Collection Z)' : `${c.slice(0, 10)}…`);
/// What the team's vote weighs on a DAO's Zyn track (§176), from the chain.
const teamRule = (z) => (z?.rule === 'weighted' ? `the team's account casts ${Number(z.share_bps) / 100}% of the tally` : "the team's account can veto, not pass");

/// This wallet's items of `collection`, as the DAO's member proofs: refused
/// when it holds none, so a site learns only that this wallet is not a member.
async function daoItems(ctx, collection) {
  const h = await holdings(ctx);
  const mine = h.held.map((note) => ({ note, item: h.items.get(note.asset) })).filter((x) => x.item?.collection === collection && BigInt(x.note.amount) === mk.ITEM_UNIT);
  if (!mine.length) throw bad('This wallet holds no item of that collection');
  return mine;
}

function heldItem(h, asset) {
  if (!isHex(asset)) throw bad('asset must be 64 hex characters');
  const note = h.held.find((x) => x.asset === asset);
  const item = h.items.get(asset);
  if (!note || !item) throw bad('This wallet does not hold that item');
  return { note, item };
}

// ---------------------------------------------------------------------------
// Bonding curves (objectvm::curve, DECISIONS §141).
// ---------------------------------------------------------------------------

const isInt = (v) => typeof v === 'string' && /^\d{1,40}$/.test(v);
const validCurve = (c) => isHex(c.token) && isHex(c.quote) && isHex(c.meta)
  && ['reserve', 'graduation', 'creator_fees', 'bond', 'price_per_token'].every((k) => isInt(c[k]))
  && Number.isSafeInteger(c.sold) && c.sold >= 0 && typeof c.graduated === 'boolean';

/// A coin's address in a card row: names and tickers repeat, addresses do not
/// (audit, 6 Oct 2026: a copycat "PEPE" read the same as the real one).
const addrText = (a) => `${a.slice(0, 8)}…${a.slice(-6)}`;
/// Other coins on a curve under the same ticker, which a card must say.
const lookalikes = (curves, c) => curves.filter((x) => x.token !== c.token && x.symbol === c.symbol).length;
/// How far a floor sits below what the order would get alone, in percent.
const floorGap = (preview, floor) => (preview > 0n ? Number(((preview - (floor < preview ? floor : preview)) * 10_000n) / preview) / 100 : 0);
/// Above this gap a floor protects little and the card says so in red.
const LOOSE_FLOOR = 10;

/// A curve's size (§166): the ledger amount one unit of its shape stands
/// for. A node from before §166 says nothing, and every curve was ZEC-sized.
const unitOf = (c) => (isInt(c?.unit) && c.unit !== '0' ? BigInt(c.unit) : mk.ZAT);

/// The assets coins launch in, and each one's size and bond. None named:
/// ZEC.zy at ZEC's size with the general bond, as before §166.
function launchAssets(ctx, market, terms) {
  const named = (market.curve_quotes || []).filter((q) => isHex(q.asset) && isInt(q.unit) && isInt(q.bond));
  if (named.length) return named.map((q) => ({ asset: q.asset, unit: BigInt(q.unit), bond: BigInt(q.bond) }));
  return [{ asset: ctx.config.zecAsset, unit: mk.ZAT, bond: BigInt(terms.bond || '0') }];
}

/// The sale credit this wallet holds and has waiting (§182), together: what
/// a payment will take from credit before any note.
async function creditOf(ctx, collection) {
  const c = await ledger.loadCredit(ctx.config, ctx.identity, collection).catch(() => null);
  return c ? c.held + c.waiting : 0n;
}

/// The review's payment rows: what comes from credit and what from ZEC.zy.
function creditRows(fromCredit, total, q) {
  if (fromCredit <= 0n) return [['You pay', `${wadText(total)} ${q}`]];
  return [['From your sale credit', `${wadText(fromCredit)} ${q}`], ['You pay', `${wadText(total - fromCredit)} ${q}`]];
}

/// The notes paying `price` once `credit` has paid what it can: none at all
/// when credit covers it, as the ledger requires.
async function notesFor(ctx, quote, price, credit) {
  if (credit >= price) return { inputs: [], change: [] };
  const h = await holdings(ctx);
  return mk.fund(ctx.identity, h.held, unhex(quote), price - credit);
}

/// This account on a sale's list (§168), as the chain has it.
async function saleAccess(ctx, collection) {
  const key = hex(mk.saleAllowKey(unhex(collection), ctx.identity.account));
  const r = await ledger.call(ctx.config, 'zyn_saleAllow', { collection, key }).catch(() => null);
  // A node from before §168 has no gates: every sale is open to all.
  if (!r) return { gated: false, listed: true, bought: 0, base: null, open: null };
  // Open-mint terms (§187): this wallet's price there, and its count of the cap.
  const open = r.open ? { price: String(r.open.price), minted: Number(r.open.minted) || 0, cap: Number(r.open.cap) || 0 } : null;
  return { gated: !!r.gated, listed: !!r.listed, bought: Number(r.bought) || 0, base: r.base ?? null, open };
}

async function curveBook(ctx) {
  const market = await ledger.call(ctx.config, 'zyn_market');
  const curves = (market.curves || []).filter(validCurve).map((c) => ({ ...c, ...(mk.decodeMeta(c.meta) || { symbol: '?', name: 'Unnamed' }) }));
  return { market, curves, terms: market.curve_terms || { set: false, fee_bps: 0, bond: '0' } };
}

async function oneCurve(ctx, token) {
  if (!isHex(token)) throw bad('token must be 64 hex characters');
  const { market, curves, terms } = await curveBook(ctx);
  const c = curves.find((x) => x.token === token);
  if (!c) throw bad('No token on a curve has that address');
  return { market, c, terms };
}

/// What an approval calls an asset: ZEC.zy, a bridged coin, a curve token by
/// its symbol, else its short address.
async function namer(ctx, market) {
  const bridged = await ledger.loadBridged(ctx.config);
  // Lending receipts, named from the asset they are a share of.
  const receipts = new Map([[ctx.config.zecAsset, 'ZEC.zy'], ...bridged.map((x) => [x.asset, ledger.bridgedName(ctx.config, x)])]
    .map(([u, n]) => [hex(mk.lendAsset(unhex(u))), `l${n}`]));
  return (a) => {
    if (a === ctx.config.zecAsset) return 'ZEC.zy';
    const b = bridged.find((x) => x.asset === a);
    if (b) return ledger.bridgedName(ctx.config, b);
    if (receipts.has(a)) return receipts.get(a);
    const c = (market.curves || []).find((x) => x.token === a);
    const meta = c && isHex(c.meta) ? mk.decodeMeta(c.meta) : null;
    return meta?.symbol || `${a.slice(0, 8)}…`;
  };
}

const tokenText = (raw) => { const v = BigInt(raw) / WAD; return v.toLocaleString('en-US'); };

// ---------------------------------------------------------------------------
// Zyn Lend (objectvm/src/lend.rs; zyn-io/zyn-lend).
// ---------------------------------------------------------------------------

const pctText = (wadRate) => `${(Number(BigInt(wadRate) * 10_000n / WAD) / 100).toFixed(2)}%`;

/// The lending markets, checked: a pool that does not parse is not offered.
async function lendBook(ctx) {
  const m = await ledger.call(ctx.config, 'zyn_lendMarkets');
  const pools = (m.pools || []).filter((x) => isHex(x.asset) && isHex(x.receipt)
    && ['cash', 'borrowed', 'supplied', 'share_price', 'borrow_rate', 'supply_rate', 'utilization'].every((k) => isInt(x[k]))
    && [x.max_ltv_bps, x.liquidation_bps, x.penalty_bps].every(Number.isSafeInteger));
  const prices = Object.fromEntries(Object.entries(m.prices || {}).filter(([a, v]) => isHex(a) && isInt(v)).map(([a, v]) => [a, BigInt(v)]));
  const name = await namer(ctx, await ledger.call(ctx.config, 'zyn_market'));
  return { m, pools, prices, name };
}

function lendPool(book, asset, what) {
  if (!isHex(asset)) throw bad(`${what} must be 64 hex characters`);
  const pool = book.pools.find((x) => x.asset === asset);
  if (!pool) throw bad(`${what}: that asset is not lent on this chain`);
  return pool;
}

/// Dollars for an amount at a posted price, both WAD.
const usdOf = (amount, price) => (price ? (amount * price) / WAD : null);
const usdText = (v) => (v == null ? 'no price posted' : `$${(Number(v / (WAD / 100n)) / 100).toLocaleString('en-US', { maximumFractionDigits: 2 })}`);

/// Health and the collateral price that liquidates, as the ledger will see it.
function lendPreview(book, coll, collAmount, borrow, owed) {
  const pc = book.prices[coll.asset], pb = book.prices[borrow.asset];
  const cv = usdOf(collAmount, pc), dv = usdOf(owed, pb);
  if (cv == null || dv == null) return { health: null, liquidation: null, allowed: false, cv, dv };
  const allowed = dv * 10_000n <= cv * BigInt(coll.max_ltv_bps);
  const health = dv > 0n ? Number((cv * BigInt(coll.liquidation_bps) * 100n) / (dv * 10_000n)) / 100 : null;
  const liquidation = dv > 0n && collAmount > 0n ? (dv * 10_000n * WAD) / (collAmount * BigInt(coll.liquidation_bps)) : null;
  return { health, liquidation, allowed, cv, dv };
}

/// The step the node rounds a pool's public amounts to (two significant
/// figures of what is supplied), unless the pool says its own.
function roundStep(pool) {
  if (isInt(pool.round_step)) return BigInt(pool.round_step);
  const supplied = BigInt(pool.supplied);
  let step = 1n;
  while (supplied / step >= 100n) step *= 10n;
  return step;
}
/// What is surely free in a pool: its published cash less half a rounding
/// step, so a pre-check never promises coins the rounding made up.
const freeCash = (pool) => { const v = BigInt(pool.cash) - roundStep(pool) / 2n; return v > 0n ? v : 0n; };

/// How a lot is sold, as the chain says, else the rules this app was built
/// for: from 102% of market down to an 85% floor, then a backstop that may
/// sell down to 70%.
function auctionTerms(book) {
  const a = book.m.auction || {};
  const n = (v, d) => (Number.isSafeInteger(v) && v > 0 ? v : d);
  return { start: n(a.start_bps, 10_200), floor: n(a.floor_bps, 8_500), backstop: n(a.backstop_min_bps ?? a.backstop_bps, 7_000) };
}
const bpsText = (b) => `${b / 100}%`;
/// The worst a liquidation can do to `coll`'s holder, in one line.
const worstCase = (book, coll, cn) => {
  const t = auctionTerms(book);
  return `your ${cn} can be sold down to ${bpsText(t.floor)} of its market price, or ${bpsText(t.backstop)} if no one bids, plus a ${bpsText(coll.penalty_bps)} penalty`;
};
/// Health and liquidation price as rows, for an approval that changes them.
function healthRows(v, cn, label = 'after') {
  if (v.health == null) return v.dv === 0n || v.dv == null ? [] : [[`Health ${label}`, 'no price posted']];
  return [[`Health ${label}`, `${v.health.toFixed(2)} — liquidated below 1.00`], [`Liquidated if (${label})`, `${cn} falls to ${usdText(v.liquidation)}`]];
}
/// Rules v2's pair entry for collateral `c` backing loans of `b`, if published.
const pairOf = (book, c, b) => (Array.isArray(book.m.pairs) ? book.m.pairs.find((x) => x?.collateral_asset === c && x?.borrow_asset === b) : null) || null;
/// The most collateral of `coll` that may still be posted against `borrow`:
/// the pair's depth room and the asset's cap room, whichever the chain
/// publishes (null: it publishes neither).
function collateralRoom(book, coll, borrowAsset) {
  const rooms = [];
  const pair = borrowAsset ? pairOf(book, coll.asset, borrowAsset) : null;
  if (pair && isInt(pair.room)) rooms.push(BigInt(pair.room));
  if (isInt(coll.collateral_room)) rooms.push(BigInt(coll.collateral_room));
  return rooms.length ? rooms.reduce((a, b) => (b < a ? b : a)) : null;
}

/// The smallest loan a pool makes, in WAD dollars, or null.
const minLoan = (pool) => (isInt(pool.min_borrow_usd) && BigInt(pool.min_borrow_usd) > 0n ? BigInt(pool.min_borrow_usd) : null);

async function ownPosition(ctx, id) {
  if (!isHex(id)) throw bad('position must be 64 hex characters');
  const p = (await ledger.loadPositions(ctx.config, ctx.identity)).find((x) => x.id === id);
  if (!p) throw bad('This wallet has no position with that id');
  if (p.state !== 'open') throw bad('That position is in a liquidation auction');
  return p;
}

/// A site's private-channel notes: what a site's bridge page acts on, and no
/// more (audit, 9 Oct 2026). The relayer's transaction signature is never
/// handed out, and neither is a spent note's commitment: on its chain the
/// one ties the spend to its exit address, the other the deposit to its
/// wallet, and neither is anything a site can still act on. An unspent
/// note keeps its commitment, which Move into Zyn and Send name it by.
export function siteNotes(notes) {
  return notes.map((n) => ({
    ch: n.ch, size: String(n.size), kind: n.kind, state: n.state,
    ...(['to zyn', 'sent', 'spent'].includes(n.state) ? {} : { commitment: n.commitment }),
  }));
}

/// `kind`: 'public' answers anyone; 'read' and 'auto' a connected site,
/// without a card; 'write' after the holder approves its card. A read that
/// names a `scope` (connect-grants.js) also waits for the holder to allow
/// that scope to the site, once.
export const METHODS = {
  nap_connect: { kind: 'connect' },
  nap_session: { kind: 'session' },
  nap_disconnect: { kind: 'session' },

  zyn_account: { kind: 'read', run: (ctx) => session(ctx) },
  zec_getAddress: {
    kind: 'read',
    run: async (ctx) => {
      if (!ctx.zec) throw new ProviderError(ERR.UNSUPPORTED, NO_ZEC);
      const v = await ctx.zec();
      return { network: v.network, address: v.address };
    },
  },

  zyn_nftOffers: {
    kind: 'public',
    run: async (ctx) => ({ offers: (await ledger.loadOffers(ctx.config)).filter((o) => o.serial >= 0) }),
  },
  zyn_nftItems: {
    kind: 'read',
    run: async (ctx) => {
      const h = await holdings(ctx);
      const listed = new Set(h.offers.map((o) => o.item));
      return {
        items: h.held.filter((n) => h.items.has(n.asset)).map((n) => ({
          asset: n.asset, ...h.items.get(n.asset), listed: listed.has(n.commitment),
        })),
      };
    },
  },
  zyn_owed: {
    kind: 'read',
    run: async (ctx) => ({ owed: (await ledger.loadOwed(ctx.config, ctx.identity)).map((r) => ({ id: r.id, asset: r.asset, amount: r.amount })) }),
  },

  zyn_curves: {
    kind: 'public',
    run: async (ctx) => {
      const { market, curves, terms } = await curveBook(ctx);
      const quotes = launchAssets(ctx, market, terms).map((q) => ({ asset: q.asset, unit: String(q.unit), bond: String(q.bond) }));
      return { curves, terms, quotes, curve: mk.CURVE };
    },
  },
  zyn_curveHoldings: {
    kind: 'read',
    run: async (ctx) => {
      const { market, curves, terms } = await curveBook(ctx);
      const h = await holdings(ctx);
      // The tokens this wallet made: its own nonces, turned into token ids.
      const mine = new Set();
      const count = (await ledger.ensureNonces(ctx.config, ctx.identity)) + ledger.LOOKAHEAD;
      for (let n = 0; n < count; n++) mine.add(hex(mk.tokenOf(ctx.identity.account, mk.marketNonce(ctx.identity.secretKey, n))));
      return {
        zec: String(h.balances.get(ctx.config.zecAsset) || 0n),
        // What it holds of each asset coins launch in, to trade them with.
        quotes: launchAssets(ctx, market, terms).map((q) => ({ asset: q.asset, amount: String(h.balances.get(q.asset) || 0n) })),
        holdings: curves.map((c) => ({ token: c.token, symbol: c.symbol, name: c.name, amount: String(h.balances.get(c.token) || 0n) }))
          .filter((x) => x.amount !== '0'),
        created: curves.filter((c) => mine.has(c.token)).map((c) => ({ token: c.token, symbol: c.symbol, name: c.name })),
      };
    },
  },

  // --- writes ---------------------------------------------------------------

  zyn_curveCreate: {
    kind: 'write',
    async prepare(ctx, p) {
      const meta = mk.encodeMeta({ symbol: p.symbol, name: p.name });
      // Optional picture and description, attached by proof after creation.
      const description = String(p.description || '').trim();
      const image = String(p.image || '');
      if (description.length > 400) throw bad('A description is at most 400 characters');
      if (image && !/^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(image)) throw bad('The picture must be a PNG, JPEG, WebP or GIF');
      if (image.length > 420_000) throw bad('The picture must be under 300 KB');
      const content = description || image ? { description, image } : null;
      const { market, terms } = await curveBook(ctx);
      // The coin it is priced in: ZEC.zy unless the site asks for another
      // the ledger launches coins in (§166).
      const quote = p.quote == null ? ctx.config.zecAsset : p.quote;
      if (!isHex(quote)) throw bad('quote must be 64 hex characters');
      const as = launchAssets(ctx, market, terms).find((q) => q.asset === quote);
      if (!as) throw bad('Coins are not launched in that asset');
      const q$ = (await namer(ctx, market))(quote);
      const bond = as.bond;
      if (bond > 0n) await mustHold(ctx, quote, bond, q$);
      const raise = mk.curveCost(0, mk.CURVE.graduateAt, as.unit);
      return {
        title: `Create ${String(p.symbol).toUpperCase()}`,
        rows: [
          ['Name', String(p.name).trim()],
          ['Priced in', q$],
          ['Supply', '1,000,000,000 — all sold on the curve or put in its pool; none to you'],
          ['Graduates', `at ${mk.CURVE.graduateAt.toLocaleString('en-US')} of 80,000 lots (about ${(Number(raise / 10n ** 14n) / 1e4).toLocaleString('en-US', { maximumFractionDigits: 2 })} ${q$} raised), into a locked pool`],
          ['Bond', bond ? `${wadText(bond)} ${q$} — returned only if it graduates; otherwise it stays in the curve` : 'none'],
          ['Your share', terms.fee_bps ? `10% of its trading fees, paid when it graduates` : 'none (no fee is set)'],
          ...(description ? [['Description', description]] : []),
          ...(image ? [['Picture', 'shown above, stored by the site that asked; it proves you made the token']] : []),
        ],
        image: image || null,
        note: 'Anyone can buy it right away. You own none unless you buy, at the same price as everybody buying in that epoch.',
        run: async () => {
          let inputs = [], change = [];
          if (bond > 0n) {
            const h = await holdings(ctx);
            ({ inputs, change } = mk.fund(ctx.identity, h.held, unhex(quote), bond));
          }
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.createCurveIntent({
            creator: ctx.identity.account, nonce: n, quote: unhex(quote), meta, inputs, change,
          }));
          const token = mk.tokenOf(ctx.identity.account, nonce);
          if (!content) return { token: hex(token), quote };
          const hash = contentHash(content);
          return { token: hex(token), quote, content: { hash: hex(hash), proof: await contentProof(ctx.identity.secretKey, nonce, token, hash, ctx.config.chain) } };
        },
      };
    },
  },

  zyn_curveBuy: {
    kind: 'write',
    async prepare(ctx, p) {
      const { market, c } = await oneCurve(ctx, p.token);
      const q$ = (await namer(ctx, market))(c.quote);
      if (c.graduated) throw bad('That token has graduated; it trades in its pool (zyn_swap)');
      const amount = amountOf(p.amount, 'amount');
      const min = mk.curveMinBuy(unitOf(c));
      if (amount < min) throw bad(`A buy is at least ${wadText(min)} ${q$}`);
      const q = mk.previewCurveBuy(c.sold, amount, c.fee_bps, unitOf(c));
      if (q.lots === 0) throw bad('That buys less than one lot at the current price');
      const minLots = p.minTokens != null ? BigInt(amountOf(p.minTokens, 'minTokens')) / mk.LOT : 0n;
      await mustHold(ctx, c.quote, amount, q$);
      const gap = floorGap(q.tokens, minLots * mk.LOT);
      const twins = lookalikes((await curveBook(ctx)).curves, c);
      return {
        title: `Buy ${c.symbol} with ${wadText(amount)} ${q$}`,
        // No floor, or one far below the preview, fills at whatever the batch
        // clears; a ticker other coins share may not be the coin meant: red.
        danger: !minLots || gap > LOOSE_FLOOR || twins > 0,
        rows: [
          ['Token', `${c.name} (${c.symbol})`],
          ['Address', `${addrText(c.token)}${twins ? ` — ${twins} other coin${twins > 1 ? 's use' : ' uses'} the ticker ${c.symbol}; check this address` : ''}`],
          ['If nobody else buys this epoch', `${tokenText(q.tokens)} tokens`],
          ['Fee', c.fee_bps ? `${wadText(q.fee)} ${q$} (${c.fee_bps / 100}%)` : 'none'],
          ['Unspent', `${wadText(q.refund)} ${q$} comes back`],
          ['At least', minLots ? `${tokenText(minLots * mk.LOT)} tokens${gap > LOOSE_FLOOR ? ` — ${gap.toFixed(1)}% below the preview` : ''}, or the whole buy comes back` : 'no floor — it fills at whatever price the batch clears'],
        ],
        note: 'Everyone buying this epoch pays one price, set when it closes; other buyers in the same epoch move it. Collect the tokens once it settles.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(c.quote), amount);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.curveTradeIntent({
            trader: ctx.identity.account, token: unhex(c.token), buy: true, amountIn: amount, minOut: minLots * mk.LOT, inputs, change, nonce: n,
          }));
          return { order: hex(mk.curveOrderId(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  zyn_curveSell: {
    kind: 'write',
    async prepare(ctx, p) {
      const { market, c } = await oneCurve(ctx, p.token);
      const q$ = (await namer(ctx, market))(c.quote);
      if (c.graduated) throw bad('That token has graduated; it trades in its pool (zyn_swap)');
      const tokens = amountOf(p.tokens, 'tokens');
      if (tokens % mk.LOT !== 0n) throw bad(`Sell whole lots of ${mk.CURVE.lotTokens.toLocaleString('en-US')} tokens`);
      const lots = Number(tokens / mk.LOT);
      const q = mk.previewCurveSell(c.sold, lots, c.fee_bps, unitOf(c));
      const minZec = p.minZec != null ? amountOf(p.minZec, 'minZec') : 0n;
      await mustHold(ctx, c.token, tokens, c.symbol);
      const gap = floorGap(q.net, minZec);
      return {
        title: `Sell ${tokenText(tokens)} ${c.symbol}`,
        danger: !minZec || gap > LOOSE_FLOOR,
        rows: [
          ['Address', addrText(c.token)],
          ['If nobody else sells this epoch', `${wadText(q.net)} ${q$}`],
          ['Fee', c.fee_bps ? `${wadText(q.fee)} ${q$} (${c.fee_bps / 100}%)` : 'none'],
          ['At least', minZec ? `${wadText(minZec)} ${q$}${gap > LOOSE_FLOOR ? ` — ${gap.toFixed(1)}% below the preview` : ''}, or the tokens come back` : 'no floor — it sells at whatever price the batch clears'],
        ],
        note: `Sellers this epoch share one price, set when it closes. Collect the ${q$} once it settles.`,
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(c.token), tokens);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.curveTradeIntent({
            trader: ctx.identity.account, token: unhex(c.token), buy: false, amountIn: tokens, minOut: minZec, inputs, change, nonce: n,
          }));
          return { order: hex(mk.curveOrderId(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  // One order through up to four venues — a coin's curve, pools, another
  // coin's curve — settled in one seal, all or nothing (§167).
  zyn_route: {
    kind: 'write',
    async prepare(ctx, p) {
      const market = await ledger.call(ctx.config, 'zyn_market');
      const name = await namer(ctx, market);
      if (!Array.isArray(p.hops) || p.hops.length < 1 || p.hops.length > 4) throw bad('A route is one to four hops');
      const pools = new Map((market.pools || []).filter((x) => isHex(x.id)).map((x) => [x.id, x]));
      const curves = new Map((market.curves || []).filter(validCurve).map((c) => [c.token, c]));
      // Each hop as the chain stands: what it takes, what it gives.
      const hops = p.hops.map((h, i) => {
        if (h && isHex(h.pool) && typeof h.sellA === 'boolean') {
          const x = pools.get(h.pool);
          if (!x || !isInt(x.reserve_a) || !isInt(x.reserve_b) || BigInt(x.reserve_a) === 0n || BigInt(x.reserve_b) === 0n) throw bad('A pool on that route is gone or empty');
          return { hop: { pool: unhex(h.pool), sellA: h.sellA }, key: { pool: h.pool, sellA: h.sellA }, input: h.sellA ? x.a : x.b, output: h.sellA ? x.b : x.a, venue: h.pool };
        }
        const t = h?.curveSell ?? h?.curveBuy;
        const c = isHex(t) && curves.get(t);
        if (!c || c.graduated) throw bad('A coin on that route is not on its curve; route through its pool');
        if (h.curveSell && i !== 0) throw bad('A sale to a curve can only start a route');
        if (h.curveBuy && i !== p.hops.length - 1) throw bad('A purchase from a curve can only end a route');
        return h.curveSell
          ? { hop: { curveSell: unhex(t) }, key: { curveSell: t }, input: c.token, output: c.quote, venue: t }
          : { hop: { curveBuy: unhex(t) }, key: { curveBuy: t }, input: c.quote, output: c.token, venue: t };
      });
      if (new Set(hops.map((h) => h.venue)).size !== hops.length) throw bad('A route passes each venue once');
      hops.forEach((h, i) => { if (i && hops[i - 1].output !== h.input) throw bad('Each hop must take what the hop before it gives'); });
      const amountIn = amountOf(p.amount, 'amount');
      const minOut = amountOf(p.minOut, 'minOut');
      if (hops[0].hop.curveSell && amountIn % mk.LOT !== 0n) throw bad(`Sell whole lots of ${mk.CURVE.lotTokens.toLocaleString('en-US')} tokens`);
      const venues = { pool: (id) => pools.get(hex(id)), curve: (t) => curves.get(hex(t)) };
      const q = mk.previewRoute(hops.map((h) => h.hop), amountIn, venues);
      if (!q) throw bad('That route delivers nothing at these prices');
      // How far below the pools' own prices the route fills, hop by hop
      // (audit, 6 Oct 2026: a thin pool on a route lost half the value and
      // nothing said so). Curve hops are priced by the curve, not a pool.
      let kept = 1;
      let into = amountIn;
      hops.forEach((h, i) => {
        if (h.hop.pool) {
          const x = pools.get(h.key.pool);
          const [rin, rout] = h.key.sellA ? [BigInt(x.reserve_a), BigInt(x.reserve_b)] : [BigInt(x.reserve_b), BigInt(x.reserve_a)];
          const spot = (into * rout) / rin;
          if (spot > 0n) kept *= Number(q.steps[i]) / Number(spot);
        }
        into = q.steps[i];
      });
      const impact = Math.max(0, (1 - kept) * 100);
      const gap = floorGap(q.out, minOut);
      const [start, end] = [hops[0].input, hops[hops.length - 1].output];
      const path = [start, ...hops.map((h) => h.output)].map(name).join(' → ');
      await mustHold(ctx, start, amountIn, name(start));
      // Whole tokens where the amount is whole; never a floor rounded to "0".
      const show = (asset, raw) => (curves.has(asset) && BigInt(raw) % WAD === 0n ? `${tokenText(raw)} ${name(asset)}` : `${wadText(raw)} ${name(asset)}`);
      const endCurve = curves.get(end);
      return {
        title: `Swap ${name(start)} for ${name(end)}`,
        danger: !minOut || gap > LOOSE_FLOOR || impact >= 5,
        rows: [
          ['Route', path],
          ...(endCurve ? [['Address', addrText(end)]] : []),
          ['Below the pools\' prices', `${impact.toFixed(2)}%${impact >= 5 ? ' — the pools on this route are thin for this amount' : ''}`],
          ['You put in', show(start, amountIn)],
          ['If nobody else trades this epoch', show(end, q.out)],
          ['At least', minOut ? `${show(end, minOut)}${gap > LOOSE_FLOOR ? ` — ${gap.toFixed(1)}% below the preview` : ''}, or the whole route comes back` : 'no floor — it fills at whatever the batches clear at'],
          ['Settles', 'in one epoch, every hop together'],
        ],
        note: 'Each venue on the route clears once this epoch, at one price for everyone in it. If the end of the route would bring less than your floor, nothing on it happens and everything you put in comes back.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(start), amountIn);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.routeIntent({
            trader: ctx.identity.account, hops: hops.map((x) => x.hop), amountIn, minOut, nonce: n, inputs, change,
          }));
          return { order: hex(mk.routeId(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  zyn_swap: {
    kind: 'write',
    async prepare(ctx, p) {
      if (!isHex(p.pool)) throw bad('pool must be 64 hex characters');
      const market = await ledger.call(ctx.config, 'zyn_market');
      const pool = (market.pools || []).find((x) => x.id === p.pool);
      if (!pool || !['a', 'b', 'lp'].every((k) => isHex(pool[k])) || !isInt(pool.reserve_a) || !isInt(pool.reserve_b) || !Number.isSafeInteger(pool.fee_bps)
        || BigInt(pool.reserve_a) === 0n || BigInt(pool.reserve_b) === 0n) throw bad('No such pool');
      // A string "false" is true to JavaScript: the direction is a boolean or nothing.
      if (typeof p.sellA !== 'boolean') throw bad('sellA must be true or false');
      const sellA = p.sellA;
      const amountIn = amountOf(p.amount, 'amount');
      const quote = mk.quoteAlone(pool, sellA, amountIn);
      if (quote <= 0n) throw bad('Too small to trade in this pool');
      const slippage = Number.isInteger(p.slippageBps) && p.slippageBps >= 0 && p.slippageBps <= 1000 ? p.slippageBps : 100;
      const minOut = mk.withSlippage(quote, slippage);
      const sold = sellA ? pool.a : pool.b;
      const bought = sellA ? pool.b : pool.a;
      const name = await namer(ctx, market);
      const [inName, outName] = [name(sold), name(bought)];
      await mustHold(ctx, sold, amountIn, inName);
      // How far below the pool's spot price this fills, if alone.
      const x = BigInt(sellA ? pool.reserve_a : pool.reserve_b), y = BigInt(sellA ? pool.reserve_b : pool.reserve_a);
      const spot = (amountIn * y) / x;
      const impact = spot > 0n ? Number(((spot - quote) * 10_000n) / spot) / 100 : 0;
      return {
        title: `Swap ${inName} for ${outName}`,
        danger: impact >= 5,
        rows: [
          ['You put in', `${wadText(amountIn)} ${inName}`],
          ['If nobody else trades this epoch', `${wadText(quote)} ${outName}`],
          ['At least', `${wadText(minOut)} ${outName} (${slippage / 100}% slippage)`],
          ['Below the pool price', `${impact.toFixed(2)}%${impact >= 5 ? ' — a large share of this pool' : ''}`],
          ['Pool fee', `${pool.fee_bps / 100}%, kept by the pool`],
          // Symbols can repeat; the addresses cannot.
          ['Selling', `${inName} · ${sold.slice(0, 8)}…${sold.slice(-4)}`],
          ['Buying', `${outName} · ${bought.slice(0, 8)}…${bought.slice(-4)}`],
        ],
        note: 'Swaps in one epoch clear together at one price. If that price is worse than your floor, everything you put in comes back.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(sold), amountIn);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.swapIntent({
            trader: ctx.identity.account, pool: unhex(p.pool), sellA, amountIn, minOut, nonce: n, inputs, change,
          }));
          return { order: hex(mk.orderId(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  // --- Zyn Lend ---------------------------------------------------------------

  zyn_lendMarkets: { kind: 'public', run: async (ctx) => ledger.call(ctx.config, 'zyn_lendMarkets') },
  /// This wallet's positions, once the holder allows it (scope `positions`).
  zyn_lendPositions: { kind: 'read', scope: 'positions', run: async (ctx) => ({ positions: await ledger.loadPositions(ctx.config, ctx.identity) }) },

  zyn_lendSupply: {
    kind: 'write',
    async prepare(ctx, p) {
      const book = await lendBook(ctx);
      const pool = lendPool(book, p.asset, 'asset');
      const amount = amountOf(p.amount, 'amount');
      const name = book.name(pool.asset);
      if (pool.supply_paused === true) throw bad(`Deposits into the ${name} pool wait while an auction recovers a loss`);
      await mustHold(ctx, pool.asset, amount, name);
      return {
        title: `Lend ${name}`,
        danger: false,
        rows: [
          ['You lend', `${wadText(amount)} ${name}`],
          ['Earning now', `${pctText(pool.supply_rate)} a year, changing as the pool is used`],
          ['You receive', `l${name} shares, collected into this wallet`],
          ['Pool lent out', pctText(pool.utilization)],
        ],
        note: 'Losses from a bad loan are shared by lenders: insurance pays first, then every share in this pool loses value. Withdrawals wait while the pool is fully lent out.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(pool.asset), amount);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.lendSupplyIntent({ lender: ctx.identity.account, asset: unhex(pool.asset), amount, nonce: n, inputs, change }));
          return { source: hex(mk.lendSource(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  zyn_lendWithdraw: {
    kind: 'write',
    async prepare(ctx, p) {
      const book = await lendBook(ctx);
      const pool = lendPool(book, p.asset, 'asset');
      const shares = amountOf(p.shares, 'shares');
      const name = book.name(pool.asset);
      if (pool.withdraw_paused === true) throw bad(`Withdrawals from the ${name} pool wait for a held price to be confirmed`);
      await mustHold(ctx, pool.receipt, shares, `l${name}`);
      // The chain publishes a share's price, not how many shares exist.
      const worth = (shares * BigInt(pool.share_price)) / WAD;
      if (worth > freeCash(pool)) throw bad(`About ${wadText(freeCash(pool))} ${name} is surely free in the pool right now; the rest is lent out, and withdrawals wait until borrowers repay`);
      return {
        title: `Withdraw ${name}`,
        danger: false,
        rows: [['You return', `${wadText(shares)} l${name}`], ['About', `${wadText(worth)} ${name}, collected into this wallet`]],
        note: 'The exact amount is what the shares are worth when this is applied.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(pool.receipt), shares);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.lendWithdrawIntent({ lender: ctx.identity.account, asset: unhex(pool.asset), shares, nonce: n, inputs, change }));
          return { source: hex(mk.lendSource(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  zyn_lendOpen: {
    kind: 'write',
    async prepare(ctx, p) {
      const book = await lendBook(ctx);
      const coll = lendPool(book, p.collateral, 'collateral');
      const borrow = lendPool(book, p.borrow, 'borrow');
      if (coll.asset === borrow.asset) throw bad('Collateral and the borrowed asset must differ');
      const collAmount = amountOf(p.collateralAmount, 'collateralAmount');
      const amount = amountOf(p.amount, 'amount');
      const [cn, bn] = [book.name(coll.asset), book.name(borrow.asset)];
      if (amount > freeCash(borrow)) throw bad(`The ${bn} pool has about ${wadText(freeCash(borrow))} surely free to borrow`);
      if (coll.price_held || borrow.price_held || coll.price_fresh === false || borrow.price_fresh === false || book.m.prices_fresh === false) throw bad('Prices are stale or still moving; borrowing waits for the next confirmed price');
      const least = minLoan(borrow);
      if (least != null && book.prices[borrow.asset] && usdOf(amount, book.prices[borrow.asset]) < least) {
        throw bad(`The smallest ${bn} loan is ${usdText(least)}`);
      }
      // Caps: refused here only when surely over them (the published totals
      // are rounded); the chain has the last word, and says why.
      if (isInt(borrow.borrow_cap) && BigInt(borrow.borrowed) - roundStep(borrow) / 2n + amount > BigInt(borrow.borrow_cap)) {
        throw bad(`The ${bn} pool lends at most ${wadText(borrow.borrow_cap)} in all; it is at or near that cap`);
      }
      const room = collateralRoom(book, coll, borrow.asset);
      if (room != null && collAmount > room) throw bad(`At most ${wadText(room)} more ${cn} can back ${bn} loans now (the collateral cap, or a quarter of Zyn's ${cn}/${bn} pool)`);
      if (pairOf(book, coll.asset, borrow.asset)?.prices_agree === false) throw bad(`Borrowing in this pair is paused: Zyn's pool and the posted price disagree`);
      await mustHold(ctx, coll.asset, collAmount, cn);
      const v = lendPreview(book, coll, collAmount, borrow, amount);
      if (v.health == null) throw bad('No price is posted for this pair yet; borrowing opens once one is');
      if (!v.allowed) throw bad(`That is over the ${coll.max_ltv_bps / 100}% most ${cn} collateral may borrow`);
      return {
        title: `Borrow ${bn} against ${cn}`,
        danger: v.health < 1.5,
        rows: [
          ['You lock', `${wadText(collAmount)} ${cn} (${usdText(v.cv)})`],
          ['You borrow', `${wadText(amount)} ${bn} (${usdText(v.dv)})`],
          ['Health', `${v.health.toFixed(2)} — liquidated below 1.00`],
          ['Liquidated if', `${cn} falls to ${usdText(v.liquidation)}`],
          ['Borrow rate', `${pctText(borrow.borrow_rate)} a year, changing as the pool is used`],
          ['If liquidated', worstCase(book, coll, cn)],
        ],
        note: 'Debt grows with interest, and health falls with it. Others on the chain cannot see this position; the operator can. Prices are posted by the operator; if Zyn\'s own pool for this pair disagrees with them, the chain refuses the borrow.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(coll.asset), collAmount);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.lendOpenIntent({
            borrower: ctx.identity.account, collateralAsset: unhex(coll.asset), collateral: collAmount, borrowAsset: unhex(borrow.asset), amount, nonce: n, inputs, change,
          }));
          return { position: hex(mk.lendSource(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  zyn_lendRepay: {
    kind: 'write',
    async prepare(ctx, p) {
      const pos = await ownPosition(ctx, p.position);
      const book = await lendBook(ctx);
      const name = book.name(pos.borrow_asset);
      const cn = book.name(pos.collateral_asset);
      const owed = BigInt(pos.owed);
      const borrowPool = book.pools.find((x) => x.asset === pos.borrow_asset);
      const collPool = book.pools.find((x) => x.asset === pos.collateral_asset);
      const all = p.amount === 'all';
      const held = async () => (await holdings(ctx)).held.filter((x) => x.asset === pos.borrow_asset).reduce((a, x) => a + BigInt(x.amount), 0n);
      let amount, have;
      if (all) {
        have = await held();
        // What is owed plus a little for interest until it lands; the chain
        // returns anything over. A holder short of that buffer still repays
        // if they hold the debt plus the interest it can grow by before the
        // next seal.
        const buffer = owed + owed / 1000n + 1n;
        const rate = borrowPool && isInt(borrowPool.borrow_rate) ? BigInt(borrowPool.borrow_rate) : 0n;
        const market = await ledger.call(ctx.config, 'zyn_market').catch(() => ({}));
        const secs = BigInt(Math.max(60, 2 * (Number(market.epoch_seconds) || 60) + 60));
        const accruing = owed + (owed * rate * secs) / (WAD * 31_536_000n) + 1n;
        amount = have >= buffer ? buffer : have >= accruing ? have : buffer;
      } else {
        amount = amountOf(p.amount, 'amount');
        if (amount >= owed) throw bad(`That is all of the debt (${wadText(owed)} ${name} now); use Repay and close`);
        // Rules v2 says the most a partial payment may be ("0": only all).
        if (isInt(pos.repay_max_partial) && amount > BigInt(pos.repay_max_partial)) {
          throw bad(BigInt(pos.repay_max_partial) === 0n
            ? 'This debt is already at the smallest loan: repay all of it'
            : `Repay all of it, or at most ${wadText(pos.repay_max_partial)} ${name}: what stays must be at least the smallest loan`);
        }
        // Before v2, the same rule from the pool's smallest loan.
        const least = borrowPool && !isInt(pos.repay_max_partial) ? minLoan(borrowPool) : null;
        const pb = book.prices[pos.borrow_asset];
        if (least != null && pb && usdOf(owed - amount, pb) < least) {
          throw bad(`That leaves ${wadText(owed - amount)} ${name} owed, under the ${usdText(least)} smallest loan. Repay all of it, or leave at least that much`);
        }
        have = await held();
      }
      if (have < amount) throw bad(`This wallet does not hold enough ${name} (that needs ${wadText(amount)})`);
      const collateral = BigInt(pos.collateral);
      // Repaying everything closes the position: the collateral comes back in
      // the same approval, as a second intent the chain applies right after.
      const closing = all && collateral > 0n;
      const after = !all && collPool && borrowPool ? lendPreview(book, collPool, collateral, borrowPool, owed - amount) : null;
      return {
        title: closing ? `Repay ${name} and close` : `Repay ${name}`,
        danger: false,
        rows: [
          ['You pay', `${wadText(amount)} ${name}`],
          ['Owed now', `${wadText(owed)} ${name}`],
          ...(after ? [['Owed after', `about ${wadText(owed - amount)} ${name}`], ...healthRows(after, cn)] : []),
          ...(closing ? [['You get back', `${wadText(collateral)} ${cn}, collected into this wallet`]] : []),
        ],
        note: all ? 'Anything paid over what is owed comes back to this wallet. If interest outgrows the payment before it lands, a little debt stays and the collateral waits for it.' : 'Debt keeps growing with interest.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(pos.borrow_asset), amount);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.lendRepayIntent({ borrower: ctx.identity.account, position: unhex(pos.id), amount, nonce: n, inputs, change }));
          const source = hex(mk.lendSource(ctx.identity.account, nonce));
          if (!closing) return { source };
          // Anything still owed (interest outran the payment) keeps the
          // collateral in: say how much, rather than fail the second step.
          const left = (await ledger.loadPositions(ctx.config, ctx.identity).catch(() => [])).find((x) => x.id === pos.id);
          if (left && left.state === 'open' && isInt(left.owed) && BigInt(left.owed) > 0n) {
            return { source, closed: false, dust: left.owed, note: `Repaid, but ${wadText(left.owed)} ${name} of interest is still owed; repay it to take the ${cn} out.` };
          }
          try {
            const back = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.lendRemoveCollateralIntent({ borrower: ctx.identity.account, position: unhex(pos.id), amount: collateral, nonce: n }));
            return { source, closed: true, collateral: hex(mk.lendSource(ctx.identity.account, back)) };
          } catch (e) {
            // The loan is repaid either way; say where the collateral is.
            return { source, closed: false, note: `Repaid. The collateral is still in the position (${e.message}); take it out under Positions.` };
          }
        },
      };
    },
  },

  zyn_lendAddCollateral: {
    kind: 'write',
    async prepare(ctx, p) {
      const pos = await ownPosition(ctx, p.position);
      const book = await lendBook(ctx);
      const name = book.name(pos.collateral_asset);
      const amount = amountOf(p.amount, 'amount');
      await mustHold(ctx, pos.collateral_asset, amount, name);
      const collPool = book.pools.find((x) => x.asset === pos.collateral_asset);
      const borrowPool = book.pools.find((x) => x.asset === pos.borrow_asset);
      const room = collPool && isInt(collPool.collateral_room) ? BigInt(collPool.collateral_room) : null;
      if (room != null && amount > room) throw bad(`${name} collateral is near its cap: at most ${wadText(room)} more fits now`);
      const after = collPool && borrowPool ? lendPreview(book, collPool, BigInt(pos.collateral) + amount, borrowPool, BigInt(pos.owed)) : null;
      return {
        title: `Add ${name} collateral`,
        danger: false,
        rows: [['You add', `${wadText(amount)} ${name}`], ['Collateral after', `${wadText(BigInt(pos.collateral) + amount)} ${name}`], ...(after ? healthRows(after, name) : [])],
        note: 'More collateral moves the liquidation price further away.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(pos.collateral_asset), amount);
          await ledger.submitIntent(ctx.config, ctx.identity, mk.lendAddCollateralIntent({ borrower: ctx.identity.account, position: unhex(pos.id), amount, inputs, change }));
          return { position: pos.id };
        },
      };
    },
  },

  zyn_lendRemoveCollateral: {
    kind: 'write',
    async prepare(ctx, p) {
      const pos = await ownPosition(ctx, p.position);
      const book = await lendBook(ctx);
      const name = book.name(pos.collateral_asset);
      const amount = p.amount === 'all' ? BigInt(pos.collateral) : amountOf(p.amount, 'amount');
      if (amount > BigInt(pos.collateral)) throw bad('More than the position holds');
      const collPool = book.pools.find((x) => x.asset === pos.collateral_asset);
      const borrowPool = book.pools.find((x) => x.asset === pos.borrow_asset);
      const left = BigInt(pos.collateral) - amount;
      const after = collPool && borrowPool && BigInt(pos.owed) > 0n ? lendPreview(book, collPool, left, borrowPool, BigInt(pos.owed)) : null;
      if (after && after.health != null && !after.allowed) throw bad(`That would leave the position over the ${collPool.max_ltv_bps / 100}% most ${name} collateral may borrow`);
      if (BigInt(pos.owed) > 0n && (collPool?.price_held || borrowPool?.price_held)) throw bad('Taking this collateral out waits for a held price to be confirmed');
      if (BigInt(pos.owed) > 0n && pairOf(book, pos.collateral_asset, pos.borrow_asset)?.prices_agree === false) throw bad('Taking collateral out is paused: Zyn\'s pool and the posted price disagree');
      return {
        title: `Take out ${name} collateral`,
        danger: BigInt(pos.owed) > 0n,
        rows: [['You take out', `${wadText(amount)} ${name}`], ['Collateral after', `${wadText(left)} ${name}`], ['Debt', `${wadText(pos.owed)} ${book.name(pos.borrow_asset)}`], ...(after ? healthRows(after, name) : [])],
        note: 'The chain refuses this if it would leave the position over its maximum.',
        run: async () => {
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.lendRemoveCollateralIntent({ borrower: ctx.identity.account, position: unhex(pos.id), amount, nonce: n }));
          return { source: hex(mk.lendSource(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  zyn_lendBid: {
    kind: 'write',
    async prepare(ctx, p) {
      if (!isHex(p.lot)) throw bad('lot must be 64 hex characters');
      const book = await lendBook(ctx);
      const lot = (book.m.lots || []).find((x) => x.lot === p.lot);
      if (!lot || !isHex(lot.borrow_asset) || !isHex(lot.collateral_asset) || !isInt(lot.price) || !isInt(lot.collateral)) throw bad('No such auction lot');
      const pay = amountOf(p.pay, 'pay');
      const [cn, bn] = [book.name(lot.collateral_asset), book.name(lot.borrow_asset)];
      if (isInt(lot.min_bid) && pay < BigInt(lot.min_bid)) throw bad(`The smallest bid on this lot is ${wadText(lot.min_bid)} ${bn}`);
      if (lot.bids_full === true && isInt(lot.outbid_above) && pay <= BigInt(lot.outbid_above)) throw bad(`This lot's bids are full; a new bid must pay more than ${wadText(lot.outbid_above)} ${bn}`);
      await mustHold(ctx, lot.borrow_asset, pay, bn);
      const price = BigInt(lot.price);
      const most = price > 0n ? (pay * WAD) / price : 0n;
      return {
        title: `Bid for ${cn} in a liquidation auction`,
        danger: false,
        rows: [
          ['You pay up to', `${wadText(pay)} ${bn}`],
          ['Price this epoch', `${wadText(price)} ${bn} per ${cn}`],
          ['You get up to', `${wadText(most)} ${cn}`],
        ],
        note: 'Every bid this epoch pays the same price. If bids want more than the lot has, each gets a share and the rest of the payment comes back.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(lot.borrow_asset), pay);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.lendBidIntent({ bidder: ctx.identity.account, lot: unhex(lot.lot), pay, nonce: n, inputs, change }));
          return { source: hex(mk.lendSource(ctx.identity.account, nonce)) };
        },
      };
    },
  },

  zyn_lendInsure: {
    kind: 'write',
    async prepare(ctx, p) {
      const book = await lendBook(ctx);
      if (book.m.rules !== 2) throw bad('Adding to insurance opens with lending rules v2 on this chain');
      const pool = lendPool(book, p.asset, 'asset');
      const amount = amountOf(p.amount, 'amount');
      const name = book.name(pool.asset);
      await mustHold(ctx, pool.asset, amount, name);
      return {
        title: `Add to the ${name} pool's insurance`,
        danger: false,
        rows: [
          ['You give', `${wadText(amount)} ${name}`],
          ['Insurance now', isInt(pool.insurance) ? `about ${wadText(pool.insurance)} ${name}` : 'not published'],
        ],
        note: 'A gift to the pool: it covers bad loans before lenders do. You get no shares and cannot take it back.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(pool.asset), amount);
          await ledger.submitIntent(ctx.config, ctx.identity, mk.lendInsureIntent({ donor: ctx.identity.account, asset: unhex(pool.asset), amount, inputs, change }));
          return { asset: pool.asset };
        },
      };
    },
  },

  zec_pay: {
    kind: 'write',
    async prepare(ctx, p) {
      if (!ctx.zec) throw new ProviderError(ERR.UNSUPPORTED, NO_ZEC);
      let req;
      if (p.uri) req = parsePaymentRequest(p.uri);
      else {
        if (typeof p.address !== 'string' || !p.address) throw bad('address is required');
        req = { address: p.address.trim(), zatoshi: zatoshiOf(String(p.amount ?? '')), memo: String(p.memo || ''), message: '' };
      }
      if (req.zatoshi == null || req.zatoshi <= 0) throw bad('The request names no amount');
      const net = ctx.config.zcashPrefix === 'u1' ? 'mainnet' : 'testnet';
      const shielded = req.address.startsWith(ctx.config.zcashPrefix);
      // Transparent: t1/t3 on mainnet, tm/t2 on testnet. Sapling (zs…) is not
      // something this wallet sends to.
      const transparent = (net === 'mainnet' ? /^t[13][a-km-zA-HJ-NP-Z1-9]{33}$/ : /^t[m2][a-km-zA-HJ-NP-Z1-9]{33}$/).test(req.address);
      if (/^z(s|testsapling)1/.test(req.address)) throw bad('That is a Sapling address; ask for a unified (u1…) or transparent address');
      if (!shielded && !transparent) throw bad(`That is not a ${net} Zcash address`);
      if (!shielded && req.memo) throw bad('A memo only reaches a shielded address');
      return {
        title: `Pay ${zecText(req.zatoshi)} ZEC`,
        rows: [
          ['To', req.address],
          ['Amount', `${zecText(req.zatoshi)} ZEC, plus the network fee`],
          ...(req.memo ? [['Memo', req.memo]] : []),
          ...(req.message ? [['The site says', req.message]] : []),
          ['Network', `Zcash ${net}`],
        ],
        note: 'A Zcash transaction from this wallet. Proving it takes about half a minute; keep this window open.',
        run: async (onStep) => {
          const account = await ctx.zecReady();
          const v = await account.send(req.address, req.zatoshi, req.memo, onStep);
          return { txid: v.txid };
        },
      };
    },
  },

  // -------------------------------------------------------------- bridges
  // A site's bridge page (Zyn Lend's) talks to Phantom or MetaMask itself;
  // Nap makes what only this wallet can — the one-time deposit code, and the
  // withdrawal — and says plainly that the other chain sees both.

  zyn_bridges: {
    kind: 'public',
    async run(ctx) {
      const st = await bridges.bridgeState(ctx.config);
      return {
        bps: Number(st.bps),
        zec: { asset: ctx.config.zecAsset, zcash: ctx.config.zcash },
        bridges: st.bridges.map((b) => ({
          key: b.key, symbol: b.symbol, zy: b.zy, chainName: b.chainName, decimals: b.decimals, network: b.network, asset: b.asset,
          live: b.live, waiting: b.waiting || null, issued: b.issued === null ? null : String(b.issued),
          vault: b.vault || null, rpc: b.rpc || null, cluster: b.cluster || null, chainId: b.chainId || null, explorer: b.explorer || null,
          capWei: b.capWei || null, custody: b.custody || null, safe: b.safe || null, multisig: b.multisig || null, chain: b.chain || null,
          token: b.token || null, assetId: b.assetId || null, faucet: !!b.faucet,
        })),
      };
    },
  },

  /// What to send, for a deposit into this wallet: SOL a memo, ETH the
  /// calldata, an ERC-20 (BOLD) the code and, given an amount, its approve
  /// and deposit calls, BTC an address (watched from now), ZEC this account's
  /// deposit address. The code names nobody; the other chain sees the sender.
  /// Each call gives a fresh code, of this bridge only (ledger.js bridgeMemo,
  /// audit 9 Oct 2026): ask once per deposit, right before it is made.
  zyn_bridgeDeposit: {
    kind: 'read',
    async run(ctx, p) {
      const key = String(p?.key || '');
      if (key === 'zec') {
        const r = await ledger.call(ctx.config, 'zyn_depositAddress', { account: ctx.identity.accountHex });
        if (typeof r?.address !== 'string') throw bad('The node has no deposit address for this account yet');
        return { key, address: r.address };
      }
      const b = bridges.bridgesOf(ctx.config).find((x) => x.key === key);
      if (!b) throw bad(`No ${key.toUpperCase() || 'such'} bridge on this network`);
      if (key === 'btc') return { key, address: await bridges.btcDepositAddress(ctx.config, ctx.identity, b) };
      if (b.token) {
        // A token the chain does not list, or its vault has not registered,
        // would be stuck in the vault: no code for it until both have.
        const live = (await bridges.bridgeState(ctx.config)).bridges.find((x) => x.key === key);
        if (!live?.live) throw bad(live?.waiting === 'vault' ? `The vault does not take ${b.symbol} yet` : `${b.symbol} deposits are not open on this network yet`);
      }
      const code = await bridges.depositCode(ctx.config, ctx.identity, key);
      if (key === 'sol') return { key, memo: `zyn:${code}`, vault: b.vault, rpc: b.rpc, cluster: b.cluster };
      if (b.token) {
        // An ERC-20 (BOLD): two transactions from the holder's wallet —
        // approve the vault for the amount, then deposit(code, assetId, amount).
        const out = { key, to: b.vault, token: b.token, chainId: b.chainId, assetId: b.assetId, decimals: b.decimals, code };
        if (p?.amount == null) return out;
        const raw = amountOf(p.amount, 'amount');
        const scale = 10n ** BigInt(18 - b.decimals);
        if (raw % scale !== 0n) throw bad(`${b.symbol} has ${b.decimals} decimal places`);
        const word = (v) => BigInt(v).toString(16).padStart(64, '0');
        const sel = (sig) => hex(keccak_256(new TextEncoder().encode(sig)).slice(0, 4));
        return {
          ...out,
          amount: String(raw / scale),
          calls: [
            { to: b.token, data: `0x${sel('approve(address,uint256)')}${word(BigInt(b.vault))}${word(raw / scale)}` },
            { to: b.vault, data: `0x${sel('deposit(bytes32,uint32,uint256)')}${code}${word(b.assetId)}${word(raw / scale)}` },
          ],
        };
      }
      const asset = new Uint8Array(32);
      new DataView(asset.buffer).setUint32(28, Number(b.assetId || 1));
      const selector = hex(keccak_256(new TextEncoder().encode('depositNative(bytes32,uint32)')).slice(0, 4));
      return { key, to: b.vault, chainId: b.chainId, data: `0x${selector}${code}${hex(asset)}`, capWei: b.capWei || null };
    },
  },

  /// SOL.zy / ETH.zy / BOLD.zy / BTC.zy / ZEC.zy back to their chain.
  zyn_bridgeWithdraw: {
    kind: 'write',
    async prepare(ctx, p) {
      const key = String(p?.key || '');
      const to = String(p?.to || '').trim();
      const amount = amountOf(p?.amount, 'amount');
      const st = await bridges.bridgeState(ctx.config);
      const fee = (amount * st.bps) / 10_000n;
      if (key === 'zec') {
        if (!to.startsWith(ctx.config.zcashPrefix) && !/^t[mu]?[1-9A-HJ-NP-Za-km-z]{30,40}$/.test(to)) throw bad('That is not a Zcash address for this network');
        await mustHold(ctx, ctx.config.zecAsset, amount + fee, 'ZEC.zy');
        return {
          title: 'Withdraw ZEC',
          danger: true,
          rows: [['You send', `${wadText(amount)} ZEC.zy`], ['Bridge fee', `${wadText(fee)} ZEC.zy`], ['To', to]],
          note: 'Paid from the vault once two custodians sign; the Zcash network fee comes out of the amount. A shielded address keeps the payout private.',
          run: async () => {
            const h = await holdings(ctx);
            // `exit`: the commitment its holder follows it by (ZynScan /api/exit).
            return { ok: true, exit: await bridges.withdrawZec(ctx.config, ctx.identity, h.held, to, wadText(amount)) };
          },
        };
      }
      const b = st.bridges.find((x) => x.key === key);
      if (!b || !b.live) throw bad(`No ${key.toUpperCase() || 'such'} bridge on this network`);
      try { bridges.checkBridgeOut(b, to, amount); } catch (e) { throw bad(e.message); }
      await mustHold(ctx, b.asset, amount + fee, b.zy);
      return {
        title: `Withdraw ${b.symbol}`,
        danger: true,
        rows: [['You send', `${wadText(amount)} ${b.zy}`], ['Bridge fee', `${wadText(fee)} ${b.zy}`], ['To', to], ['On', b.chainName]],
        note: `${b.chainName} will show this address receiving the amount from the vault${b.safe ? '; the Safe owners approve each payout, which can take hours' : b.multisig ? "; the multisig's owners approve each payout, which can take hours" : ''}.`,
        run: async () => {
          const h = await holdings(ctx);
          return { ok: true, exit: await bridges.bridgeOut(ctx.config, ctx.identity, h.held, b, to, amount, st.bps) };
        },
      };
    },
  },

  // -------------------------------------------------------- private channel
  // Through the pools (§158): SOL on Solana, ETH on Sepolia, BTC on Mezo as
  // mzBTC.zy. Fixed sizes, a zero-knowledge proof each way, spends submitted
  // by the relayer. The site talks to Phantom or MetaMask for the deposit
  // itself; Nap makes the notes and the proofs. `channel`: sol, eth or mzbtc.

  zyn_poolInfo: {
    kind: 'public',
    async run(ctx, p) {
      if (p?.channel) {
        const c = pool.channel(ctx.config, String(p.channel));
        return { ...(await pool.info(ctx.config, c)), channel: c.key, sizes: c.sizes.map(String) };
      }
      return { channels: pool.channels(ctx.config).map((c) => ({ channel: c.key, chain: c.chain, symbol: c.symbol, asset: c.zy, sizes: c.sizes.map(String) })) };
    },
  },

  /// The hash a private deposit receipt carries for one of this wallet's pool
  /// notes: it commits to the note with a salt only this wallet derives, so
  /// its holder can open it later and nobody else can match it to the deposit.
  zyn_receiptHash: {
    kind: 'read',
    async run(ctx, p) {
      if (!isHex(p?.commitment)) throw bad('commitment: 64 hex characters');
      const chain = String(p?.chain || '');
      if (!['sol', 'evm'].includes(chain)) throw bad('chain: sol or evm');
      const te = new TextEncoder();
      const c = unhex(p.commitment);
      const salt = sha256(new Uint8Array([...te.encode('zyn-receipt.salt.v1'), ...ctx.identity.secretKey, ...c]));
      const hash = sha256(new Uint8Array([...te.encode('zyn-receipt.private.v1'), ...te.encode(chain), ...c, ...salt]));
      return { hash: hex(hash) };
    },
  },

  /// This wallet's private-channel notes, once the holder allows it (scope
  /// `notes`), as siteNotes trims them.
  zyn_poolNotes: {
    kind: 'read',
    scope: 'notes',
    async run(ctx) { return { notes: siteNotes(await pool.notes(ctx.config, ctx.identity)) }; },
  },

  /// A fresh note to deposit into the `size` pool from any wallet on its chain.
  zyn_poolDeposit: {
    kind: 'read',
    async run(ctx, p) {
      const c = channelOf(ctx, p);
      const size = sizeIn(c, p?.size);
      const i = await pool.info(ctx.config, c);
      const address = (i.pools || []).find((x) => String(x.size) === String(size))?.address;
      if (!address) throw bad(`No ${pool.sizeText(c, size)} pool`);
      const note = await pool.newNote(ctx.config, ctx.identity, c, size, 'in');
      return { channel: c.key, commitment: note.commitment, size: String(size), program: i.program, pool: address, chain: c.chain };
    },
  },

  zyn_poolToZyn: {
    kind: 'write',
    async prepare(ctx, p) {
      if (!isHex(p?.commitment)) throw bad('commitment: 64 hex characters');
      const n = (await pool.notes(ctx.config, ctx.identity)).find((x) => x.commitment === p.commitment);
      if (!n) throw bad('No such note in this wallet');
      if (n.state !== 'in pool') throw bad(['to zyn', 'sent', 'spent'].includes(n.state) ? 'That note is already spent' : 'That note is not in its pool yet; try again once it is confirmed');
      const c = pool.channel(ctx.config, n.ch);
      const amount = pool.sizeText(c, n.size);
      return {
        title: `Move ${amount} into Zyn`,
        danger: false,
        rows: [['From', `a ${amount} note in the ${c.chainName} pool`], ['Arrives as', `${amount.split(' ')[0]} ${c.zy}, less the bridge fee`]],
        note: 'Nap proves the note is one of the pool\'s without saying which; the relayer submits it, so no wallet of yours appears.',
        run: async () => pool.toZyn(ctx.config, ctx.identity, p.commitment),
      };
    },
  },

  zyn_poolWithdraw: {
    kind: 'write',
    async prepare(ctx, p) {
      const c = channelOf(ctx, p);
      const size = sizeIn(c, p?.size);
      const st = await bridges.bridgeState(ctx.config);
      const registered = (await ledger.loadBridged(ctx.config)).some((x) => x.asset === c.asset);
      if (!registered) throw bad(`${c.zy} is not bridged on this network`);
      const raw = pool.wadOf(c, size);
      const fee = (raw * st.bps) / 10_000n;
      await mustHold(ctx, c.asset, raw + fee, c.zy);
      const amount = pool.sizeText(c, size);
      return {
        title: `Withdraw ${amount} privately`,
        danger: true,
        rows: [['You send', `${wadText(raw)} ${c.zy}`], ['Bridge fee', `${wadText(fee)} ${c.zy}`], ['Becomes', `a ${amount} note in the ${c.chainName} pool`]],
        note: `The bridge puts the note into the pool; then send it to any ${c.chainName} address. Nobody, the operator included, learns that address.`,
        run: async () => {
          const h = await holdings(ctx);
          const note = await pool.withdraw(ctx.config, ctx.identity, h.held, c, size, st.bps);
          return { channel: c.key, commitment: note.commitment, size: String(size) };
        },
      };
    },
  },

  zyn_poolSend: {
    kind: 'write',
    async prepare(ctx, p) {
      if (!isHex(p?.commitment)) throw bad('commitment: 64 hex characters');
      const n = (await pool.notes(ctx.config, ctx.identity)).find((x) => x.commitment === p.commitment);
      if (!n) throw bad('No such note in this wallet');
      if (n.state !== 'in pool') throw bad(['to zyn', 'sent', 'spent'].includes(n.state) ? 'That note is already spent' : 'That note is not in its pool yet');
      const c = pool.channel(ctx.config, n.ch);
      const to = String(p?.to || '').trim();
      try { pool.recipientOf(c, to); } catch (e) { throw bad(e.message); }
      const i = await pool.info(ctx.config, c);
      const fee = BigInt(i.fee);
      return {
        title: `Send ${pool.sizeText(c, n.size)} to an address`,
        danger: true,
        rows: [['To', to], ['Relayer fee', pool.sizeText(c, fee)], ['Arrives', pool.sizeText(c, BigInt(n.size) - fee)]],
        note: `${c.chainName} shows the address receiving from the pool, not from you. Use an address never linked to the one you deposited from.`,
        run: async () => pool.sendOut(ctx.config, ctx.identity, p.commitment, to),
      };
    },
  },

  zyn_nftBuy: {
    kind: 'write',
    async prepare(ctx, p) {
      if (!isHex(p.item)) throw bad('item must be the listing\'s 64-hex item');
      const offers = await ledger.loadOffers(ctx.config);
      const o = offers.find((x) => x.item === p.item && x.serial >= 0);
      if (!o) throw bad('That listing is gone');
      const pay = BigInt(o.pay_raw);
      // The site shows a price; the chain has one. If they differ the holder
      // would be approving a number they were not shown.
      if (p.pay != null && amountOf(p.pay, 'pay') !== pay) throw bad('The price changed since the page loaded; reload and try again');
      const q = await quoteName(ctx, o.price_asset);
      await mustHold(ctx, o.price_asset, pay, q);
      return {
        title: `Buy ${itemName(o.collection, o.serial)}`,
        rows: [['Price', `${wadText(o.price_raw)} ${q}`], ['Collection fee', `${wadText(o.fee_raw)} ${q}`], ['You pay', `${wadText(pay)} ${q}`]],
        note: 'The item arrives in this wallet. The seller is paid by the ledger; you never learn who they are.',
        run: async () => {
          const h = await holdings(ctx);
          const { inputs, change } = mk.fund(ctx.identity, h.held, unhex(o.price_asset), pay);
          const item = mk.selfNote(ctx.identity, unhex(o.asset), mk.ITEM_UNIT);
          await ledger.submitIntent(ctx.config, ctx.identity, mk.takeOfferIntent({
            buyer: ctx.identity.account, item: unhex(o.item), itemNullifier: unhex(o.nullifier), payment: inputs, outputs: [item, ...change],
          }));
          return { bought: o.asset };
        },
      };
    },
  },

  zyn_nftList: {
    kind: 'write',
    async prepare(ctx, p) {
      const price = amountOf(p.price, 'price');
      if (price <= 0n) throw bad('price must be above zero');
      const h = await holdings(ctx);
      const { note, item } = heldItem(h, p.asset);
      if (h.offers.some((o) => o.item === note.commitment)) throw bad('That item is already listed');
      const market = await ledger.call(ctx.config, 'zyn_market');
      const terms = (market.collections || []).find((c) => c.asset === item.collection);
      const quote = terms && isHex(terms.quote) ? terms.quote : ctx.config.zecAsset;
      const feeBps = terms ? Number(terms.fee_bps) || 0 : 0;
      const q = (await namer(ctx, market))(quote);
      return {
        title: `List ${itemName(item.collection, item.serial)}`,
        rows: [['Price', `${wadText(price)} ${q}`], ['Fee', feeBps ? `${feeBps / 100}% from each side` : 'none'], ['You receive', `${wadText(price - (price * BigInt(feeBps)) / 10_000n)} ${q} when it sells`]],
        note: 'The listing names no seller. When it sells, your proceeds wait as a claim only this wallet can find.',
        run: async () => {
          const c = unhex(note.commitment);
          await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.listIntent({
            seller: ctx.identity.account, item: c, itemNullifier: nullifierOf(ctx.identity.nullifier, c),
            priceAsset: unhex(quote), priceAmount: price, expiresAtEpoch: 0xffffffffn, nonce: n,
          }));
          return { listed: note.asset };
        },
      };
    },
  },

  zyn_nftCancel: {
    kind: 'write',
    async prepare(ctx, p) {
      const h = await holdings(ctx);
      const { note, item } = heldItem(h, p.asset);
      if (!h.offers.some((o) => o.item === note.commitment)) throw bad('That item is not listed');
      return {
        title: `Cancel the listing of ${itemName(item.collection, item.serial)}`,
        rows: [['Item', itemName(item.collection, item.serial)]],
        note: 'The item stays in your wallet and can be moved again.',
        run: async () => {
          await ledger.submitIntent(ctx.config, ctx.identity, mk.cancelOfferIntent({ seller: ctx.identity.account, item: unhex(note.commitment) }));
          return { cancelled: note.asset };
        },
      };
    },
  },

  zyn_nftRedeem: {
    kind: 'write',
    async prepare(ctx, p) {
      const h = await holdings(ctx);
      const { note, item } = heldItem(h, p.asset);
      const market = await ledger.call(ctx.config, 'zyn_market');
      const terms = (market.collections || []).find((c) => c.asset === item.collection);
      if (!terms || !(BigInt(terms.outstanding || '0') > 0n)) throw bad('This collection has no floor to redeem from yet');
      const share = BigInt(terms.floor) / BigInt(terms.outstanding);
      if (share <= 0n) throw bad('The floor is empty; redeeming now would burn the item for nothing');
      const q = (await namer(ctx, market))(terms.quote);
      return {
        title: `Redeem ${itemName(item.collection, item.serial)} for the floor`,
        rows: [['Floor share', `${wadText(share)} ${q}`], ['The item', 'is burned — this cannot be undone']],
        note: 'Your share of the floor waits as a claim; collect it afterwards.',
        danger: true,
        run: async () => {
          const c = unhex(note.commitment);
          await ledger.submitIntent(ctx.config, ctx.identity, mk.redeemIntent({
            holder: ctx.identity.account, collection: unhex(item.collection), inputs: [{ commitment: c, nullifier: nullifierOf(ctx.identity.nullifier, c) }],
          }));
          return { redeemed: note.asset };
        },
      };
    },
  },

  // A collection's DAO (§172, §173): a member pass, a proposal, a vote. Each
  // is proved by this wallet's own items of the collection. The public sees
  // tallies and pass hashes; the operator and replicas see which item acted —
  // said on every card.
  zyn_daoPass: {
    kind: 'write',
    async prepare(ctx, p) {
      const collection = saleCollection(p);
      const mine = await daoItems(ctx, collection);
      // The pass an item already has is used again: nothing new to register.
      const tokenOf = (x) => mk.passToken(ctx.identity.secretKey, unhex(collection), unhex(x.note.commitment));
      const isLive = async (x) => !!(await ledger.call(ctx.config, 'zyn_memberPass', { collection, pass: hex(mk.daoPass(tokenOf(x))) }).catch(() => null))?.member;
      let pick = null;
      for (const x of mine.slice(0, 8)) if (await isLive(x)) { pick = x; break; }
      const live = !!pick;
      const { note, item } = pick || mine[0];
      return {
        title: 'Member pass',
        rows: [['Collection', collectionLabel(collection)], ['Proved by', itemName(collection, item.serial)], ['Pass', live ? 'already registered: nothing new on the ledger' : 'registered on the ledger now']],
        note: "The pass code opens the members' chat. Keep it private: whoever has it can use your membership. Selling or moving the item ends the pass. The operator and replicas can see which item made it, and the Cave team, which runs the chat, could link the two.",
        run: async () => {
          const token = tokenOf({ note });
          const pass = mk.daoPass(token);
          if (!live) await ledger.submitIntent(ctx.config, ctx.identity, mk.memberPassIntent({ holder: ctx.identity.account, collection: unhex(collection), item: unhex(note.commitment), pass }));
          return { token: hex(token), pass: hex(pass) };
        },
      };
    },
  },

  zyn_daoPropose: {
    kind: 'write',
    async prepare(ctx, p) {
      const collection = saleCollection(p);
      const text = String(p?.text ?? '').trim();
      if (!text || text.length > 4000) throw bad('A proposal is 1 to 4,000 characters');
      if (p?.track === 'zyn' && p?.pay) throw bad('A Zyn proposal pays nothing from the treasury');
      let pay = null;
      if (p?.pay) {
        if (!isHex(p.pay.asset) || !isHex(p.pay.to)) throw bad('pay.asset and pay.to must be 64 hex characters');
        let amount;
        try { amount = parseAmount(p.pay.amount); } catch (e) { throw bad(e.message); }
        if (amount <= 0n) throw bad('A payment must be worth something');
        pay = { asset: unhex(p.pay.asset), amount, to: unhex(p.pay.to), shown: `${wadText(amount)} ${await quoteName(ctx, p.pay.asset)} to ${shortHex(p.pay.to)}` };
      }
      const dao = await ledger.call(ctx.config, 'zyn_dao', { collection });
      if (!dao?.set) throw bad('That collection has no DAO');
      // The Zyn track (§176): members vote on Zyn's issues; it pays nothing,
      // and the team's own account casts a vote the track's rule weighs.
      const zyn = p?.track === 'zyn';
      if (p?.track !== undefined && p.track !== 'zyn' && p.track !== 'collection') throw bad("track must be 'collection' or 'zyn'");
      if (zyn && !dao.zyn) throw bad('This DAO does not vote on Zyn issues yet');
      const mine = await daoItems(ctx, collection);
      const hash = sha256(new TextEncoder().encode(text));
      const item = unhex(mine[0].note.commitment);
      return {
        title: zyn ? 'Zyn proposal' : 'Proposal',
        rows: [
          ['Says', text],
          zyn ? ['Team vote', teamRule(dao.zyn)] : ['Treasury pays', pay ? pay.shown : 'nothing'],
          ['Needs', `${dao.backers} backing item${dao.backers === 1 ? '' : 's'}, then a vote`],
          ['Backed by', 'one of your items'],
        ],
        note: 'The proposal, its text and any payment are public. The operator and replicas can see which item backed it.',
        run: async () => {
          await ledger.submitIntent(ctx.config, ctx.identity, zyn
            ? mk.proposeZynIntent({ proposer: ctx.identity.account, collection: unhex(collection), item, text: hash })
            : mk.proposeIntent({ proposer: ctx.identity.account, collection: unhex(collection), item, text: hash, pay: pay && { asset: pay.asset, amount: pay.amount, to: pay.to } }));
          // Which track it went on, so a site can tell an older Nap (which
          // ignores `track`) from this one.
          return { text: hex(hash), track: zyn ? 'zyn' : 'collection' };
        },
      };
    },
  },

  zyn_daoVote: {
    kind: 'write',
    async prepare(ctx, p) {
      const collection = saleCollection(p);
      const id = Number(p?.proposal);
      if (!Number.isSafeInteger(id) || id < 1 || id > 0xffffffff) throw bad('proposal must be a proposal number');
      const choice = { back: mk.DAO_BACK, yes: mk.DAO_YES, no: mk.DAO_NO }[p?.choice];
      if (choice === undefined) throw bad('choice must be back, yes or no');
      // What is voted on is read here, from the chain, not taken from the page.
      const dao = await ledger.call(ctx.config, 'zyn_dao', { collection });
      const prop = (dao?.proposals || []).find((x) => x.id === id);
      if (!prop) throw bad(`There is no proposal #${id}`);
      const want = p.choice === 'back' ? 'backing' : 'voting';
      if (prop.state !== want) throw bad(`Proposal #${id} is ${prop.state}, not ${want === 'backing' ? 'gathering backers' : 'open for votes'}`);
      const mine = await daoItems(ctx, collection);
      const pays = prop.pay ? `${wadText(BigInt(prop.pay.amount))} ${await quoteName(ctx, prop.pay.asset)} to ${shortHex(prop.pay.to)}` : 'nothing';
      const word = { back: 'Back', yes: 'Vote yes on', no: 'Vote no on' }[p.choice];
      const zyn = prop.track === 'zyn';
      return {
        title: `${word} ${zyn ? 'Zyn ' : ''}proposal #${id}`,
        rows: [
          ['Text', `hash ${prop.text.slice(0, 16)}…`],
          zyn ? ['Team vote', `${teamRule(dao.zyn)}; so far ${prop.team === 'none' || !prop.team ? 'not cast' : prop.team}`] : ['Treasury pays', pays],
          ['Items', `${mine.length} of yours, one vote each; any that voted before are skipped`],
        ],
        note: 'The public sees the tally, not which items voted. The operator and replicas can see it.',
        run: async () => {
          // 32 items a vote: every chunk is sent, and one whose items all
          // acted before counts nothing rather than failing the rest.
          let counted = 0;
          for (let i = 0; i < mine.length; i += 32) {
            try {
              const r = await ledger.submitIntent(ctx.config, ctx.identity, mk.voteIntent({
                voter: ctx.identity.account, collection: unhex(collection), proposal: id, items: mine.slice(i, i + 32).map((x) => unhex(x.note.commitment)), choice,
              }));
              counted += Number(/Voted \{[^}]*items: (\d+)/.exec(String(r?.receipts || ''))?.[1] || 0);
            } catch (e) {
              if (!/every item has already/.test(e.message)) throw e;
            }
          }
          return { items: counted };
        },
      };
    },
  },

  // Collection Z's sale (§144): tickets in ZEC.zy, a lottery drawn after the
  // close, winners claim with a proof against the posted root, and whatever
  // is left sells in the posted order.
  zyn_saleInfo: {
    kind: 'public',
    run: async (ctx, p) => {
      const s = await ledger.loadSale(ctx.config, saleCollection(p));
      if (!s) return { sale: null };
      return { sale: s.sale, drawPosted: !!s.draw, openPosted: !!s.open, remaining: s.open ? s.sale.open_count - s.sale.open_next : null };
    },
  },
  // This wallet's place in a gated sale (§168): on the list or not, tickets
  // bought, and what the next ones cost. In an ungated sale, everyone's.
  zyn_saleAccess: {
    kind: 'read',
    run: async (ctx, p) => {
      const collection = saleCollection(p);
      const s = await ledger.loadSale(ctx.config, collection);
      if (!s) return { sale: null };
      const a = await saleAccess(ctx, collection);
      const prices = a.gated ? Array.from({ length: 20 }, (_, i) => String(mk.gatedPrice(s.sale.ticket_price, a.base, a.bought + i + 1))) : null;
      return { gated: a.gated, listed: a.listed, bought: a.bought, base: a.base, next: prices ? prices[0] : s.sale.ticket_price, prices, open: a.open };
    },
  },

  zyn_saleTickets: {
    kind: 'read',
    run: async (ctx, p) => {
      const collection = saleCollection(p);
      const [s, mine] = await Promise.all([ledger.loadSale(ctx.config, collection), ledger.loadTickets(ctx.config, ctx.identity, collection)]);
      const wins = new Map((s?.draw?.won || []).map((w) => [w.ticket, w.serials]));
      const drawn = !!s?.draw;
      return {
        tickets: mine.map((t) => ({
          ticket: t.ticket, index: t.index, claimed: t.claimed, burned: !!t.voucher,
          result: !drawn ? 'waiting' : t.claimed ? 'claimed' : wins.has(t.ticket) ? 'won' : 'no win',
          serials: wins.get(t.ticket) || [],
          names: (wins.get(t.ticket) || []).map((x) => itemName(collection, x)),
        })),
      };
    },
  },

  // The memo that makes a burn of the sale's promotional token on Solana
  // into this wallet's tickets (§145). It names no account: the commitment
  // binds this one without saying which. Nothing moves, so no approval.
  zyn_burnMemo: {
    kind: 'read',
    run: async (ctx, p) => ledger.burnMemo(ctx.config, ctx.identity, { fresh: p?.fresh === true }),
  },

  // Sale credit (§182): burns of ZCAVE or REGI become credit in the sale,
  // worth what was burned; it pays tickets, claims and the open mint before
  // any ZEC.zy. What this wallet holds and what waits for it to take up.
  zyn_saleCredit: {
    kind: 'read',
    run: async (ctx, p) => {
      const c = await ledger.loadCredit(ctx.config, ctx.identity, saleCollection(p));
      return { held: String(c.held), waiting: String(c.waiting), budget: String(c.budget) };
    },
  },
  // Taking credit up only moves it into this wallet's own place in the sale,
  // so a connected site may ask without an approval each time.
  zyn_takeUpCredit: {
    kind: 'auto',
    run: async (ctx, p) => ({ held: String(await ledger.takeUpCredit(ctx.config, ctx.identity, saleCollection(p))) }),
  },

  zyn_buyTickets: {
    kind: 'write',
    async prepare(ctx, p) {
      const collection = saleCollection(p);
      const count = Number(p.count ?? 1);
      if (!Number.isInteger(count) || count < 1 || count > 20) throw bad('Buy between 1 and 20 tickets at a time');
      const s = await ledger.loadSale(ctx.config, collection);
      if (!s) throw bad('There is no sale for that collection');
      if (s.sale.phase !== 'open') throw bad('The sale is closed');
      // A gated sale (§168): this account must be on the list, and pays
      // more for each ticket past the base.
      const a = await saleAccess(ctx, collection);
      if (!a.listed) throw bad('This wallet is not on the sale\'s list. Link your whitelist code to it first.');
      const total = a.gated ? mk.gatedTotal(s.sale.ticket_price, a.base, a.bought, count) : BigInt(s.sale.ticket_price) * BigInt(count);
      if (p.pay != null && amountOf(p.pay, 'pay') !== total) throw bad('The price changed since the page loaded; reload and try again');
      const q = await quoteName(ctx, s.quote);
      const credit = await creditOf(ctx, collection);
      const fromCredit = credit < total ? credit : total;
      if (total > fromCredit) await mustHold(ctx, s.quote, total - fromCredit, q);
      const each = a.gated ? Array.from({ length: count }, (_, i) => mk.gatedPrice(s.sale.ticket_price, a.base, a.bought + i + 1)) : null;
      const rising = each && each.some((x) => x !== BigInt(s.sale.ticket_price));
      return {
        title: `Buy ${count} ticket${count > 1 ? 's' : ''} in the ${collection === CAVE_Z ? 'Collection Z' : `${collection.slice(0, 6)}…`} sale`,
        rows: [
          ['Per ticket', rising ? `${each.map((x) => wadText(x)).join(', ')} ${q}` : `${wadText(s.sale.ticket_price)} ${q}`],
          ['Tickets', a.gated ? `${count} (your ${a.bought + 1}${count > 1 ? `–${a.bought + count}` : ''})` : String(count)],
          ...(a.gated ? [['Price rule', `${wadText(s.sale.ticket_price)} each for your first ${a.base}, then ${wadText(s.sale.ticket_price)} more for each one after`]] : []),
          ...creditRows(fromCredit, total, q),
        ],
        note: 'Each ticket is drawn after the sale closes. A winning ticket claims its items at the claim price; the ticket price is not refunded.',
        run: async () => {
          const held = await ledger.takeUpCredit(ctx.config, ctx.identity, collection);
          const { inputs, change } = await notesFor(ctx, s.quote, total, held);
          const nonce = await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.buyTicketsIntent({
            buyer: ctx.identity.account, collection: unhex(collection), count, nonce: n, inputs, change,
          }));
          return { tickets: Array.from({ length: count }, (_, k) => hex(mk.ticketId(ctx.identity.account, nonce, k))) };
        },
      };
    },
  },

  zyn_claimItems: {
    kind: 'write',
    async prepare(ctx, p) {
      const collection = saleCollection(p);
      const s = await ledger.loadSale(ctx.config, collection);
      if (!s || s.sale.phase !== 'drawn') throw bad('Claims open after the draw is posted and close when the open mint starts');
      if (!s.draw) throw bad('The posted draw does not match the chain; nothing can be claimed until it does');
      const index = new Map(s.draw.won.map((w, i) => [w.ticket, i]));
      let mine = (await ledger.loadTickets(ctx.config, ctx.identity, collection)).filter((t) => !t.claimed && index.has(t.ticket));
      if (!mine.length) throw bad('This wallet has no unclaimed winning tickets');
      // In a gated sale (§168) a burn ticket is claimed only from a listed account.
      const access = await saleAccess(ctx, collection);
      if (!access.listed) {
        const before = mine.length;
        mine = mine.filter((t) => !t.voucher);
        if (!mine.length) throw bad('Burn tickets in this sale are claimed only from a wallet on the sale\'s list. Link your whitelist code to this wallet first.');
      }
      const serials = mine.flatMap((t) => s.draw.won[index.get(t.ticket)].serials);
      const total = BigInt(s.sale.claim_price) * BigInt(serials.length);
      const q = await quoteName(ctx, s.quote);
      const credit = await creditOf(ctx, collection);
      const fromCredit = credit < total ? credit : total;
      if (total > fromCredit) await mustHold(ctx, s.quote, total - fromCredit, q);
      return {
        title: `Claim ${serials.length} item${serials.length > 1 ? 's' : ''}`,
        rows: [...serials.slice(0, 6).map((x) => ['Item', itemName(collection, x)]), ...(serials.length > 6 ? [['…', `and ${serials.length - 6} more`]] : []),
          ['Per item', `${wadText(s.sale.claim_price)} ${q}`], ...creditRows(fromCredit, total, q)],
        note: 'Each item is minted straight into this wallet. Unclaimed wins go to the open mint when claims close.',
        run: async () => {
          const claimed = [];
          let spent = [];
          let credit = await ledger.takeUpCredit(ctx.config, ctx.identity, collection);
          for (const t of mine) {
            if (spent.length) await ledger.waitSpent(ctx.config, ctx.identity, spent);
            const i = index.get(t.ticket);
            const won = s.draw.won[i].serials;
            const price = BigInt(s.sale.claim_price) * BigInt(won.length);
            const { inputs, change } = await notesFor(ctx, s.quote, price, credit);
            credit = credit > price ? credit - price : 0n;
            const claim = {
              buyer: ctx.identity.account, collection: unhex(collection), k: t.k, serials: won,
              proof: mk.merkleProof(s.draw.leaves, i),
              items: won.map((x) => mk.selfNote(ctx.identity, mk.itemAsset(unhex(collection), x), mk.ITEM_UNIT)), inputs, change,
            };
            // A burn ticket is claimed by revealing the secret its memo committed to.
            await ledger.submitIntent(ctx.config, ctx.identity, t.voucher
              ? mk.claimVoucherItemsIntent({ ...claim, secret: t.nonce })
              : mk.claimItemsIntent({ ...claim, nonce: t.nonce }));
            spent = inputs.map((x) => hex(x.commitment));
            claimed.push(...won);
          }
          return { claimed };
        },
      };
    },
  },

  zyn_mintOpen: {
    kind: 'write',
    async prepare(ctx, p) {
      const collection = saleCollection(p);
      const count = Number(p.count ?? 1);
      if (!Number.isInteger(count) || count < 1 || count > 20) throw bad('Mint between 1 and 20 at a time');
      const s = await ledger.loadSale(ctx.config, collection);
      if (!s || s.sale.phase !== 'openmint') throw bad('The open mint has not started');
      if (!s.open) throw bad('The posted order does not match the chain; nothing can be minted until it does');
      const left = s.sale.open_count - s.sale.open_next;
      if (left < count) throw bad(left ? `Only ${left} left` : 'The open mint is sold out');
      // §187: what this wallet pays per item, and how many more it may mint.
      const a = await saleAccess(ctx, collection);
      const price = BigInt(a.open?.price ?? s.sale.open_price);
      if (a.open) {
        const mine = a.open.cap - a.open.minted;
        if (mine <= 0) throw bad(`This wallet has minted ${a.open.cap}, the most one wallet may`);
        if (count > mine) throw bad(`This wallet may mint ${mine} more`);
      }
      const total = price * BigInt(count);
      const q = await quoteName(ctx, s.quote);
      const credit = await creditOf(ctx, collection);
      const fromCredit = credit < total ? credit : total;
      if (total > fromCredit) await mustHold(ctx, s.quote, total - fromCredit, q);
      return {
        title: `Mint ${count} from the open mint`,
        rows: [
          ['Per item', `${wadText(String(price))} ${q}${price < BigInt(s.sale.open_price) ? ' (whitelist)' : ''}`],
          ['Items', String(count)],
          ...creditRows(fromCredit, total, q),
          ...(a.open ? [['This wallet', `${a.open.minted + count} of ${a.open.cap} after this`]] : []),
          ['Left', String(left)],
        ],
        note: 'Items come in the order fixed when the mint opened — the next ones in line, whichever they are.',
        run: async () => {
          const minted = [];
          let spent = [];
          await ledger.takeUpCredit(ctx.config, ctx.identity, collection);
          // The chain takes 12 intents from one account an epoch (fair
          // batches, §179): a longer run waits for the next epoch there.
          let waits = 0;
          const nextEpoch = async () => {
            const was = Number((await ledger.call(ctx.config, 'zyn_status')).epoch);
            for (let i = 0; i < 120; i++) {
              await new Promise((r) => setTimeout(r, 1000));
              if (Number((await ledger.call(ctx.config, 'zyn_status')).epoch) > was) return;
            }
          };
          for (let got = 0, tries = 0; got < count && tries < count + 8; tries++) {
            if (spent.length) await ledger.waitSpent(ctx.config, ctx.identity, spent);
            const now = await ledger.loadSale(ctx.config, collection);
            const pos = now.sale.open_next;
            if (pos >= now.sale.open_count) break;
            const serial = s.open.order[pos];
            // What credit is left after the last mint, read from the chain.
            const credit = (await ledger.loadCredit(ctx.config, ctx.identity, collection)).held;
            const { inputs, change } = await notesFor(ctx, s.quote, price, credit);
            const item = mk.selfNote(ctx.identity, mk.itemAsset(unhex(collection), serial), mk.ITEM_UNIT);
            try {
              await ledger.submitFresh(ctx.config, ctx.identity, (n) => mk.mintOpenIntent({
                buyer: ctx.identity.account, collection: unhex(collection), serial, proof: mk.merkleProof(s.open.leaves, pos), item, nonce: n, inputs, change,
              }));
            } catch (e) {
              // Someone else minted that place first; take the next one.
              if (/not the next item|already minted/.test(String(e.message))) continue;
              if (/as many as one account may/.test(String(e.message))) break;
              if (/its share of this epoch's intents/.test(String(e.message)) && waits++ < 4) { tries--; await nextEpoch(); continue; }
              throw e;
            }
            spent = inputs.map((x) => hex(x.commitment));
            minted.push(serial);
            got++;
          }
          if (!minted.length) throw new Error('The open mint sold out first');
          return { minted, names: minted.map((x) => itemName(collection, x)) };
        },
      };
    },
  },

  // Collecting only moves what the ledger owes this wallet into it, so a
  // connected site may ask without an approval each time — trades then
  // simply arrive, as they do on any launchpad.
  zyn_collect: {
    kind: 'auto',
    run: async (ctx) => {
      const owed = await ledger.loadOwed(ctx.config, ctx.identity);
      for (let i = 0; i < owed.length; i += ledger.PER_CLAIM) {
        await ledger.submitIntent(ctx.config, ctx.identity, mk.claimIntent(mk.redeem(ctx.identity, owed.slice(i, i + ledger.PER_CLAIM))));
      }
      // Deposits from other chains waiting for this wallet (§146).
      const arrived = await ledger.claimWaiting(ctx.config, ctx.identity).catch(() => 0);
      return { collected: owed.length + arrived };
    },
  },

};

export { forgetIdentity, hex };
