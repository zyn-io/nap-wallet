// The market's wire format, held to the bytes Rust produces.
//
// Every id and every intent in the fixture's `market` section was printed by
// `zyn-object-vectors` from the VM's own encoder. An intent this file encodes
// differently is one the VM refuses — or, if only a program id moved, runs
// under a rule the holder did not sign for.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { hex, unhex } from '../src/object.js';
import * as m from '../src/market.js';

const here = dirname(fileURLToPath(import.meta.url));
const v = JSON.parse(readFileSync(join(here, 'object-vectors.json'), 'utf8')).market;
const W = (n) => BigInt(n) * m.WAD;

const ZEC = unhex(v.zec), TOKEN = unhex(v.token), OWNER = unhex(v.owner), NONCE = unhex(v.nonce);
const change = [{
  note: { asset: ZEC, amount: W(2), owner: OWNER, nonce: unhex(v.change_nonce) },
  enc: { epk: unhex(v.change_epk), ciphertext: unhex(v.change_ciphertext) },
}];
const inputs = [
  { commitment: new Uint8Array(32).fill(0xc1), nullifier: new Uint8Array(32).fill(0xd1) },
  { commitment: new Uint8Array(32).fill(0xc2), nullifier: new Uint8Array(32).fill(0xd2) },
];

test('the market program ids match the Rust side', () => {
  assert.equal(m.MARKET_PROGRAM.ammSwap, v.program_amm_swap);
  assert.equal(m.MARKET_PROGRAM.addLiquidity, v.program_add_liquidity);
  assert.equal(m.MARKET_PROGRAM.removeLiquidity, v.program_remove_liquidity);
  assert.equal(m.MARKET_PROGRAM.claim, v.program_claim);
  assert.equal(m.MARKET_PROGRAM.launchCreate, v.program_launch_create);
  assert.equal(m.MARKET_PROGRAM.launchCommit, v.program_launch_commit);
});

/// A wallet finds its claims only by deriving their ids. One derivation off
/// and the claim is still there, owed, and invisible.
test('every derived id matches the Rust side', () => {
  const pool = m.poolId(ZEC, TOKEN);
  assert.equal(hex(pool), v.pool_id);
  assert.equal(hex(m.poolId(TOKEN, ZEC)), v.pool_id, 'a pool is the same pool either way round');
  assert.equal(hex(m.lpAsset(pool)), v.lp_asset);
  assert.equal(hex(m.tokenOf(OWNER, NONCE)), v.token_of);
  assert.equal(hex(m.launchSource(OWNER, NONCE)), v.launch_source);
  const order = m.orderId(OWNER, NONCE);
  assert.equal(hex(order), v.order_id);
  assert.equal(hex(m.commitId(OWNER, NONCE)), v.commit_id);
  assert.equal(hex(m.liquidityId(OWNER, NONCE)), v.liquidity_id);
  assert.equal(hex(m.claimId(order, 0)), v.claim_id_order_0);
  const route = m.routeId(OWNER, NONCE);
  assert.equal(hex(route), v.route_id);
  assert.equal(hex(m.routeLegId(route, 1)), v.route_leg_1);
  assert.equal(m.MARKET_PROGRAM.route, v.program_route);
});

test('a route\'s preview is each hop\'s preview, fed by the one before', () => {
  const pool = { reserve_a: String(20n * m.WAD), reserve_b: String(40n * m.WAD), fee_bps: 30 };
  const coin = { sold: 200, fee_bps: 100, unit: String(m.ZAT) };
  const venues = { pool: () => pool, curve: () => coin };
  const r = m.previewRoute([{ pool: 'p', sellA: true }, { curveBuy: 'b' }], m.WAD, venues);
  const zec = m.quoteAlone(pool, true, m.WAD);
  assert.deepEqual(r.steps, [zec, m.previewCurveBuy(200, zec, 100).tokens]);
  assert.equal(m.previewRoute([{ pool: 'p', sellA: true }], 0n, venues), null, 'nothing in, nothing out');
});

test('every market intent encodes to exactly the bytes Rust produces', () => {
  const pool = m.poolId(ZEC, TOKEN);
  const order = m.orderId(OWNER, NONCE);
  const cases = {
    create_pool: m.createPoolIntent({ provider: OWNER, assetA: ZEC, assetB: TOKEN, amountA: W(10), amountB: W(40), feeBps: 30, inputs, change, nonce: NONCE }),
    add_liquidity: m.addLiquidityIntent({ provider: OWNER, pool, amountA: W(1), amountB: W(4), minShares: 12345n, inputs, change, nonce: NONCE }),
    remove_liquidity: m.removeLiquidityIntent({ provider: OWNER, pool, shares: W(3), minA: 1n, minB: 2n, inputs, change, nonce: NONCE }),
    swap: m.swapIntent({ trader: OWNER, pool, sellA: true, amountIn: W(5), minOut: 4_900_000_000_000_000_000n, inputs, change, nonce: NONCE }),
    claim: m.claimIntent({ owner: OWNER, claims: [m.claimId(order, 0), m.claimId(order, 1)], outputs: change }),
    create_launch: m.createLaunchIntent({
      creator: OWNER, nonce: NONCE, quote: ZEC, totalSupply: W(1_000_000), saleSupply: W(600_000), poolSupply: W(200_000),
      softCap: W(10), hardCap: W(100), poolBps: 5000, feeBps: 30, closesAtEpoch: 4321, meta: new Uint8Array(32).fill(0x4d),
    }),
    commit: m.commitIntent({ buyer: OWNER, launch: TOKEN, amount: W(7), inputs, change, nonce: NONCE }),
    // A route (§167): a coin's curve, a pool, another coin's curve.
    route: m.routeIntent({
      trader: OWNER, hops: [{ curveSell: TOKEN }, { pool, sellA: false }, { curveBuy: new Uint8Array(32).fill(0xe1) }],
      amountIn: W(125_000), minOut: 4_900_000_000_000_000_000n, inputs, change, nonce: NONCE,
    }),
  };
  for (const [name, bytes] of Object.entries(cases)) assert.equal(hex(bytes), v[name], `${name} moved`);
});

/// The preview uses the VM's own formula and floors, so it never quotes more
/// than the ledger could pay a lone order.
test('a lone order is quoted at the batch price', () => {
  const pool = { reserve_a: W(1000).toString(), reserve_b: W(1000).toString(), fee_bps: 0 };
  assert.equal(m.quoteAlone(pool, true, W(100)), 83_333_333_333_333_333_333n);
  assert.equal(m.withSlippage(W(100), 50), W(995) / 10n);
});

test('a new pool opens with the geometric mean of its deposits', () => {
  assert.equal(m.geometricMean(W(100), W(400)), W(200));
  assert.equal(m.geometricMean(W(2), W(1)), 1_414_213_562_373_095_048n);
});

/// Nonces are the receipts. Derived, not random, so a restored wallet can
/// walk them and find its claims again.
test('market nonces are reproducible from the key and distinct per counter', () => {
  const key = new Uint8Array(32).fill(7);
  assert.equal(hex(m.marketNonce(key, 0)), hex(m.marketNonce(key, 0)));
  assert.notEqual(hex(m.marketNonce(key, 0)), hex(m.marketNonce(key, 1)));
});

/// A launch's name is public and chosen by its creator, so it is decoded
/// strictly: anything that is not exactly symbol ‖ name ‖ zeros shows as an id.
test('a launch name round-trips, and anything else does not decode', () => {
  const meta = m.encodeMeta({ symbol: 'mole', name: 'Nap Mole' });
  assert.deepEqual(m.decodeMeta(meta), { symbol: 'MOLE', name: 'Nap Mole' });
  assert.deepEqual(m.decodeMeta(hex(meta)), { symbol: 'MOLE', name: 'Nap Mole' });
  assert.equal(m.decodeMeta(new Uint8Array(32).fill(0xff)), null);
  assert.equal(m.decodeMeta(new Uint8Array(32)), null, "all zeros names nothing");
  const smuggled = meta.slice(); smuggled[31] = 0x41;
  assert.equal(m.decodeMeta(smuggled), null, 'bytes after the padding');
  const markup = meta.slice(); markup.set(new TextEncoder().encode('<img>'), 8);
  assert.deepEqual(m.decodeMeta(markup).name.startsWith('<img>'), true, 'printable — escaping is the renderer\'s job');
  assert.throws(() => m.encodeMeta({ symbol: 'TOOLONGSYM', name: 'x' }));
});

/// Leaving is the other half of the bridge, and the same bytes rule applies.
test('a Withdraw intent encodes to exactly the bytes Rust produces', async () => {
  const { withdrawIntent, PROGRAM } = await import('../src/object.js');
  assert.equal(PROGRAM.withdraw, v.program_withdraw);
  const bytes = withdrawIntent({ holder: OWNER, inputs, asset: ZEC, amount: W(3), destination: new Uint8Array(32).fill(0xde), outputs: change });
  assert.equal(hex(bytes), v.withdraw);
});

/// The NFT cycle's bytes and ids, held to Rust's.
test('item identity, listing sources and the NFT intents match the Rust side', () => {
  assert.equal(hex(m.itemAsset(TOKEN, 7)), v.item_asset_serial_7);
  assert.equal(hex(m.listingSource(OWNER, NONCE)), v.listing_source);
  const item = new Uint8Array(32).fill(0xc1);
  assert.equal(hex(m.saleFeeSource(item)), v.sale_fee_source);
  assert.equal(hex(m.redemptionSource(item)), v.redemption_source);
  assert.equal(hex(m.listIntent({
    seller: OWNER, item, itemNullifier: new Uint8Array(32).fill(0xd1), priceAsset: ZEC,
    priceAmount: W(2), expiresAtEpoch: 99_999, nonce: NONCE,
  })), v.list);
  assert.equal(hex(m.cancelOfferIntent({ seller: OWNER, item })), v.cancel_offer);
  assert.equal(hex(m.takeOfferIntent({ buyer: OWNER, item, itemNullifier: new Uint8Array(32).fill(0xd1), payment: inputs, outputs: change })), v.take_offer);
  assert.equal(hex(m.redeemIntent({ holder: OWNER, collection: TOKEN, inputs })), v.redeem);
});

// Bonding curves (DECISIONS §141): ids, intents and the curve's own prices,
// each held to the bytes and numbers objectvm::curve produces.
test('curve ids and intents match the Rust side', () => {
  assert.equal(m.MARKET_PROGRAM.curveCreate, v.program_curve_create);
  assert.equal(m.MARKET_PROGRAM.curveTrade, v.program_curve_trade);
  assert.equal(hex(m.curveSource(OWNER, NONCE)), v.curve_source);
  assert.equal(hex(m.curveOrderId(OWNER, NONCE)), v.curve_order_id);
  assert.equal(hex(m.tokenOf(OWNER, NONCE)), v.curve_token);
  assert.equal(hex(m.createCurveIntent({ creator: OWNER, nonce: NONCE, quote: ZEC, meta: new Uint8Array(32).fill(0x4d), inputs, change })), v.create_curve);
  assert.equal(hex(m.curveTradeIntent({ trader: OWNER, token: TOKEN, buy: true, amountIn: m.WAD, minOut: m.LOT, inputs, change, nonce: NONCE })), v.curve_trade);
});

test('the curve prices lots exactly as the ledger does', () => {
  assert.equal(m.curveCost(0, m.CURVE.graduateAt).toString(), v.curve_cost_to_graduation);
  assert.equal(m.curveCost(1000, 50).toString(), v.curve_cost_1000_50);
  // Sized for another coin (§166).
  assert.equal(m.GRADUATION_MC_UNITS.toString(), v.curve_graduation_mc_units);
  assert.equal(m.curveUnitFor(23n * m.WAD).toString(), v.curve_unit_23);
  assert.equal(m.curveUnitFor(63_000n * m.WAD).toString(), v.curve_unit_63000);
  assert.equal(m.curveCost(1000, 50, BigInt(v.curve_unit_23)).toString(), v.curve_cost_1000_50_at_23);
  assert.equal(m.curveCost(1000, 50, m.ZAT), m.curveCost(1000, 50), 'ZEC-sized is the default');
  // A lone buy never spends more than it put in, and one more lot is out of reach.
  const q = m.previewCurveBuy(1234, m.WAD / 10n, 100);
  assert.ok(q.paid + q.fee <= m.WAD / 10n && q.refund >= 0n);
  assert.ok(m.curveCost(1234, q.lots + 1) > (m.WAD / 10n) * 10_000n / 10_100n);
  // Selling what was just bought returns less than it cost (the curve is not a pump).
  const s = m.previewCurveSell(1234 + q.lots, q.lots, 100);
  assert.ok(s.net < q.paid + q.fee);
  // Nothing past graduation.
  assert.equal(m.previewCurveBuy(m.CURVE.graduateAt, m.WAD, 0).lots, 0);
});

test('primary sales: ids, leaves, the draw proof and the three holder intents match the ledger (§144)', () => {
  assert.equal(m.MARKET_PROGRAM.saleTickets, v.program_sale_tickets);
  assert.equal(m.MARKET_PROGRAM.saleClaim, v.program_sale_claim);
  assert.equal(m.MARKET_PROGRAM.saleMint, v.program_sale_mint);
  const ticket = m.ticketId(OWNER, NONCE, 1);
  assert.equal(hex(ticket), v.ticket_id);
  assert.equal(hex(m.treasurySource(TOKEN, ticket)), v.treasury_source);
  assert.equal(hex(m.drawLeaf(ticket, [7, 1])), v.draw_leaf);
  assert.equal(hex(m.openLeaf(3, 11)), v.open_leaf);
  const leaves = [m.drawLeaf(new Uint8Array(32).fill(0x01), [4]), m.drawLeaf(ticket, [7, 1]), m.drawLeaf(new Uint8Array(32).fill(0x03), [0, 2, 9])];
  assert.equal(hex(m.merkleRoot(leaves)), v.draw_root);
  const proof = m.merkleProof(leaves, 1);
  assert.equal(proof.map((p) => `${hex(p.sibling)}${p.nodeIsRight ? 1 : 0}`).join(','), v.draw_proof);
  assert.ok(m.verifyProof(leaves[1], proof, m.merkleRoot(leaves)), 'a proof verifies against its root');
  assert.ok(!m.verifyProof(m.drawLeaf(ticket, [7, 2]), proof, m.merkleRoot(leaves)), 'and not for serials it did not draw');
  const item = (serial) => ({ note: { ...change[0].note, asset: m.itemAsset(TOKEN, serial), amount: m.ITEM_UNIT }, enc: change[0].enc });
  assert.equal(hex(m.buyTicketsIntent({ buyer: OWNER, collection: TOKEN, count: 3, nonce: NONCE, inputs, change })), v.buy_tickets);
  assert.equal(hex(m.claimItemsIntent({ buyer: OWNER, collection: TOKEN, nonce: NONCE, k: 1, serials: [7, 1], proof, items: [item(7), item(1)], inputs, change })), v.claim_items);
  assert.equal(hex(m.mintOpenIntent({ buyer: OWNER, collection: TOKEN, serial: 11, proof, item: item(11), nonce: NONCE, inputs, change })), v.mint_open);
  // Burn tickets (§145).
  const commitment = m.voucherCommitment(OWNER, NONCE);
  assert.equal(hex(commitment), v.voucher_commitment);
  assert.equal(hex(m.voucherTicketId(commitment, 2)), v.voucher_ticket_id);
  assert.equal(hex(m.claimVoucherItemsIntent({ buyer: OWNER, collection: TOKEN, secret: NONCE, k: 2, serials: [7, 1], proof, items: [item(7), item(1)], inputs, change })), v.claim_voucher_items);
});

test('bridged assets beside ZEC: ids, the deposit commitment, the claim and the exit commitment match the ledger (§146)', () => {
  assert.equal(hex(m.bridgedAsset('solana-devnet')), v.bridged_sol_devnet);
  assert.equal(hex(m.bridgedAsset('eip155:11155111')), v.bridged_eth_sepolia);
  const commitment = m.depositCommitment(OWNER, NONCE);
  assert.equal(hex(commitment), v.deposit_commitment);
  const sol = m.bridgedAsset('solana-devnet');
  assert.equal(hex(m.depositKey(commitment, sol)), v.deposit_key);
  assert.equal(hex(m.exitCommitment(new Uint8Array(20).fill(0x11), NONCE)), v.exit_commitment_evm);
  const output = { note: { ...change[0].note, asset: sol }, enc: change[0].enc };
  assert.equal(hex(m.claimDepositIntent({ owner: OWNER, secret: NONCE, asset: sol, output })), v.claim_deposit);
});


test('Zyn Lend: programs, ids and every holder intent match the ledger byte for byte', () => {
  for (const [k, name] of [['lendSupply', 'supply'], ['lendWithdraw', 'withdraw'], ['lendOpen', 'open'], ['lendRepay', 'repay'], ['lendCollateral', 'collateral'], ['lendBid', 'bid']]) {
    assert.equal(m.MARKET_PROGRAM[k], v[`program_lend_${name}`], k);
  }
  assert.equal(hex(m.lendAsset(ZEC)), v.lend_asset);
  const position = m.lendSource(OWNER, NONCE);
  assert.equal(hex(position), v.lend_source);
  assert.equal(hex(m.lotSource(position)), v.lot_source);
  assert.equal(hex(m.leftoverSource(position)), v.leftover_source);
  const common = { nonce: NONCE, inputs, change };
  assert.equal(hex(m.lendSupplyIntent({ lender: OWNER, asset: ZEC, amount: W(3), ...common })), v.lend_supply);
  assert.equal(hex(m.lendWithdrawIntent({ lender: OWNER, asset: ZEC, shares: W(3), ...common })), v.lend_withdraw);
  assert.equal(hex(m.lendOpenIntent({ borrower: OWNER, collateralAsset: ZEC, collateral: W(5), borrowAsset: TOKEN, amount: W(1), ...common })), v.lend_open);
  assert.equal(hex(m.lendRepayIntent({ borrower: OWNER, position, amount: W(1), ...common })), v.lend_repay);
  assert.equal(hex(m.lendAddCollateralIntent({ borrower: OWNER, position, amount: W(1), inputs, change })), v.lend_add_collateral);
  assert.equal(hex(m.lendRemoveCollateralIntent({ borrower: OWNER, position, amount: W(1), nonce: NONCE })), v.lend_remove_collateral);
  assert.equal(hex(m.lendBidIntent({ bidder: OWNER, lot: m.lotSource(position), pay: W(1), ...common })), v.lend_bid);
});

test('Zyn Lend v2: adding to a pool\'s insurance is laid out as the ledger reads op 51', () => {
  // Until the shared fixture carries `lend_insure`, the layout is held to
  // add-collateral's, which the ledger reads the same way after the tag and
  // the program: account, a 32-byte id, the amount, inputs, change.
  const insure = m.lendInsureIntent({ donor: OWNER, asset: ZEC, amount: W(1), inputs, change });
  const add = m.lendAddCollateralIntent({ borrower: OWNER, position: ZEC, amount: W(1), inputs, change });
  assert.equal(insure[0], 51);
  assert.deepEqual(insure.slice(33, 65), unhexBytes(m.MARKET_PROGRAM.lendInsure));
  assert.deepEqual(insure.slice(65), add.slice(65));
  assert.deepEqual(insure.slice(1, 33), add.slice(1, 33));
  if (v.program_lend_insure) assert.equal(m.MARKET_PROGRAM.lendInsure, v.program_lend_insure);
  if (v.lend_insure) assert.equal(hex(insure), v.lend_insure);
});
const unhexBytes = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));

/// A redeemed item's floor share waits under the item note's own commitment;
/// Nap finds it from the spent notes it scans, which a restore sees too.
test('a redeemed item\'s floor share is found from the spent item note', async () => {
  const { redemptionClaims } = await import('../src/ledger.js');
  const item = 'ab'.repeat(32);
  const ids = redemptionClaims([
    { commitment: item, asset: 'cd'.repeat(32), amount: 10n ** 18n },
    { commitment: 'ef'.repeat(32), asset: 'cd'.repeat(32), amount: 5n },
  ]);
  assert.deepEqual([...ids.keys()], [hex(m.claimId(m.redemptionSource(Buffer.from(item, 'hex')), 0))], 'one-unit notes only');
});

test('a gated sale\'s key and prices are the ledger\'s', () => {
  assert.equal(hex(m.saleAllowKey(TOKEN, OWNER)), v.sale_allow_key);
  assert.equal(m.gatedTotal(10n ** 16n, 10, 10, 2).toString(), v.sale_gated_total_10_2);
  assert.deepEqual([10, 11, 12].map((n) => m.gatedPrice(10n ** 16n, 10, n)), [10n ** 16n, 2n * 10n ** 16n, 3n * 10n ** 16n]);
});

test('a DAO\'s pass, payment source and member intents are the ledger\'s (§172)', () => {
  const item = new Uint8Array(32).fill(0xc1);
  assert.equal(m.MARKET_PROGRAM.dao, v.program_dao);
  assert.equal(hex(m.daoPass(new TextEncoder().encode('cave-pass-token'))), v.dao_pass);
  assert.equal(hex(m.daoPaymentSource(TOKEN, 7)), v.dao_payment_source);
  assert.equal(hex(m.memberPassIntent({ holder: OWNER, collection: TOKEN, item, pass: m.daoPass(new TextEncoder().encode('cave-pass-token')) })), v.member_pass);
  const pay = { asset: ZEC, amount: W(3), to: new Uint8Array(32).fill(0xb0) };
  assert.equal(hex(m.proposeIntent({ proposer: OWNER, collection: TOKEN, item, text: new Uint8Array(32).fill(0x7a), pay })), v.propose);
  assert.equal(hex(m.proposeIntent({ proposer: OWNER, collection: TOKEN, item, text: new Uint8Array(32).fill(0x7a), pay: null })), v.propose_no_pay);
  assert.equal(hex(m.voteIntent({ voter: OWNER, collection: TOKEN, proposal: 7, items: [item, new Uint8Array(32).fill(0xc2)], choice: m.DAO_YES })), v.vote);
  assert.equal(hex(m.proposeZynIntent({ proposer: OWNER, collection: TOKEN, item, text: new Uint8Array(32).fill(0x7a) })), v.propose_zyn);
});
