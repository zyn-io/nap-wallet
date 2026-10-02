// Pool and curve arithmetic the pages quote from, held to the VM's rules
// (objectvm::market `clear`, `apply_add_liquidity`, `apply_remove_liquidity`;
// objectvm::curve). Found in the 27 Sep line-by-line review: the formulas
// matched, but only one case of each had a test.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as mk from '../src/market.js';

const WAD = 10n ** 18n;
const BPS = 10_000n;

test('a lone order is quoted as the batch clears it, with the fee, on either side', () => {
  const pool = { reserve_a: String(7n * WAD), reserve_b: String(3n * WAD), fee_bps: 30 };
  for (const [sellA, amountIn] of [[true, WAD / 10n], [false, WAD / 7n], [true, 1n], [false, 123456789n]]) {
    const net = (amountIn * (BPS - 30n)) / BPS;
    const [x, y] = sellA ? [7n * WAD, 3n * WAD] : [3n * WAD, 7n * WAD];
    const want = net > 0n ? (net * y) / (x + 2n * net) : 0n;
    assert.equal(mk.quoteAlone(pool, sellA, amountIn), want, `sellA=${sellA} in=${amountIn}`);
  }
});

test('the minimum rounds down, never above the quote', () => {
  for (const q of [0n, 1n, 99n, 10n ** 17n + 1n]) {
    const m = mk.withSlippage(q, 100);
    assert.ok(m <= q && m === (q * 9_900n) / BPS);
  }
});

test('adding liquidity: shares round down, what is used rounds up, never more than was put in', () => {
  const pool = { reserve_a: String(5n * WAD + 3n), reserve_b: String(2n * WAD + 7n), shares: String(3n * WAD + 1n) };
  for (const [a, b] of [[WAD, WAD], [WAD / 3n, WAD], [7n, 11n], [2n * WAD, WAD / 1000n]]) {
    const pv = mk.liquidityPreview(pool, a, b);
    const x = BigInt(pool.reserve_a), y = BigInt(pool.reserve_b), s = BigInt(pool.shares);
    assert.equal(pv.shares, [(a * s) / x, (b * s) / y].reduce((m, v) => (v < m ? v : m)));
    assert.ok(pv.usedA <= a && pv.usedB <= b, 'never more than was put in');
    assert.ok(pv.usedA * s >= pv.shares * x && pv.usedB * s >= pv.shares * y, 'used covers the shares');
  }
});

test('the square root a pool opens with is exact and fast at any size', () => {
  const start = Date.now();
  for (const [a, b] of [[1n, 1n], [2n, 3n], [4n, 9n], [10n ** 24n * 3n, 10n ** 24n], [10n ** 27n, 17n * WAD], [10n ** 36n, 10n ** 36n], [(1n << 120n) - 1n, (1n << 120n) + 5n]]) {
    const r = mk.geometricMean(a, b);
    assert.ok(r * r <= a * b && (r + 1n) * (r + 1n) > a * b, `√(${a}·${b})`);
  }
  // It used to walk the float error one by one and could freeze the page.
  assert.ok(Date.now() - start < 200, `took ${Date.now() - start} ms`);
});

test('a curve buy never previews more than its budget, and a sell nets its fee', () => {
  for (const [sold, amountIn, fee] of [[0, 10n ** 16n, 100], [94, 10n ** 15n, 100], [51_000, 10n ** 17n, 100], [51_097, 10n ** 17n, 0]]) {
    const q = mk.previewCurveBuy(sold, amountIn, fee);
    assert.ok(q.lots >= 0 && sold + q.lots <= mk.CURVE.graduateAt, 'never past graduation');
    assert.ok(q.paid + q.fee <= amountIn, 'never more than the budget');
  }
  const s = mk.previewCurveSell(100, 10, 100);
  assert.equal(s.net, s.gross - s.fee);
});
