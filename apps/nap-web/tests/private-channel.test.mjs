// The private channel's channels, sizes and exit destinations (DECISIONS
// §158), held to what the bridges and the pools read.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as pool from '../src/pool.js';

const testnet = { bridges: { sol: { network: 'solana-devnet' }, eth: { chainId: 11155111 }, mezo: { chainId: 31611 } } };
const mainnet = { bridges: { eth: { chainId: 1 } } };

test('testnet has SOL, ETH and mzBTC; mainnet has none until the keys come from a ceremony', () => {
  assert.deepEqual(pool.channels(testnet).map((c) => [c.key, c.chain, c.zy]), [
    ['sol', 'solana', 'SOL.zy'],
    ['eth', 'eip155:11155111', 'ETH.zy'],
    ['mzbtc', 'eip155:31611', 'mzBTC.zy'],
  ]);
  assert.deepEqual(pool.channels(mainnet), []);
  assert.throws(() => pool.channel(mainnet, 'eth'), /No such private channel/);
});

test('sizes read as people read them and only a pool\'s own sizes pass', () => {
  const [sol, eth, btc] = pool.channels(testnet);
  assert.deepEqual(sol.sizes.map((s) => pool.sizeText(sol, s)), ['0.1 SOL', '1 SOL', '10 SOL']);
  assert.deepEqual(eth.sizes.map((s) => pool.sizeText(eth, s)), ['0.01 ETH', '0.1 ETH', '1 ETH']);
  assert.deepEqual(btc.sizes.map((s) => pool.sizeText(btc, s)), ['0.001 BTC', '0.01 BTC', '0.1 BTC']);
  assert.equal(pool.sizeOf(eth, '100000000000000000'), 10n ** 17n);
  assert.equal(pool.sizeOf(sol, 1_000_000_000), 1_000_000_000n);
  assert.throws(() => pool.sizeOf(eth, '5'), /Pools take 0.01 ETH, 0.1 ETH, 1 ETH/);
  assert.throws(() => pool.sizeOf(btc, 'x'), /Pools take/);
});

test('a size is burned on Zyn as its WAD amount', () => {
  const [sol, eth] = pool.channels(testnet);
  assert.equal(pool.wadOf(sol, 100_000_000n), 10n ** 17n);
  assert.equal(pool.wadOf(eth, 10n ** 17n), 10n ** 17n);
});

test('an exit destination is "zyn-pool", the size (u64 LE) and the commitment', () => {
  const c = 'ab'.repeat(32);
  const d = pool.destination(10n ** 18n, c);
  assert.equal(d.length, 48);
  assert.equal(new TextDecoder().decode(d.slice(0, 8)), 'zyn-pool');
  assert.equal(new DataView(d.buffer).getBigUint64(8, true), 10n ** 18n);
  assert.ok(d.slice(16).every((b) => b === 0xab));
});

test('recipients are checked against their chain', () => {
  const [sol, eth, btc] = pool.channels(testnet);
  assert.equal(pool.recipientOf(eth, '0x797a4F004C37848A5906045DaD18C7aE791Dd47A').length, 20);
  assert.throws(() => pool.recipientOf(btc, 'HBvV7YqSRSPW4YEBsDvpvF2PrUWFubqVbTNYafkddTsy'), /not a Mezo testnet address/);
  assert.equal(pool.recipientOf(sol, 'HBvV7YqSRSPW4YEBsDvpvF2PrUWFubqVbTNYafkddTsy').length, 32);
  assert.throws(() => pool.recipientOf(sol, '0x797a4F004C37848A5906045DaD18C7aE791Dd47A'), /not a Solana address/);
});
