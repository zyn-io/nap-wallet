// Nap's Apps list: Bridge opens Lend's Bridge page on the wallet's network,
// naming the coins that network's bridges carry.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

globalThis.localStorage ??= { getItem: () => null, setItem() {}, removeItem() {} };
const { appsFor } = await import('../src/apps.js');
const CONFIG = JSON.parse(readFileSync(new URL('../public/config.json', import.meta.url), 'utf8'));
const net = (id) => CONFIG.networks.find((n) => n.id === id);

test('mainnet: Bridge opens Lend’s mainnet Bridge with SOL, ETH and BOLD', () => {
  const bridge = appsFor(net('mainnet')).find((a) => a.name === 'Bridge');
  assert.equal(bridge.url, 'https://lend.zyn-network.com/?network=mainnet#/bridge');
  assert.equal(bridge.what, 'SOL · ETH · BOLD in and out');
});

test('testnet: Bridge opens Lend’s testnet Bridge', () => {
  const bridge = appsFor(net('testnet')).find((a) => a.name === 'Bridge');
  assert.equal(bridge.url, 'https://lend.zyn-network.com/#/bridge');
  assert.match(bridge.what, /SOL/);
});

test('a network without bridges lists no Bridge', () => {
  assert.equal(appsFor({ id: 'mainnet' }).some((a) => a.name === 'Bridge'), false);
});
