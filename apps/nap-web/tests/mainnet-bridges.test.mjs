// Mainnet's bridges: ETH.zy is a capped pilot under a Safe; BOLD.zy waits
// until the chain lists it and the vault's Safe has registered Liquity BOLD
// under asset id 2 — read from the vault itself (`assets(2)`), through Nap's
// one-call relay (functions/eth). Anything short of that answer keeps it shut.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

const { bridgesOf, bridgeState, readVaultAsset, VAULT_ASSETS } = await import('../src/bridges.js');
const { METHODS } = await import('../src/connect-ops.js');
const { deriveIdentity } = await import('../src/core.js');
const relay = await import(new URL('../functions/eth/[[path]].js', import.meta.url));

const CONFIG = JSON.parse(readFileSync(new URL('../public/config.json', import.meta.url), 'utf8'));
const mainnet = CONFIG.networks.find((n) => n.id === 'mainnet');
const ETH_ZY = '9f5a2c088a0071ba7afcb2c74b9c7cc23f0f94c297d97aef68e50392c04acc6c';
const BOLD_ZY = 'ddf2b7ecc2634e39a891a19020205ae26a87e9f753e492e03b84e7dc627f250f';
const BOLD = '0x6440f144b7e50d6a8439336510312d2f54beb01d';
const VAULT = '0x235730d7738CC16d3b94d0e3D7097F9ddE22A459';
const w = (v) => BigInt(v).toString(16).padStart(64, '0');
/// What the vault answers for assets(id): (token, decimals, registered).
const answer = (token, decimals, registered) => `0x${w(BigInt(token))}${w(decimals)}${w(registered ? 1 : 0)}`;

test('the vault registry reads as token, decimals, registered — from the live mainnet answers', () => {
  // assets(1) on 0x2357…A459: native ETH, 18 decimals, registered.
  assert.deepEqual(readVaultAsset(answer(0, 18, true)), { token: `0x${'0'.repeat(40)}`, decimals: 18, registered: true });
  // assets(2) before the Safe registers BOLD: all zeros.
  assert.deepEqual(readVaultAsset(`0x${'0'.repeat(192)}`), { token: `0x${'0'.repeat(40)}`, decimals: 0, registered: false });
  assert.equal(readVaultAsset('0x'), null);
  assert.equal(readVaultAsset(undefined), null);
});

test('mainnet ETH is the capped pilot under the Safe; its asset id is the chain\'s', () => {
  const eth = bridgesOf(mainnet).find((b) => b.key === 'eth');
  assert.equal(eth.asset, ETH_ZY);
  assert.equal(eth.chainId, 1);
  assert.equal(eth.vault, VAULT);
  assert.equal(eth.capWei, '10000000000000000');
  assert.equal(eth.custody, '2-of-3 Safe');
  assert.match(eth.safe, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(eth.checkVault, undefined, 'ETH is the native asset: nothing to wait for');
  assert.deepEqual(bridgesOf(mainnet).map((b) => b.key), ['eth', 'bold']);
});

const identity = deriveIdentity('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art');
const config = { ...mainnet, rpcUrl: 'http://chain.test/' };
let bridged = [];
let vault = null; // what assets(2) answers; an Error to fail
const asked = [];
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const reply = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), { status: 200 });
  if (url === '/eth/mainnet') {
    asked.push(body);
    if (vault instanceof Error) throw vault;
    return reply(vault);
  }
  switch (body.method) {
    case 'zyn_bridged': return reply(bridged);
    case 'zyn_market': return reply({ epoch: 5, epoch_seconds: 60, pools: [], curves: [], fees: { bridge_bps: 50 } });
    default: return reply([]);
  }
};
const bold = async () => (await bridgeState(config)).bridges.find((b) => b.key === 'bold');

test('BOLD stays shut until the chain lists it and the vault has registered that exact token', async () => {
  bridged = [{ asset: ETH_ZY, network: 'eip155:1', origin: '', decimals: 18, issued: '0' }];
  vault = `0x${'0'.repeat(192)}`;
  // Today: neither. The Safe's registration is what it waits on first.
  let b = await bold();
  assert.deepEqual([b.live, b.waiting], [false, 'vault']);
  assert.deepEqual(asked.at(-1).params, [{ to: VAULT, data: `0x${VAULT_ASSETS}${w(2)}` }, 'latest']);
  vault = answer(BOLD, 18, true);
  b = await bold();
  assert.deepEqual([b.live, b.waiting], [false, 'chain'], 'registered in the vault, not listed on Zyn');
  bridged.push({ asset: BOLD_ZY, network: 'eip155:1', origin: BOLD.slice(2), decimals: 18, issued: '0' });
  vault = `0x${'0'.repeat(192)}`;
  b = await bold();
  assert.deepEqual([b.live, b.waiting], [false, 'vault'], 'listed on Zyn, not registered in the vault');
  vault = answer('0xD58C9e3EeBE83fda55D59C186E86b37aa5d0f79a', 18, true);
  assert.equal((await bold()).live, false, 'another token under id 2 is not BOLD');
  vault = new Error('offline');
  assert.equal((await bold()).live, false, 'no answer is not a yes');
  vault = answer(BOLD, 18, true);
  b = await bold();
  assert.deepEqual([b.live, b.waiting], [true, null]);
  // ETH needs no registry read.
  assert.equal((await bridgeState(config)).bridges.find((x) => x.key === 'eth').live, true);
});

test('no BOLD deposit code while the vault does not take it — and no nonce spent asking', async () => {
  const ctx = { config, identity };
  vault = `0x${'0'.repeat(192)}`;
  const before = store.get(`nap.market.n.${config.chain}.${identity.accountHex}`);
  await assert.rejects(METHODS.zyn_bridgeDeposit.run(ctx, { key: 'bold', amount: '1' }), /vault does not take BOLD yet/);
  assert.equal(store.get(`nap.market.n.${config.chain}.${identity.accountHex}`), before);
  vault = answer(BOLD, 18, true);
  const r = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'bold', amount: '1' });
  assert.equal(r.to, VAULT);
  assert.equal(r.token.toLowerCase(), BOLD);
  assert.equal(r.chainId, 1);
  // ETH: the pilot's cap travels with the deposit, for the page to check.
  const e = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'eth' });
  assert.equal(e.capWei, '10000000000000000');
  const listed = await METHODS.zyn_bridges.run(ctx);
  const eth = listed.bridges.find((x) => x.key === 'eth');
  assert.equal(eth.safe, mainnet.bridges.eth.safe);
  assert.equal(listed.bridges.find((x) => x.key === 'bold').waiting, null);
});

test('the relay passes the vault registry read and nothing else', async () => {
  const sent = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => { sent.push({ url, body: JSON.parse(init.body) }); return new Response('{"jsonrpc":"2.0","id":1,"result":"0x"}'); };
  const ask = (body, path = ['mainnet'], method = 'POST') => relay.onRequest({ request: new Request('https://nap.example/eth/mainnet', { method, body: method === 'POST' ? JSON.stringify(body) : undefined }), params: { path } });
  try {
    const good = { jsonrpc: '2.0', id: 7, method: 'eth_call', params: [{ to: VAULT, data: `0x${VAULT_ASSETS}${w(2)}` }, 'latest'] };
    assert.equal((await ask(good)).status, 200);
    assert.equal(sent.at(-1).url, 'https://ethereum-rpc.publicnode.com');
    assert.deepEqual(sent.at(-1).body.params, good.params);
    const n = sent.length;
    for (const bad of [
      { ...good, method: 'eth_sendRawTransaction' },
      { ...good, params: [{ to: VAULT, data: `0x70a08231${w(1)}` }, 'latest'] },
      { ...good, params: [{ to: VAULT, data: `0x${VAULT_ASSETS}${w(2)}`, value: '0x1' }, 'latest'] },
      { ...good, params: [{ to: VAULT, data: `0x${VAULT_ASSETS}${w(2)}` }, 'pending'] },
    ]) assert.equal((await ask(bad)).status, 400, JSON.stringify(bad.params));
    assert.equal((await ask(good, ['base'])).status, 404);
    assert.equal((await ask(good, ['mainnet'], 'GET')).status, 405);
    assert.equal(sent.length, n, 'nothing refused reached Ethereum');
  } finally { globalThis.fetch = real; }
});
