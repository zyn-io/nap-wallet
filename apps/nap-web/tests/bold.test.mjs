// BOLD.zy (DECISIONS §68): an ERC-20 into the Sepolia vault beside ETH —
// its asset id, its name, the two calls a deposit takes, and the way out.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3.js';

const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

const { bridgesOf, evmTokens } = await import('../src/bridges.js');
const { bridgedName } = await import('../src/ledger.js');
const { METHODS } = await import('../src/connect-ops.js');
const { deriveIdentity } = await import('../src/core.js');

const CONFIG = JSON.parse(readFileSync(new URL('../public/config.json', import.meta.url), 'utf8'));
const testnet = CONFIG.networks.find((n) => n.id === 'testnet');
const mainnet = CONFIG.networks.find((n) => n.id === 'mainnet');
const TEST_BOLD = '0xD58C9e3EeBE83fda55D59C186E86b37aa5d0f79a';
const BOLD_ZY = '8c1a1b0616cef63250e9f5bab8b20908320cc47ead0f60215a229d34b5c93ac2';
const ETH_ZY = '56737e143259c754d165074ad15058139bc0b116f5a22b2f3d50129a2a7a24a6';
const VAULT = '0xe17bb5943b34133f6a8a5D221BE4eD9493B3ef27';
const sel = (sig) => Buffer.from(keccak_256(new TextEncoder().encode(sig)).slice(0, 4)).toString('hex');

test('testnet lists BOLD on the Sepolia vault, with the asset id the chain derives', () => {
  const bold = bridgesOf(testnet).find((b) => b.key === 'bold');
  assert.ok(bold);
  assert.equal(bold.asset, BOLD_ZY);
  assert.equal(bold.zy, 'BOLD.zy');
  assert.equal(bold.chainName, 'Sepolia');
  assert.equal(bold.network, 'eip155:11155111');
  assert.equal(bold.vault, VAULT);
  assert.equal(bold.token, TEST_BOLD);
  assert.equal(bold.assetId, 2);
  assert.equal(bold.faucet, true);
  assert.equal(bold.capWei, undefined);
  // ETH stays what it was.
  assert.equal(bridgesOf(testnet).find((b) => b.key === 'eth').asset, ETH_ZY);
});

test('mainnet lists Liquity BOLD on the Ethereum vault, checked against the vault itself', () => {
  const bold = bridgesOf(mainnet).find((b) => b.key === 'bold');
  assert.equal(bold.token, '0x6440f144b7e50D6a8439336510312d2F54beB01D');
  assert.equal(bold.asset, 'ddf2b7ecc2634e39a891a19020205ae26a87e9f753e492e03b84e7dc627f250f');
  assert.equal(bold.assetId, 2);
  assert.equal(bold.chainName, 'Ethereum');
  assert.equal(bold.faucet, false);
  assert.equal(bold.checkVault, true);
  assert.equal(bold.vaultRpc, '/eth/mainnet');
  // Testnet's TestBold is not checked that way.
  assert.equal(bridgesOf(testnet).find((b) => b.key === 'bold').checkVault, false);
});

test('a token that would take a coin\'s key, or has no asset id, is left out', () => {
  const eth = { ...testnet.bridges.eth, tokens: [{ symbol: 'ETH', address: TEST_BOLD, decimals: 18, assetId: 3 }, { symbol: 'X', address: TEST_BOLD, decimals: 18, assetId: 3 }, { symbol: 'USDZ', address: TEST_BOLD, decimals: 18 }] };
  assert.deepEqual(evmTokens(eth), []);
});

test('the chain\'s BOLD row is named BOLD.zy; ETH stays ETH.zy', () => {
  assert.equal(bridgedName(testnet, { asset: BOLD_ZY, network: 'eip155:11155111', origin: TEST_BOLD.slice(2).toLowerCase(), decimals: 18 }), 'BOLD.zy');
  assert.equal(bridgedName(testnet, { asset: ETH_ZY, network: 'eip155:11155111', origin: '', decimals: 18 }), 'ETH.zy');
  // The same contract on another chain is not this BOLD.
  assert.match(bridgedName(testnet, { asset: 'aa'.repeat(32), network: 'eip155:1', origin: TEST_BOLD.slice(2).toLowerCase(), decimals: 18 }), /^d58c9e3e…\.zy$/);
});

// ------------------------------------------------------------- Nap Connect

const identity = deriveIdentity('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art');
const config = { ...testnet, rpcUrl: 'http://chain.test/' };
const ctx = { config, identity };
store.set(`nap.market.n.${config.chain}.${identity.accountHex}`, '1');
let bridged = [];
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const answer = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), { status: 200 });
  switch (body.method) {
    case 'zyn_bridged': return answer(bridged);
    case 'zyn_market': return answer({ epoch: 5, epoch_seconds: 10, pools: [], curves: [], fees: { bridge_bps: 50 } });
    default: return answer([]);
  }
};

test('zyn_bridges says whether BOLD is live from what the chain lists', async () => {
  bridged = [{ asset: ETH_ZY, network: 'eip155:11155111', origin: '', decimals: 18, issued: '1' }];
  let r = await METHODS.zyn_bridges.run(ctx);
  const before = r.bridges.find((b) => b.key === 'bold');
  assert.equal(before.live, false);
  assert.equal(before.token, TEST_BOLD);
  assert.equal(before.assetId, 2);
  bridged.push({ asset: BOLD_ZY, network: 'eip155:11155111', origin: TEST_BOLD.slice(2).toLowerCase(), decimals: 18, issued: '5' });
  r = await METHODS.zyn_bridges.run(ctx);
  assert.equal(r.bridges.find((b) => b.key === 'bold').live, true);
});

test('a BOLD deposit is approve(vault, amount) then deposit(code, 2, amount)', async () => {
  const plain = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'bold' });
  assert.match(plain.code, /^[0-9a-f]{64}$/);
  assert.equal(plain.calls, undefined);
  const r = await METHODS.zyn_bridgeDeposit.run(ctx, { key: 'bold', amount: '12.5' });
  // A fresh code each request (audit, 9 Oct 2026): two deposits never share one.
  assert.match(r.code, /^[0-9a-f]{64}$/);
  assert.notEqual(r.code, plain.code);
  assert.equal(r.to, VAULT);
  assert.equal(r.token, TEST_BOLD);
  assert.equal(r.assetId, 2);
  assert.equal(r.amount, (125n * 10n ** 17n).toString());
  const amt = (125n * 10n ** 17n).toString(16).padStart(64, '0');
  assert.equal(r.calls[0].to, TEST_BOLD);
  assert.equal(r.calls[0].data, `0x${sel('approve(address,uint256)')}${VAULT.slice(2).toLowerCase().padStart(64, '0')}${amt}`);
  assert.equal(r.calls[1].to, VAULT);
  assert.equal(r.calls[1].data, `0x${sel('deposit(bytes32,uint32,uint256)')}${r.code}${'2'.padStart(64, '0')}${amt}`);
  await assert.rejects(METHODS.zyn_bridgeDeposit.run(ctx, { key: 'bold', amount: '0' }), /greater than zero/);
});

test('BOLD.zy goes out through the vault once the chain lists it; not before', async () => {
  bridged = [];
  await assert.rejects(METHODS.zyn_bridgeWithdraw.prepare(ctx, { key: 'bold', to: '0x' + '11'.repeat(20), amount: '1' }), /No BOLD bridge/);
  bridged = [{ asset: BOLD_ZY, network: 'eip155:11155111', origin: TEST_BOLD.slice(2).toLowerCase(), decimals: 18, issued: '5' }];
  await assert.rejects(METHODS.zyn_bridgeWithdraw.prepare(ctx, { key: 'bold', to: 'not an address', amount: '1' }), /not an Ethereum address/);
  // Holding none, it is refused before anything is signed.
  await assert.rejects(METHODS.zyn_bridgeWithdraw.prepare(ctx, { key: 'bold', to: '0x' + '11'.repeat(20), amount: '1' }), /BOLD\.zy/);
});
