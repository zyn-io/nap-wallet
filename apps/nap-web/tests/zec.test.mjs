// The built Zcash core, as the page loads it: keys must be the desktop's.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { initSync, spendingKeyFromPhrase, ZecWallet, blocksRequest, replyBody } from '../src/zec-pkg/nap_zec.js';

initSync({ module: readFileSync(new URL('../src/zec-pkg/nap_zec_bg.wasm', import.meta.url)) });
const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const hex = (b) => Buffer.from(b).toString('hex');

// zynzapd::wallet::recovery_tests pins the same two keys. If the browser
// derived anything else, it would show an empty wallet to someone whose ZEC
// sits at the address desktop Nap gave them.
test('the browser derives the desktop Zcash keys', () => {
  assert.equal(hex(spendingKeyFromPhrase(WORDS, '', 'mainnet', 0)), 'ba36a915cf195348f4f8bcd584e2635735778190071db2f2af78d80b44a97bcb');
  assert.equal(hex(spendingKeyFromPhrase(WORDS, '', 'testnet', 0)), '13548ce4ac2ec6cc6b93a8f66f50ddce51e9e156cc084d3cef279873446f1b1b');
});

test('addresses are for their own network', () => {
  const main = new ZecWallet(spendingKeyFromPhrase(WORDS, '', 'mainnet', 0), 'mainnet');
  const test_ = new ZecWallet(spendingKeyFromPhrase(WORDS, '', 'testnet', 0), 'testnet');
  assert.match(main.address(), /^u1[a-z0-9]+$/);
  assert.match(test_.address(), /^utest1[a-z0-9]+$/);
});

test('a bad phrase and a server refusal are errors, not garbage', () => {
  assert.throws(() => spendingKeyFromPhrase('abandon art', '', 'mainnet', 0), /recovery phrase/);
  const refusal = new Uint8Array([1, 4, 0, ...Buffer.from('nope')]);
  assert.throws(() => replyBody(refusal), /nope/);
  assert.deepEqual([...replyBody(new Uint8Array([0, 7]))], [7]);
  // BLOCKS: op 2, from u64 LE, count u32 LE.
  assert.deepEqual([...blocksRequest(258, 100)], [2, 2, 1, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0]);
});

// ---- Transparent receive and Shield ------------------------------------

import { transparentKeyFromPhrase } from '../src/zec-pkg/nap_zec.js';
import * as zec from '../src/zec-pkg/nap_zec.js';
import { engine } from '../src/zec/engine.js';
import { pendingOutpoints, rememberShield } from '../src/zec/client.js';
import { deriveIdentity, exportKeys, importKeys } from '../src/core.js';
import { mnemonicToSeedSync } from '@scure/bip39';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

/// BIP-32 from first principles, so the core's path is checked against
/// something that is not the same Rust crate.
function bip44(seed, path) {
  const N = secp256k1.CURVE.n;
  let I = hmac(sha512, new TextEncoder().encode('Bitcoin seed'), seed);
  let k = BigInt(`0x${hex(I.slice(0, 32))}`), c = I.slice(32);
  for (const step of path) {
    const hard = step >= 0x80000000;
    const kb = Uint8Array.from(Buffer.from(k.toString(16).padStart(64, '0'), 'hex'));
    const data = hard ? [0, ...kb] : [...secp256k1.getPublicKey(kb, true)];
    I = hmac(sha512, c, Uint8Array.from([...data, step >>> 24, (step >>> 16) & 255, (step >>> 8) & 255, step & 255]));
    k = (BigInt(`0x${hex(I.slice(0, 32))}`) + k) % N; c = I.slice(32);
  }
  return Uint8Array.from(Buffer.from(k.toString(16).padStart(64, '0'), 'hex'));
}
function base58check(prefix, payload) {
  const body = Uint8Array.from([...prefix, ...payload]);
  const full = [...body, ...sha256(sha256(body)).slice(0, 4)];
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt(`0x${hex(full)}`), out = '';
  while (n > 0n) { out = A[Number(n % 58n)] + out; n /= 58n; }
  for (const b of full) { if (b) break; out = `1${out}`; }
  return out;
}
const H = 0x80000000;

test("the transparent key is BIP-44 m/44'/coin'/0'/0/0, as other Zcash wallets derive it", () => {
  const seed = mnemonicToSeedSync(WORDS, '');
  for (const [net, coin, prefix, addr] of [
    ['mainnet', 133, [0x1c, 0xb8], 't1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F'],
    ['testnet', 1, [0x1d, 0x25], 'tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd'],
  ]) {
    const mine = bip44(seed, [44 + H, coin + H, 0 + H, 0, 0]);
    assert.equal(hex(transparentKeyFromPhrase(WORDS, '', net, 0)), hex(mine));
    assert.equal(base58check(prefix, ripemd160(sha256(secp256k1.getPublicKey(mine, true)))), addr);
    const w = new ZecWallet(spendingKeyFromPhrase(WORDS, '', net, 0), net);
    assert.equal(w.transparentAddress(), undefined);
    w.setTransparent(mine);
    assert.equal(w.transparentAddress(), addr);
  }
});

/// A block server that knows one transparent address and two outputs on it.
function fakeServer(address, utxos) {
  const le = (n, bytes) => { const b = Buffer.alloc(bytes); if (bytes === 8) b.writeBigUInt64LE(BigInt(n)); else if (bytes === 4) b.writeUInt32LE(n); else b.writeUInt16LE(n); return b; };
  const seen = [];
  return {
    seen,
    post: async (frame) => {
      seen.push(frame[0]);
      if (frame[0] !== 6) return new Uint8Array([1, 3, 0, ...Buffer.from('nop')]);
      const asked = Buffer.from(frame.slice(3)).toString();
      assert.equal(asked, address, 'UTXOS names the transparent address and nothing else');
      const parts = [le(utxos.length, 4)];
      for (const u of utxos) parts.push(Buffer.alloc(32, u.fill), le(u.index, 4), le(u.value, 8), le(4_380_010, 8), le(0, 2));
      return new Uint8Array([0, ...Buffer.concat(parts)]);
    },
  };
}

test('the transparent balance plans the sweep and leaves out what a shield already spent', async () => {
  const keys = engine(zec, async () => { throw new Error('no network'); }).derive(WORDS, '', 0);
  assert.equal(keys.transparent.testnet.length, 32);
  const server = fakeServer('tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd', [{ fill: 1, index: 0, value: 100_000 }, { fill: 2, index: 1, value: 40_000 }]);
  const e = engine(zec, server.post);
  const view = e.open(keys.testnet, 'testnet', null, keys.transparent.testnet);
  assert.equal(view.transparent, 'tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd');
  const all = await e.transparent([]);
  assert.deepEqual([all.total, all.fee, all.net, all.count], [140_000, 20_000, 120_000, 2]);
  const first = all.utxos[0].outpoint;
  assert.match(first, /^(01){32}:0$/);
  const rest = await e.transparent([first]);
  assert.deepEqual([rest.total, rest.fee, rest.net, rest.count], [40_000, 15_000, 25_000, 1]);
  assert.deepEqual(server.seen, [6, 6], 'only UTXOS was asked');
  // Without a transparent key there is no address to ask about.
  const bare = engine(zec, server.post);
  assert.equal(bare.open(keys.testnet, 'testnet', null, null).transparent, null);
  await assert.rejects(() => bare.transparent([]), /no transparent key/);
});

test('outputs a shield spent are remembered per network until the chain mines it', () => {
  rememberShield('testnet', ['aa:0', 'bb:1']);
  assert.deepEqual(pendingOutpoints('testnet'), ['aa:0', 'bb:1']);
  assert.deepEqual(pendingOutpoints('mainnet'), []);
});

test('the sealed record carries the transparent keys, and opens without them', () => {
  const id = deriveIdentity(WORDS, '', 0);
  id.zec = { mainnet: new Uint8Array(32).fill(1), testnet: new Uint8Array(32).fill(2), transparent: { mainnet: new Uint8Array(32).fill(3), testnet: new Uint8Array(32).fill(4) } };
  const blob = exportKeys(id, []);
  assert.equal(blob.tm, '03'.repeat(32));
  assert.equal(blob.tt, '04'.repeat(32));
  const back = importKeys(blob, 0).identity;
  assert.equal(hex(back.zec.transparent.testnet), '04'.repeat(32));
  const { tm, tt, ...older } = blob;
  const old = importKeys(older, 0).identity;
  assert.ok(old.zec && !old.zec.transparent, 'a record kept before transparent keys still opens its shielded wallet');
});
