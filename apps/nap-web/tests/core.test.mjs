import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveIdentity, hex, parseAmount, signedRead, transferFrame, unhex, vmId, WAD } from '../src/core.js';

const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

test('browser derivation matches the normative Rust vectors', () => {
  const zero = deriveIdentity(WORDS, '', 0);
  assert.equal(hex(zero.secretKey), '57d47cefdba062bb9669a7a64e9072e49d2b5bc66892952429240e4c91b16183');
  assert.equal(hex(zero.publicKey), '308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a6');
  assert.equal(zero.accountHex, 'b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea');
  const seven = deriveIdentity(WORDS, 'nap passphrase', 7);
  assert.equal(hex(seven.secretKey), 'f4e1b20f8a0cd2e19ae9d85ce3057cbb13863be3630e87972afce0b14c513c2e');
  assert.equal(hex(seven.publicKey), '276237e6804911ecd6d44c3d170ac67ff8dc8abf87cf423489a71dddf68857eb');
  assert.equal(seven.accountHex, '4c976ef0d248340b910e246439c3139911f1752e6ba1d3c198f41071e4503604');
});

test('signed reads and transfers have canonical wire lengths', () => {
  const id = deriveIdentity(WORDS, '', 0);
  const read = signedRead(id, 11, 42);
  const frame = transferFrame(id, 11, 42, unhex('11'.repeat(32), 32), 7, WAD);
  assert.equal(hex(vmId()), '7eb9445f363ad075fb2c76833138f0fe4f69b4a4d136e424c08d84f0ed795bcf');
  assert.equal(hex(read), 'b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea000000000000002a01308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a612d919d7b6805ae80ff169cbbf7be20b8548456aaf38d6c60a892dc25be1c0fa28d8e5af2a0bb8411aec809507942a8e1b58219c97f151141b172e16b18d210e');
  assert.equal(hex(frame), '7eb9445f363ad075fb2c76833138f0fe4f69b4a4d136e424c08d84f0ed795bcf000000000000008e01308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a6f19baeaf36700150c81b46dd04ba1f054cd41cacd0318ebb874021be01b07b41c3435cf32fe6a7eee43e8acb4b4af152d7b8acb83e5f32aff6d154d4ad676f0d02b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea11111111111111111111111111111111111111111111111111111111111111110000000700000000000000000de0b6b3a7640000');
});

test('decimal parser is exact and rejects fractions beyond WAD precision', () => {
  assert.equal(parseAmount('1'), WAD);
  assert.equal(parseAmount('0.000000000000000001'), 1n);
  assert.throws(() => parseAmount('0'));
  assert.throws(() => parseAmount('1.0000000000000000001'));
});
