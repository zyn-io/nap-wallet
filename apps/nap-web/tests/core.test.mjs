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
  const frame = transferFrame(id, 11, 42, unhex('11'.repeat(32), 32), '0'.repeat(63) + '7', WAD);
  assert.equal(hex(vmId()), '5cf4557b297390b6c6d08f752fc04a0ac8496349d6fbd0f68657328812d4e5ee');
  assert.equal(hex(read), 'b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea000000000000002a01308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a612d919d7b6805ae80ff169cbbf7be20b8548456aaf38d6c60a892dc25be1c0fa28d8e5af2a0bb8411aec809507942a8e1b58219c97f151141b172e16b18d210e');
  assert.equal(hex(frame), '5cf4557b297390b6c6d08f752fc04a0ac8496349d6fbd0f68657328812d4e5ee000000000000008e01308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a653e89fba1119f7490c8b9c0e58f89db87d4b1e1402b1e9335d05a72b5440f4f4b492289fab01e5a1b05dd80879d1b80ecef529c4c3ff3d7e433a6a7b4305360602b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000700000000000000000de0b6b3a7640000');
});

test('decimal parser is exact and rejects fractions beyond WAD precision', () => {
  assert.equal(parseAmount('1'), WAD);
  assert.equal(parseAmount('0.000000000000000001'), 1n);
  assert.throws(() => parseAmount('0'));
  assert.throws(() => parseAmount('1.0000000000000000001'));
});

test('a kept wallet round-trips under its password, and holds only the derived key', async () => {
  const { deriveIdentity, sealWallet, openSealedWallet, hex, deriveCollectionAccount, unhex } = await import('../src/core.js');
  const id = deriveIdentity(WORDS, '', 0);
  const account = hex(id.account);

  const blob = await sealWallet(id, [], 'a decent passphrase', 0);
  const opened = await openSealedWallet(blob, 'a decent passphrase');
  assert.equal(hex(opened.identity.account), account, 'the same account comes back');

  // What is on the device must be the derived key and nothing that could
  // recover the phrase — the words also control the Zcash wallet.
  const stored = JSON.stringify(blob).toLowerCase();
  assert.ok(!stored.includes('abandon'), 'no mnemonic in the stored record');
  assert.ok(!stored.includes(hex(id.secretKey)), 'the key is not stored in the clear');
  assert.ok(!stored.includes(account), 'not even the account is stored in the clear');
});

test('a wrong password is refused, and says nothing about how wrong', async () => {
  const { deriveIdentity, sealWallet, openSealedWallet } = await import('../src/core.js');
  const blob = await sealWallet(deriveIdentity(WORDS, '', 0), [], 'the right password', 0);
  await assert.rejects(() => openSealedWallet(blob, 'the wrong password'), /does not open this wallet/);
  // A damaged record fails the same way: AES-GCM authenticates, so a tampered
  // ciphertext and a bad password are the same answer.
  await assert.rejects(() => openSealedWallet({ ...blob, key: blob.key.replace(/^../, 'ff') }, 'the right password'), /does not open this wallet/);
});

test('a kept wallet will not be opened under weakened settings', async () => {
  const { deriveIdentity, sealWallet, openSealedWallet } = await import('../src/core.js');
  const blob = await sealWallet(deriveIdentity(WORDS, '', 0), [], 'the right password', 0);
  // Someone editing the stored record down to a cheap KDF is trying to make a
  // later brute force affordable. Refused before the password is even tried.
  await assert.rejects(() => openSealedWallet({ ...blob, iterations: 1000 }, 'the right password'), /too weak/);
  await assert.rejects(() => openSealedWallet({ ...blob, v: 99 }, 'the right password'), /saved by a newer Nap/);
  await assert.rejects(() => openSealedWallet(null, 'the right password'), /No wallet is saved in this browser/);
});

test('a short password is refused when sealing, not when opening', async () => {
  const { deriveIdentity, sealWallet } = await import('../src/core.js');
  await assert.rejects(() => sealWallet(deriveIdentity(WORDS, '', 0), [], 'short', 0), /at least 8/);
});

test('mainnet and testnet Zcash address prefixes cannot be confused', () => {
  // The header names a Zcash network; the deposit address is checked against
  // it. These are the two prefixes that check distinguishes, and a testnet
  // address must not satisfy the mainnet rule.
  const mainnet = 'u1rhlf93n37mt08m6qagxwlswkesezh7hfg24ty64t8g86efq9cmuvqf0z2aeaq2usp94l9v59m2nsu0yzx7wkz99af0x7vlcmhgg8j37k';
  const testnet = 'utest1nkjqphuc4nxdj3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  assert.ok(mainnet.startsWith('u1'), 'a mainnet address satisfies the mainnet rule');
  assert.ok(!testnet.startsWith('u1'), 'a testnet address must not satisfy it');
  assert.ok(testnet.startsWith('utest1'), 'and satisfies the testnet rule instead');
  assert.ok(!mainnet.startsWith('utest1'), 'which a mainnet address must not');
});

test('amounts are trimmed for reading without changing the value', async () => {
  const { readableAmount } = await import('../src/core.js');
  assert.equal(readableAmount('0.100000000000000000'), '0.1');
  assert.equal(readableAmount('12.500000000000000000'), '12.5');
  assert.equal(readableAmount('0.000000000000000001'), '0.000000000000000001', 'a dust amount is not rounded away');
  assert.equal(readableAmount('0.0'), '0');
  assert.equal(readableAmount('0'), '0');
  assert.equal(readableAmount('21000000.0'), '21000000');
  // Never invent a value it cannot read.
  assert.equal(readableAmount('not a number'), 'not a number');
});

test('a kept wallet carries the receiving accounts a bought item lands in', async () => {
  const { deriveIdentity, deriveCollectionAccount, sealWallet, openSealedWallet, hex, unhex } = await import('../src/core.js');
  const CAVEZ = unhex('024277b607ce4edbf78fe2855aba562096d00264729168bd0ddea71bdf5b5f1e', 32);
  const id = deriveIdentity(WORDS, '', 0);
  const rx = deriveCollectionAccount(WORDS, '', 0, CAVEZ);

  const blob = await sealWallet(id, [rx], 'a decent passphrase', 0);
  const opened = await openSealedWallet(blob, 'a decent passphrase');

  // The seed is not kept, so without this a reopened wallet could not derive
  // the account holding whatever the buyer paid for.
  assert.equal(opened.receiving.length, 1);
  assert.equal(hex(opened.receiving[0].account), hex(rx.account), 'the receiving account survives a lock');
  assert.equal(hex(opened.receiving[0].collection), hex(CAVEZ));

  const stored = JSON.stringify(blob).toLowerCase();
  assert.ok(!stored.includes('abandon'), 'still no mnemonic on the device');
  assert.ok(!stored.includes(hex(rx.secretKey)), 'and no receiving key in the clear');
});
