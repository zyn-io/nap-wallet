// The sign-in a wallet signs to open its Zyn account (src/signin.js). The
// bytes are the account: the same address must sign the same message every
// time, and the wallet must be able to read the domain out of it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SIGN_IN, checksumAddress, signInText, solanaSignInInput, solanaSignInOk, evmSignature } from '../src/signin.js';

const te = new TextEncoder();

test('Ethereum addresses are written as EIP-55 says', () => {
  // The EIP's own examples.
  for (const a of ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359', '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb']) {
    assert.equal(checksumAddress(a.toLowerCase()), a);
  }
  assert.throws(() => checksumAddress('0x123'));
});

test('the Ethereum sign-in is EIP-4361, fixed, for lend.zyn-network.com', () => {
  const t = signInText('evm', '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed');
  assert.equal(t, [
    'lend.zyn-network.com wants you to sign in with your Ethereum account:',
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '',
    'Open my Zyn account. This signature is the key to the account. Sign it only on lend.zyn-network.com.',
    '',
    'URI: https://lend.zyn-network.com',
    'Version: 1',
    'Chain ID: 1',
    'Nonce: zynaccount1',
    'Issued At: 2026-10-02T00:00:00Z',
  ].join('\n'));
  // The same address, however it is cased, signs the same bytes.
  assert.equal(signInText('evm', '0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED'), t);
  // EIP-4361's grammar: a statement of URI characters, an 8+ alphanumeric
  // nonce, an RFC 3339 date.
  assert.match(SIGN_IN.statement, /^[A-Za-z0-9 .,:;!?'()*+=$&@/#\[\]_~-]+$/);
  assert.match(SIGN_IN.nonce, /^[A-Za-z0-9]{8,}$/);
  assert.ok(!Number.isNaN(Date.parse(SIGN_IN.issuedAt)));
});

/// @solana/wallet-standard-util's createSignInMessageText, for the fields
/// this app sends.
function siws(input) {
  let m = `${input.domain} wants you to sign in with your Solana account:\n${input.address}`;
  if (input.statement) m += `\n\n${input.statement}`;
  const f = [];
  if (input.uri) f.push(`URI: ${input.uri}`);
  if (input.version) f.push(`Version: ${input.version}`);
  if (input.chainId) f.push(`Chain ID: ${input.chainId}`);
  if (input.nonce) f.push(`Nonce: ${input.nonce}`);
  if (input.issuedAt) f.push(`Issued At: ${input.issuedAt}`);
  if (f.length) m += `\n\n${f.join('\n')}`;
  return m;
}

test('the Solana sign-in is the text a wallet builds from the same fields', () => {
  const address = 'HBvV7YqSRSPW4YEBsDvpvF2PrUWFubqVbTNYafkddTsy';
  const t = signInText('sol', address);
  assert.equal(t, siws({ ...solanaSignInInput(), address }));
  assert.ok(solanaSignInOk(te.encode(t), address));
  // A wallet that adds a field still signed in for this domain and address…
  assert.ok(solanaSignInOk(te.encode(siws({ ...solanaSignInInput(), address, chainId: 'solana:devnet' })), address));
  // …but not one that names another domain or another address.
  assert.ok(!solanaSignInOk(te.encode(t.replace('lend.zyn-network.com wants', 'evil.example wants')), address));
  assert.ok(!solanaSignInOk(te.encode(t), '11111111111111111111111111111111'));
  assert.throws(() => signInText('sol', '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'));
});

test('an Ethereum signature is read one way, whatever v the wallet wrote', () => {
  const rs = Uint8Array.from({ length: 64 }, (_, i) => i + 1);
  const at = (v) => evmSignature(Uint8Array.from([...rs, v]));
  assert.deepEqual(at(0), at(27));
  assert.deepEqual(at(1), at(28));
  assert.equal(at(0)[64], 27);
  assert.equal(at(28)[64], 28);
  // EIP-2098: v rides in the top bit of s.
  const s = rs.slice();
  s[32] |= 0x80;
  assert.deepEqual(evmSignature(s), at(28));
  assert.deepEqual(evmSignature(rs), at(27));
});
