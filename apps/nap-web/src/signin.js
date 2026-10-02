// The message a wallet signs to open its Zyn account, and the one form its
// signature is read in. Kept apart from embedded.js so it can be tested
// without a bundler: these bytes are the account, and a change here is every
// account moving.

import { keccak_256 } from '@noble/hashes/sha3.js';

const te = new TextEncoder();

/// The sign-in every wallet signs to open its Zyn account. Fixed, so the same
/// address signs the same bytes every time: the nonce and the date are not
/// fresh, on purpose — the signature is a key, not a login token.
export const SIGN_IN = Object.freeze({
  domain: 'lend.zyn-network.com',
  uri: 'https://lend.zyn-network.com',
  statement: 'Open my Zyn account. This signature is the key to the account. Sign it only on lend.zyn-network.com.',
  version: '1',
  // One account per wallet: the same message on testnet and mainnet.
  chainId: 1,
  nonce: 'zynaccount1',
  issuedAt: '2026-10-02T00:00:00Z',
});

/// An Ethereum address as EIP-55 writes it (EIP-4361 requires it).
export function checksumAddress(address) {
  const a = String(address).toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error('That is not an Ethereum address');
  const h = keccak_256(te.encode(a));
  return `0x${[...a].map((c, i) => (/[a-f]/.test(c) && ((h[i >> 1] >> (i % 2 ? 0 : 4)) & 0xf) >= 8 ? c.toUpperCase() : c)).join('')}`;
}

/// The exact text `kind` ('evm' or 'sol') signs for `address`: EIP-4361 for
/// Ethereum, the Solana sign-in format (SIWS) for Solana.
export function signInText(kind, address) {
  const s = SIGN_IN;
  if (kind === 'evm') {
    return [
      `${s.domain} wants you to sign in with your Ethereum account:`,
      checksumAddress(address),
      '',
      s.statement,
      '',
      `URI: ${s.uri}`,
      `Version: ${s.version}`,
      `Chain ID: ${s.chainId}`,
      `Nonce: ${s.nonce}`,
      `Issued At: ${s.issuedAt}`,
    ].join('\n');
  }
  if (kind === 'sol') {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(address))) throw new Error('That is not a Solana address');
    return [
      `${s.domain} wants you to sign in with your Solana account:`,
      address,
      '',
      s.statement,
      '',
      `URI: ${s.uri}`,
      `Version: ${s.version}`,
      `Nonce: ${s.nonce}`,
      `Issued At: ${s.issuedAt}`,
    ].join('\n');
  }
  throw new Error(`No sign-in for ${kind}`);
}

/// What `solana:signIn` is asked for: the same fields, so a wallet that
/// builds the text itself builds `signInText('sol', …)`.
export const solanaSignInInput = () => ({
  domain: SIGN_IN.domain, statement: SIGN_IN.statement, uri: SIGN_IN.uri, version: SIGN_IN.version, nonce: SIGN_IN.nonce, issuedAt: SIGN_IN.issuedAt,
});

/// Whether `signed` (the bytes a Solana wallet says it signed in with) is a
/// sign-in for this domain and `address`, carrying this statement — the
/// wallet may have added fields (a chain, a request id), never changed these.
export function solanaSignInOk(signed, address) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(signed);
  const lines = text.split('\n');
  return lines[0] === `${SIGN_IN.domain} wants you to sign in with your Solana account:` && lines[1] === address
    && lines[3] === SIGN_IN.statement && lines.includes(`URI: ${SIGN_IN.uri}`);
}

/// One form for an Ethereum signature, whatever the wallet returns: r‖s‖v
/// with v 27 or 28 (hardware wallets say 0 or 1; EIP-2098 packs v into s).
export function evmSignature(sig) {
  if (!(sig instanceof Uint8Array)) throw new Error('The wallet returned no signature');
  if (sig.length === 64) {
    const out = new Uint8Array(65);
    out.set(sig);
    out[32] &= 0x7f;
    out[64] = 27 + (sig[32] >> 7);
    return out;
  }
  if (sig.length === 65) {
    const v = sig[64];
    if (v === 0 || v === 1) { const out = sig.slice(); out[64] = v + 27; return out; }
  }
  return sig;
}
