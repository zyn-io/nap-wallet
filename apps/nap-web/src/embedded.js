// A Zyn account inside a site, opened with a wallet the holder already has
// (Phantom, MetaMask, Backpack, Rabby…) instead of Nap.
//
// The holder signs one fixed sign-in message for lend.zyn-network.com — EIP-4361
// (Sign-In with Ethereum) or its Solana form — so the wallet itself checks the
// site asking is that domain before it signs. The message is the same every
// time for the same address (fixed nonce and date), the signature is hashed
// into a 24-word phrase, and the account comes from that phrase exactly as
// Nap derives one — so the same wallet always opens the same account, on any
// device, and the phrase can be shown and restored in Nap.
//
// Several wallets can open one account (a Solana wallet and an Ethereum one,
// say): the account's words are sealed for each linked wallet under a key
// only that wallet's signature makes, and kept by the Zyn app's service
// under an id the same signature makes (the keyring) — so nobody can look a
// wallet up, and the service holds ciphertext only.
//
// The provider answers the same methods Nap Connect does, from the same
// operations (`connect-ops.js`); writes go through the site's own approval,
// passed in as `approve(plan)`. Nothing is stored: the account lives in the
// page until it is closed.

import { sha256 } from '@noble/hashes/sha2.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import * as ed from '@noble/ed25519';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { deriveIdentity, forgetIdentity, WAD } from './core.js';
import { ERR, METHODS, ProviderError, session } from './connect-ops.js';
import { objectCall, registerIntent } from './object.js';
import { submitIntent, call, loadPositions } from './ledger.js';
import { notes as poolNotes } from './pool.js';
import { loadPocket, payOnZyn, resolveRecipient } from './pocket.js';
import CONFIG from '../public/config.json';
import { SIGN_IN, checksumAddress, signInText, solanaKeyText, solanaSignInInput, solanaSignInOk, evmSignature } from './signin.js';

const te = new TextEncoder();

/// An ed25519 signature over `message` by `publicKey`.
export const verifyEd25519 = (signature, message, publicKey) => ed.verifyAsync(signature, message, publicKey).catch(() => false);

export { SIGN_IN, checksumAddress, signInText, solanaKeyText, solanaSignInInput, solanaSignInOk, evmSignature };

/// A signature as the account is derived from it: a 65-byte Ethereum one
/// with v made 27/28 (the same key, whichever way the wallet wrote v).
const keyOf = (signature) => (signature instanceof Uint8Array && signature.length === 65 ? evmSignature(signature) : signature);

const label = (l, sig) => sha256(new Uint8Array([...te.encode(l), 0, ...keyOf(sig)]));
const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const bytesOf = (h) => Uint8Array.from(String(h).match(/../g) || [], (x) => parseInt(x, 16));

/// Where a wallet's sealed key is kept, and the key that opens it: both
/// from its signature, so only that wallet finds and opens its entry. v2: the
/// sign-in message changed (EIP-4361 / SIWS), so v1 entries are left alone.
export const keyringId = (signature) => hexOf(label('zyn-keyring.id.v2', signature));
const wrapKey = (signature) => label('zyn-keyring.wrap.v2', signature);

/// Where the keyring is asked: `config.keyringUrl` when set, else the chain.
/// The entry is the account's words sealed under the signature, so one
/// keyring serves every network: a site that points each network's config at
/// the same keyring links a wallet to the same account on all of them.
const keyring = (config) => (config.keyringUrl && config.keyringUrl !== config.rpcUrl ? { ...config, rpcUrl: config.keyringUrl } : config);

/// The words this signature opens: the account it is linked to, if any,
/// else its own (`linked` says which).
export async function wordsFor(config, signature) {
  // "Not linked" opens the wallet's own account; "cannot tell" must not, or
  // a linked wallet would quietly open an empty account of its own. A node
  // without a keyring yet is the first.
  const entry = await call(keyring(config), 'zyn_keyringGet', { key: keyringId(signature) }).catch((e) => {
    if (/does not serve zyn_keyring/.test(e.message)) return null;
    throw new Error(`The Zyn keyring did not answer (${e.message}); try again shortly`);
  });
  if (entry?.blob) {
    const blob = bytesOf(entry.blob);
    const entropy = xchacha20poly1305(wrapKey(signature), blob.slice(0, 24)).decrypt(blob.slice(24));
    return { words: entropyToMnemonic(entropy, wordlist), linked: true };
  }
  return { words: wordsFromSignature(signature), linked: false };
}

/// Seal `words` (the open account's) for the wallet that made `signature`,
/// so it opens this account from now on. Signed by the account.
export async function link(config, identity, words, signature) {
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const sealed = xchacha20poly1305(wrapKey(signature), nonce).encrypt(mnemonicToEntropy(words, wordlist));
  const blob = new Uint8Array([...nonce, ...sealed]);
  const id = keyringId(signature);
  const digest = sha256(new Uint8Array([...te.encode('zyn-keyring.put.v1'), ...bytesOf(id), ...blob]));
  await call(keyring(config), 'zyn_keyringPut', { key: id, blob: hexOf(blob), account: hexOf(identity.publicKey), signature: hexOf(ed.sign(digest, identity.secretKey)) });
}

/// Undo `link` for the wallet that made `signature`.
export async function unlink(config, identity, signature) {
  const id = keyringId(signature);
  const digest = sha256(new Uint8Array([...te.encode('zyn-keyring.delete.v1'), ...bytesOf(id)]));
  await call(keyring(config), 'zyn_keyringDelete', { key: id, account: hexOf(identity.publicKey), signature: hexOf(ed.sign(digest, identity.secretKey)) });
}

/// The 24 words a signature opens: the same signature, the same words.
export function wordsFromSignature(signature, domain = SIGN_IN.domain) {
  if (!(signature instanceof Uint8Array) || signature.length < 64) throw new Error('The wallet returned no signature');
  const entropy = sha256(new Uint8Array([...te.encode('zyn.embedded.v2\0'), ...te.encode(domain), 0, ...keyOf(signature)]));
  return entropyToMnemonic(entropy, wordlist);
}

/// A short, non-secret fingerprint of an account: enough to notice that a
/// wallet now opens a different one, nothing to find the account by.
export const accountTag = (accountHex) => hexOf(sha256(bytesOf(accountHex)).slice(0, 8));

/// A provider for `identity` on `config`, answering as Nap Connect does.
/// `approve(plan)` shows a write's title, rows and note and resolves true or
/// false; `progress(text)` reports a long step (proving, syncing).
export async function open({ config, identity, approve, progress = () => {} }) {
  const ctx = { config, identity, zec: null, zecReady: null };
  // A new account publishes where its notes are sealed before anything can
  // arrive for it: deposits, claims and withdrawals all wait on it.
  const r = await objectCall(config.rpcUrl, 'zyn_depositAddress', { account: identity.accountHex }).catch(() => null);
  if (r?.registered === false && identity.viewing) {
    await submitIntent(config, identity, registerIntent(identity.account, x25519.getPublicKey(identity.viewing)));
  }
  const provider = {
    async request({ method, params = {} }) {
      if (method === 'nap_connect' || method === 'nap_session') return session(ctx);
      const m = METHODS[method];
      if (!m) throw new ProviderError(ERR.UNSUPPORTED, `This account does not do ${method}`);
      if (m.kind === 'public' || m.kind === 'read' || m.kind === 'auto') return m.run(ctx, params);
      const plan = await m.prepare(ctx, params);
      if (!(await approve(plan))) throw new ProviderError(ERR.REJECTED, 'You declined');
      return plan.run((s) => {
        if (s?.proving) progress('Proving the transaction — about half a minute…');
        else if (s?.to) progress(`Syncing ${Number(s.at).toLocaleString('en-US')} of ${Number(s.to).toLocaleString('en-US')}…`);
      });
    },
  };
  return {
    provider,
    session: await session(ctx),
    close: () => forgetIdentity(identity),
    /// Everything this account holds, named: coins, items, what swaps owe.
    pocket: () => loadPocket(config, identity),
    /// Pay `amount` (WAD) of `asset` to another Zyn account (64 hex), after
    /// the site's approval shows the exact amount and the recipient.
    async send(asset, amount, to) {
      const raw = BigInt(amount);
      if (raw <= 0n) throw new Error('Amount must be greater than zero');
      const { to: account } = await resolveRecipient(config, identity, to, { isZec: false, isItem: false });
      const pocket = await loadPocket(config, identity);
      const name = pocket.nameOf ? pocket.nameOf(asset) : `${asset.slice(0, 8)}…`;
      const have = pocket.held.filter((h) => h.asset === asset).reduce((a, h) => a + BigInt(h.amount), 0n);
      if (have < raw) throw new Error(`This account holds ${wadText(have)} ${name}`);
      const ok = await approve({
        title: `Send ${name}`,
        danger: false,
        rows: [['You send', `${wadText(raw)} ${name}`], ['To Zyn account', account]],
        note: 'It arrives at the next seal. A payment on Zyn cannot be taken back.',
      });
      if (!ok) throw new ProviderError(ERR.REJECTED, 'You declined');
      return payOnZyn(config, identity, pocket.held, asset, raw, account);
    },
  };
}

/// What `identity` holds, read without opening (or registering) it:
/// coins, what is owed to it, lending positions and private-pool notes —
/// everything a holder would lose sight of if the wallet stopped opening it.
export async function peek(config, identity) {
  const pocket = await loadPocket(config, identity);
  const positions = await loadPositions(config, identity).catch(() => []);
  const notes = await poolNotes(config, identity).catch(() => []);
  return {
    ...pocket,
    positions: positions.filter((x) => x.state === 'open' || x.state === 'auction'),
    notes: notes.filter((n) => !['to zyn', 'sent', 'spent'].includes(n.state)),
  };
}

const wadText = (raw) => { const v = BigInt(raw); const f = (v % WAD).toString().padStart(18, '0').replace(/0+$/, ''); return `${v / WAD}${f ? `.${f}` : ''}`; };

/// The account `words` open.
export const identityFromWords = (words) => deriveIdentity(words);

/// Drop an identity this page derived but will not open.
export const forget = (identity) => forgetIdentity(identity);

/// The account a signature opens, ready for `open`.
export function identityFromSignature(signature) {
  return deriveIdentity(wordsFromSignature(signature));
}

/// Nap's settings for network `id`, with the ledger reached at `rpcUrl` (a
/// site calls the node directly, not through Nap's own paths). Options:
/// `keyringUrl`, where linked wallets are looked up (default: `rpcUrl`);
/// `ethRpcUrl`, an Ethereum endpoint for the vault registry read in place of
/// Nap's own relay path (which a site cannot reach).
export function networkConfig(id, rpcUrl, { keyringUrl, ethRpcUrl } = {}) {
  const n = CONFIG.networks.find((x) => x.id === id);
  if (!n) throw new Error(`No network ${id}`);
  const out = { ...n, rpcUrl, keyringUrl: keyringUrl || rpcUrl, lightdUrl: null };
  if (n.bridges?.eth?.vaultRpc) {
    // Without a reachable endpoint the read fails, and the token stays shut.
    out.bridges = { ...n.bridges, eth: { ...n.bridges.eth, vaultRpc: ethRpcUrl || '' } };
  }
  return out;
}
