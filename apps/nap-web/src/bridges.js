// The bridges (§146, §154, §155), as Nap Connect (connect-ops.js) serves
// them to a site's bridge page (Zyn Lend's Bridge), and what the wallet
// itself does with them (pocket.js): claim what arrived under its codes, and
// tell the vault where its exits go. No page, no Vite: it runs in Node's
// tests too.
import { hex, parseAmount, unhex } from './core.js';
import { bridgedAsset, exitCommitment, fund } from './market.js';
import { bridgeMemo, call, claimWaiting, loadBridged, loadWaiting, submitIntent } from './ledger.js';
import * as btc from './bitcoin.js';
import { solanaKey } from './solana.js';
import { objectCall, withdrawIntent } from './object.js';

const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* this session only */ } };

/// The ERC-20s an EVM bridge config lists (`tokens`), the malformed left out.
/// Their keys must not take a coin's own (eth, sol, btc, zec).
export function evmTokens(eth) {
  return (Array.isArray(eth?.tokens) ? eth.tokens : []).filter((t) => /^[A-Z][A-Z0-9]{1,9}$/.test(String(t?.symbol || ''))
    && !['ETH', 'SOL', 'BTC', 'ZEC'].includes(t.symbol)
    && /^0x[0-9a-fA-F]{40}$/.test(String(t.address || ''))
    && Number.isSafeInteger(t.assetId) && t.assetId > 1 && t.assetId < 2 ** 32
    && Number.isSafeInteger(t.decimals) && t.decimals >= 0 && t.decimals <= 18);
}

/// The bridges a network's config declares.
export function bridgesOf(net) {
  const b = net.bridges || {};
  const out = [];
  if (b.sol && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(b.sol.vault || '')) {
    out.push({ ...b.sol, key: 'sol', symbol: 'SOL', zy: 'SOL.zy', chainName: /devnet/.test(b.sol.network) ? 'Solana devnet' : /testnet/.test(b.sol.network) ? 'Solana testnet' : 'Solana', decimals: 9, network: b.sol.network, asset: hex(bridgedAsset(b.sol.network)) });
  }
  if (b.eth && /^0x[0-9a-fA-F]{40}$/.test(b.eth.vault || '') && Number.isSafeInteger(b.eth.chainId)) {
    const chainName = b.eth.chainId === 1 ? 'Ethereum' : 'Sepolia';
    const network = `eip155:${b.eth.chainId}`;
    out.push({ ...b.eth, key: 'eth', evm: true, symbol: 'ETH', zy: 'ETH.zy', chainName, decimals: 18, network, asset: hex(bridgedAsset(network)) });
    // ERC-20s into the same vault (BOLD, §68): approve, then deposit under
    // the token's own vault asset id. Each is its own asset on Zyn, named by
    // the symbol the deployment gives it.
    for (const t of evmTokens(b.eth)) {
      out.push({
        key: t.symbol.toLowerCase(), evm: true, symbol: t.symbol, zy: `${t.symbol}.zy`, chainName, decimals: t.decimals, network,
        vault: b.eth.vault, chainId: b.eth.chainId, explorer: b.eth.explorer, token: t.address, assetId: t.assetId, origin: t.address.slice(2).toLowerCase(),
        faucet: !!t.faucet && b.eth.chainId !== 1, asset: hex(bridgedAsset(network, unhex(t.address.slice(2).toLowerCase(), 20))),
        // A vault whose registry is read on its own chain (mainnet): the token
        // waits for it. Declared but unreachable is shut, never skipped.
        checkVault: b.eth.vaultRpc !== undefined, vaultRpc: typeof b.eth.vaultRpc === 'string' && b.eth.vaultRpc ? b.eth.vaultRpc : null,
      });
    }
  }
  if (b.btc && /^[0-9a-f]{64}$/.test(b.btc.internal || '')) {
    const chain = ['bitcoin', 'testnet4'].includes(b.btc.network) ? b.btc.network : 'signet';
    const network = { bitcoin: 'bitcoin', testnet4: 'bitcoin-test', signet: 'bitcoin-signet' }[chain];
    out.push({ ...b.btc, key: 'btc', symbol: 'BTC', zy: 'BTC.zy', chainName: chain === 'bitcoin' ? 'Bitcoin' : `Bitcoin ${chain}`, decimals: 8, chain, network, asset: hex(bridgedAsset(network)) });
  }
  return out;
}

/// `assets(uint32)` on a ZynVault: the token registered under an asset id.
export const VAULT_ASSETS = 'f8a80dc8';

/// The vault's answer to `assets(id)`: the token (lowercase), its decimals,
/// and whether the id is registered; null for anything else.
export function readVaultAsset(result) {
  const h = String(result ?? '').replace(/^0x/, '');
  if (!/^[0-9a-fA-F]{192}$/.test(h)) return null;
  return { token: `0x${h.slice(24, 64).toLowerCase()}`, decimals: Number(BigInt(`0x${h.slice(64, 128)}`)), registered: BigInt(`0x${h.slice(128, 192)}`) === 1n };
}

/// Whether `b`'s vault has registered `b.token` under `b.assetId`, read on
/// its chain through `b.vaultRpc`. A token the vault does not take yet would
/// be stuck in it, so anything short of that exact answer is false.
export async function vaultTakes(b) {
  if (!b.token || !b.checkVault) return true;
  if (!b.vaultRpc) return false;
  try {
    const r = await fetch(b.vaultRpc, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: b.vault, data: `0x${VAULT_ASSETS}${BigInt(b.assetId).toString(16).padStart(64, '0')}` }, 'latest'] }),
      signal: AbortSignal.timeout(10_000),
    });
    const a = readVaultAsset((await r.json())?.result);
    return !!a?.registered && a.token === String(b.token).toLowerCase();
  } catch {
    return false;
  }
}

/// Which bridges this chain has registered, what each has issued, and the fee.
/// A token on a vault checked on its own chain (mainnet BOLD) is live only
/// once the chain lists it and the vault has registered it; `waiting` says
/// which is missing.
export async function bridgeState(config) {
  const [bridged, market] = await Promise.all([loadBridged(config), objectCall(config.rpcUrl, 'zyn_market').catch(() => ({}))]);
  const bridges = await Promise.all(bridgesOf(config).map(async (b) => {
    const row = bridged.find((x) => x.asset === b.asset);
    const vault = await vaultTakes(b);
    return { ...b, live: !!row && vault, waiting: !vault ? 'vault' : !row ? 'chain' : null, issued: /^\d+$/.test(String(row?.issued ?? '')) ? BigInt(row.issued) : null };
  }));
  return { bridges, bps: BigInt(Number(market?.fees?.bridge_bps) || 0) };
}

/// Deposits that arrived for this wallet's codes, claimed into it. Returns them.
export async function claimDeposits(config, identity) {
  const waiting = await loadWaiting(config, identity).catch(() => []);
  if (waiting.length) await claimWaiting(config, identity);
  return waiting;
}

/// A fresh deposit code for one deposit made elsewhere. `kind` is the
/// bridge's key, or `to-zyn` for a private note moved into Zyn: a code is never
/// shared between two kinds, nor between two requests while there is room
/// (ledger.js bridgeMemo, audit 9 Oct 2026).
export const depositCode = async (config, identity, kind) => (await bridgeMemo(config, identity, { kind })).commitment;

/// A Bitcoin deposit address: the vault key tweaked by a fresh code of this
/// wallet's, derived here, with the bridge asked to watch it.
export async function btcDepositAddress(config, identity, b) {
  const commitment = await depositCode(config, identity, 'btc');
  await call(config, 'zyn_depositWatch', { network: b.network, commitment });
  return btc.depositAddress(b.internal, unhex(commitment, 32), b.chain);
}

const LAMPORT = 1_000_000_000n; // one lamport in WAD
const SAT = 10_000_000_000n; // one satoshi in WAD

function destinationBytes(b, text) {
  const t = String(text).trim();
  if (b.key === 'sol') return solanaKey(t);
  if (b.key === 'btc') {
    const script = btc.scriptOf(t, b.chain);
    if (!script) throw new Error(`That is not a ${b.chain === 'bitcoin' ? 'bc1' : 'tb1'}… address (segwit or Taproot)`);
    return script;
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(t)) throw new Error('That is not an Ethereum address');
  return unhex(t.slice(2).toLowerCase(), 20);
}

// Exits waiting to be revealed: a record kept on this device, shared by every page of Nap.
const bridgeExitsKey = (config) => `nap.bridge.exits.${config.chain}`;
const bridgeExits = (config) => { try { return JSON.parse(read(bridgeExitsKey(config)) || '[]'); } catch { return []; } };

export async function revealBridgeExits(config) {
  const left = [];
  for (const x of bridgeExits(config)) {
    try { await call(config, 'zyn_bridgeReveal', { asset: x.asset, address: x.address, salt: x.salt }); }
    catch (e) { if (!/no unpaid exit/.test(e.message)) left.push(x); }
  }
  write(bridgeExitsKey(config), JSON.stringify(left));
}

/// Check an exit before anything is signed: the address and the amount's
/// precision and floor for that chain.
export function checkBridgeOut(b, to, raw) {
  if (b.key === 'sol' && raw % LAMPORT !== 0n) throw new Error('SOL has nine decimal places');
  if (b.key === 'sol' && raw <= 5_000n * LAMPORT) throw new Error('Send more than the 0.000005 SOL network fee');
  if (b.key === 'btc' && raw % SAT !== 0n) throw new Error('BTC has eight decimal places');
  if (b.key === 'btc' && raw < 10_000n * SAT) throw new Error('Send at least 0.0001 BTC; the Bitcoin fee comes out of it');
  if (b.token && b.decimals < 18 && raw % 10n ** BigInt(18 - b.decimals) !== 0n) throw new Error(`${b.symbol} has ${b.decimals} decimal places`);
  return destinationBytes(b, to);
}

/// SOL.zy / ETH.zy / BOLD.zy / BTC.zy back to their chain: commit to the address,
/// burn, then show the address to the bridge that pays it.
export async function bridgeOut(config, identity, held, b, to, raw, bps) {
  return bridgeOutTo(config, identity, held, b, checkBridgeOut(b, to, raw), raw, bps);
}

/// The same, to destination bytes already checked: an address, or a private
/// pool note (§158.4), which the bridge inserts instead of paying.
export async function bridgeOutTo(config, identity, held, b, address, raw, bps) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const fee = (raw * bps) / 10_000n;
  const { inputs, change } = fund(identity, held, unhex(b.asset, 32), raw + fee);
  write(bridgeExitsKey(config), JSON.stringify([...bridgeExits(config), { asset: b.asset, address: hex(address), salt: hex(salt) }]));
  await submitIntent(config, identity, withdrawIntent({ holder: identity.account, inputs, asset: unhex(b.asset, 32), amount: raw, destination: exitCommitment(address, salt), outputs: change }));
  await revealBridgeExits(config);
}

// ---------------------------------------------------------------------------
// ZEC.zy out to Zcash, and the exits waiting to be revealed to the vault.

const exitsKey = (config, identity) => `nap.exits.${config.chain}.${identity.accountHex}`;
const pendingExits = (config, identity) => { try { return JSON.parse(read(exitsKey(config, identity)) || '[]'); } catch { return []; } };

export async function revealExits(config, identity) {
  const left = [];
  for (const x of pendingExits(config, identity)) {
    try { await objectCall(config.rpcUrl, 'zyn_exitReveal', { address: x.address, salt: x.salt }); }
    catch (e) { if (!/no unpaid exit/.test(e.message)) left.push(x); }
  }
  write(exitsKey(config, identity), JSON.stringify(left));
}

/// ZEC.zy out to a Zcash address: commit to the address, burn, then reveal
/// it to the vault. The bridge fee rides on top; the Zcash fee comes out.
export async function withdrawZec(config, identity, held, address, amountText) {
  const raw = parseAmount(amountText);
  if (raw % 10_000_000_000n !== 0n) throw new Error('ZEC has eight decimal places');
  if (raw < 100_000n * 10_000_000_000n) throw new Error('Withdraw at least 0.001 ZEC — the Zcash fee comes out of it');
  const salt = hex(crypto.getRandomValues(new Uint8Array(32)));
  const { destination } = await objectCall(config.rpcUrl, 'zyn_exitCommitment', { address, salt });
  if (!/^[0-9a-f]{64}$/.test(String(destination))) throw new Error('The node did not return a commitment');
  const market = await objectCall(config.rpcUrl, 'zyn_market');
  const fee = (raw * BigInt(Number(market?.fees?.bridge_bps) || 0)) / 10_000n;
  const zec = unhex(config.zecAsset, 32);
  const { inputs, change } = fund(identity, held, zec, raw + fee);
  write(exitsKey(config, identity), JSON.stringify([...pendingExits(config, identity), { address, salt }]));
  await submitIntent(config, identity, withdrawIntent({ holder: identity.account, inputs, asset: zec, amount: raw, destination: unhex(destination, 32), outputs: change }));
  await revealExits(config, identity);
}
