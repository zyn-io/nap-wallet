// The bridges (§146, §154, §155), shared by the toolbar wallet (pocket.js)
// and Nap Connect (connect-ops.js), so a site's bridge page and Nap's own
// follow one set of rules. No page, no Vite: it runs in Node's tests too.
import { hex, parseAmount, unhex } from './core.js';
import { bridgedAsset, exitCommitment, fund } from './market.js';
import { bridgeMemo, call, claimWaiting, loadBridged, loadWaiting, submitIntent } from './ledger.js';
import * as btc from './bitcoin.js';
import { solanaKey } from './solana.js';
import { objectCall, withdrawIntent } from './object.js';

/// Where bridging happens on testnet: the lending app's Bridge tab, where
/// Phantom and MetaMask can reach the page (they cannot reach Nap's own
/// extension pages). Mainnet keeps Nap's page for the ETH pilot until the app
/// serves mainnet.
export const LEND_BRIDGE = 'https://lend.zyn-network.com/#/bridge';
export const bridgePage = (config) => (config?.id === 'testnet' ? LEND_BRIDGE : null);
/// A deposit handed over with its one-time code, on the page for `config`.
export const handoffUrl = (config, key, code, fallback) => (bridgePage(config) ? `${LEND_BRIDGE}/deposit/${key}?code=${code}` : fallback);

const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* this session only */ } };

/// The bridges a network's config declares, as bridge.html reads them.
export function bridgesOf(net) {
  const b = net.bridges || {};
  const out = [];
  if (b.sol && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(b.sol.vault || '')) {
    out.push({ ...b.sol, key: 'sol', symbol: 'SOL', zy: 'SOL.zy', chainName: /devnet/.test(b.sol.network) ? 'Solana devnet' : /testnet/.test(b.sol.network) ? 'Solana testnet' : 'Solana', decimals: 9, network: b.sol.network, asset: hex(bridgedAsset(b.sol.network)) });
  }
  if (b.eth && /^0x[0-9a-fA-F]{40}$/.test(b.eth.vault || '') && Number.isSafeInteger(b.eth.chainId)) {
    out.push({ ...b.eth, key: 'eth', symbol: 'ETH', zy: 'ETH.zy', chainName: b.eth.chainId === 1 ? 'Ethereum' : 'Sepolia', decimals: 18, network: `eip155:${b.eth.chainId}`, asset: hex(bridgedAsset(`eip155:${b.eth.chainId}`)) });
  }
  if (b.btc && /^[0-9a-f]{64}$/.test(b.btc.internal || '')) {
    const chain = ['bitcoin', 'testnet4'].includes(b.btc.network) ? b.btc.network : 'signet';
    const network = { bitcoin: 'bitcoin', testnet4: 'bitcoin-test', signet: 'bitcoin-signet' }[chain];
    out.push({ ...b.btc, key: 'btc', symbol: 'BTC', zy: 'BTC.zy', chainName: chain === 'bitcoin' ? 'Bitcoin' : `Bitcoin ${chain}`, decimals: 8, chain, network, asset: hex(bridgedAsset(network)) });
  }
  return out;
}

/// Which bridges this chain has registered, what each has issued, and the fee.
export async function bridgeState(config) {
  const [bridged, market] = await Promise.all([loadBridged(config), objectCall(config.rpcUrl, 'zyn_market').catch(() => ({}))]);
  const bridges = bridgesOf(config).map((b) => {
    const row = bridged.find((x) => x.asset === b.asset);
    return { ...b, live: !!row, issued: /^\d+$/.test(String(row?.issued ?? '')) ? BigInt(row.issued) : null };
  });
  return { bridges, bps: BigInt(Number(market?.fees?.bridge_bps) || 0) };
}

/// Deposits that arrived for this wallet's codes, claimed into it. Returns them.
export async function claimDeposits(config, identity) {
  const waiting = await loadWaiting(config, identity).catch(() => []);
  if (waiting.length) await claimWaiting(config, identity);
  return waiting;
}

/// This wallet's one-time deposit code, for a deposit made elsewhere.
export const depositCode = async (config, identity) => (await bridgeMemo(config, identity)).commitment;

/// A Bitcoin deposit address: the vault key tweaked by this wallet's code,
/// derived here, with the bridge asked to watch it.
export async function btcDepositAddress(config, identity, b) {
  const commitment = await depositCode(config, identity);
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

// Exits waiting to be revealed — the record bridge.html keeps, shared.
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
  return destinationBytes(b, to);
}

/// SOL.zy / ETH.zy / BTC.zy back to their chain: commit to the address,
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
