// A SOL deposit into the bridge vault, with the memo that makes it this
// wallet's (DECISIONS §146): one legacy transaction, a system transfer and a
// memo, laid out here and handed to the holder's Solana wallet through the
// Wallet Standard, which signs and sends it. The same layout the Cave store
// uses for a burn (`apps/cave-collection-z/solana-burn.js`), with a transfer
// where the burn was.

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export const SYSTEM_PROGRAM = '11111111111111111111111111111111';
export const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const TRANSFER = 2;

export function b58decode(s) {
  let n = 0n;
  for (const c of s) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error('not base58');
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n % 256n)); n /= 256n; }
  for (const c of s) { if (c !== '1') break; bytes.unshift(0); }
  return Uint8Array.from(bytes);
}

export function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = '';
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = `1${out}`; }
  return out;
}

/// A Solana address as its 32 bytes, or a thrown error that says so.
export function solanaKey(s) {
  const k = b58decode(String(s).trim());
  if (k.length !== 32) throw new Error('That is not a Solana address');
  return k;
}

const shortVec = (n) => { const out = []; do { let b = n & 0x7f; n >>= 7; if (n) b |= 0x80; out.push(b); } while (n); return out; };
const u64le = (v) => { const b = new Uint8Array(8); let x = BigInt(v); for (let i = 0; i < 8; i++) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };

/// The message: the owner signs, pays and sends; the vault receives; the
/// system and memo programs are read.
export function depositMessage({ owner, vault, lamports, memo, blockhash }) {
  if (!/^zyn:[0-9a-f]{64}$/.test(memo)) throw new Error('The memo must be the one Nap gave');
  if (BigInt(lamports) <= 0n) throw new Error('Deposit something');
  const keys = [owner, vault, SYSTEM_PROGRAM, MEMO_PROGRAM].map(solanaKey);
  const data = [TRANSFER, 0, 0, 0, ...u64le(lamports)];
  const memoData = [...new TextEncoder().encode(memo)];
  return Uint8Array.from([
    1, 0, 2,
    ...shortVec(keys.length), ...keys.flatMap((k) => [...k]),
    ...solanaKey(blockhash),
    ...shortVec(2),
    2, ...shortVec(2), 0, 1, ...shortVec(data.length), ...data,
    3, ...shortVec(0), ...shortVec(memoData.length), ...memoData,
  ]);
}

/// A deposit into a private pool (DECISIONS §158): the owner pays one note
/// of the pool's size in, with the note's commitment. The system program and
/// the pool program are read.
export function poolDepositMessage({ owner, program, pool, commitment, blockhash }) {
  if (!/^[0-9a-f]{64}$/.test(commitment)) throw new Error('No note commitment');
  const keys = [owner, pool, SYSTEM_PROGRAM, program].map(solanaKey);
  const data = [1, ...commitment.match(/../g).map((h) => parseInt(h, 16))];
  return Uint8Array.from([
    1, 0, 2,
    ...shortVec(keys.length), ...keys.flatMap((k) => [...k]),
    ...solanaKey(blockhash),
    ...shortVec(1),
    3, ...shortVec(3), 0, 1, 2, ...shortVec(data.length), ...data,
  ]);
}

/// A transaction awaiting its one signature.
export function unsigned(message) {
  const out = new Uint8Array(1 + 64 + message.length);
  out[0] = 1;
  out.set(message, 65);
  return out;
}

/// Every Solana wallet that registers through the Wallet Standard.
export function solanaWallets() {
  const found = [];
  const register = (...ws) => {
    for (const w of ws) {
      if (w?.features?.['solana:signAndSendTransaction'] && w?.features?.['standard:connect'] && !found.includes(w)) found.push(w);
    }
  };
  try {
    window.addEventListener('wallet-standard:register-wallet', (e) => { try { e.detail?.({ register }); } catch { /* one wallet */ } });
    window.dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: { register } }));
  } catch { /* no window */ }
  return found;
}

export async function signAndSend(wallet, account, tx, chain) {
  const [r] = await wallet.features['solana:signAndSendTransaction'].signAndSendTransaction({ account, transaction: tx, chain });
  return b58encode(r.signature);
}
