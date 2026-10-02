// ZIP-321 payment requests: `zcash:<address>?amount=…&memo=…`.
//
// The one way Zcash wallets agree on for a site, a shop or a QR code to ask
// for a payment. Nap reads it in two places: pasted into Send, and handed to
// the connect window by a site (`zec_pay {uri}`). Either way it only fills in
// a payment the holder then reviews; nothing here sends anything.
//
// Nap pays one recipient per request. A multi-payment request (`address.1`,
// `amount.1`, …) is refused whole rather than paid in part, and so is any
// `req-` parameter this parser does not know — ZIP-321 says a wallet must not
// pay a request whose required parameters it does not understand.

const ZAT = 100_000_000n;

function base64urlBytes(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('The memo is not base64url');
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/// ZEC as written in a request ("1.5", "0.0001") to zatoshi.
export function zatoshiOf(text) {
  if (!/^\d+(\.\d{1,8})?$/.test(text)) throw new Error('The amount must be ZEC with at most eight decimals');
  const [whole, frac = ''] = text.split('.');
  const zat = BigInt(whole) * ZAT + BigInt(frac.padEnd(8, '0'));
  if (zat > 21_000_000n * ZAT) throw new Error('That is more ZEC than exists');
  return Number(zat);
}

/// `{address, zatoshi|null, memo, label, message}`, or an error saying why
/// the request cannot be paid.
export function parsePaymentRequest(uri) {
  const text = String(uri || '').trim();
  if (!/^zcash:/i.test(text)) throw new Error('A payment request starts with zcash:');
  const rest = text.slice(6);
  const q = rest.indexOf('?');
  const path = decodeURIComponent(q < 0 ? rest : rest.slice(0, q));
  const out = { address: path || null, zatoshi: null, memo: '', label: '', message: '' };
  const seen = new Set();
  if (q >= 0) {
    for (const part of rest.slice(q + 1).split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const rawKey = eq < 0 ? part : part.slice(0, eq);
      const value = decodeURIComponent((eq < 0 ? '' : part.slice(eq + 1)).replace(/\+/g, '%20'));
      const dot = rawKey.indexOf('.');
      const key = dot < 0 ? rawKey : rawKey.slice(0, dot);
      const index = dot < 0 ? '' : rawKey.slice(dot + 1);
      if (index !== '' && index !== '0') throw new Error('This request pays more than one recipient; Nap pays one per request');
      if (seen.has(key)) throw new Error(`The request names ${key} twice`);
      seen.add(key);
      switch (key) {
        case 'address': out.address = value; break;
        case 'amount': out.zatoshi = zatoshiOf(value); break;
        case 'memo': {
          const bytes = base64urlBytes(value);
          if (bytes.length > 512) throw new Error('The memo is longer than 512 bytes');
          try { out.memo = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
          catch { throw new Error('The memo is not text; Nap sends text memos only'); }
          break;
        }
        case 'label': out.label = value; break;
        case 'message': out.message = value; break;
        default:
          if (key.startsWith('req-')) throw new Error(`The request requires ${key}, which Nap does not understand`);
      }
    }
  }
  if (!out.address) throw new Error('The request names no address');
  if (out.memo && /^t/i.test(out.address)) throw new Error('A memo only reaches a shielded address');
  return out;
}

/// The inverse, for a page that wants to show a request of its own.
export function paymentRequest({ address, zatoshi, memo = '', message = '' }) {
  const params = [];
  if (zatoshi != null) {
    const v = BigInt(zatoshi);
    const frac = (v % ZAT).toString().padStart(8, '0').replace(/0+$/, '');
    params.push(`amount=${v / ZAT}${frac ? `.${frac}` : ''}`);
  }
  if (memo) {
    const bytes = new TextEncoder().encode(memo);
    params.push(`memo=${btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`);
  }
  if (message) params.push(`message=${encodeURIComponent(message)}`);
  return `zcash:${address}${params.length ? `?${params.join('&')}` : ''}`;
}
