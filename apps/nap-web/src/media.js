import { hex } from './core.js';

export const MAX_MANIFEST = 256 * 1024;
export const MAX_IMAGE = 8 * 1024 * 1024;
const decoder = new TextDecoder('utf-8', { fatal: true });
const DOMAIN = 'zyn.manifest.v1';

export function parseManifest(bytes) {
  if (bytes.length > MAX_MANIFEST) throw new Error('Manifest too large');
  let at = 0;
  const take = (n) => {
    if (!Number.isSafeInteger(n) || n < 0 || at + n > bytes.length) throw new Error('Truncated manifest');
    const result = bytes.slice(at, at + n); at += n; return result;
  };
  const u32 = () => new DataView(take(4).buffer).getUint32(0);
  const u64 = () => {
    const n = new DataView(take(8).buffer).getBigUint64(0);
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Unsafe media size');
    return Number(n);
  };
  const text = () => decoder.decode(take(u32()));
  const count = () => { const n = u32(); if (n > 1024) throw new Error('Too many manifest entries'); return n; };
  if (decoder.decode(take(new TextEncoder().encode(DOMAIN).length)) !== DOMAIN) throw new Error('Wrong manifest domain');
  const name = text(), description = text(), media = [], attributes = [];
  for (let n = count(), i = 0; i < n; i++) {
    const role = take(1)[0];
    if (role > 1) throw new Error('Unknown media role');
    media.push({ role, hash: hex(take(32)), mime: text(), bytes: u64(), width: u32(), height: u32(), duration: u32() });
  }
  for (let n = count(), i = 0; i < n; i++) attributes.push({ trait: text(), value: text() });
  if (at !== bytes.length) throw new Error('Trailing manifest data');
  return { name, description, media, attributes };
}

export async function boundedBytes(url, max) {
  const response = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Media HTTP ${response.status}`);
  const reader = response.body.getReader();
  const chunks = []; let length = 0;
  try {
    if (Number(response.headers.get('content-length')) > max) throw new Error('Media too large');
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > max) throw new Error('Media too large');
      chunks.push(value);
    }
  } finally { await reader.cancel(); reader.releaseLock(); }
  const bytes = new Uint8Array(length); let at = 0;
  for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.length; }
  return bytes;
}

export function safeRaster(media, bytes) {
  if (!media.width || !media.height || media.width > 4096 || media.height > 4096 || media.bytes > MAX_IMAGE) return false;
  // No SVG/HTML or script-capable media, even when correctly committed.
  if (media.mime === 'image/png' && bytes.length >= 24) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return hex(bytes.slice(0, 8)) === '89504e470d0a1a0a' && decoder.decode(bytes.slice(12, 16)) === 'IHDR'
      && view.getUint32(16) === media.width && view.getUint32(20) === media.height;
  }
  // Add other raster types only with pre-decode dimension validation.
  return false;
}
