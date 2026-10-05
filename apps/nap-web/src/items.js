// Items: what a held item is called, and its picture.
//
// Collection Z (§86) is frozen: its 4,444 pictures are named by the SHA-256
// of their bytes, in serial order, in `public/art/<collection>.bin` (32 bytes
// each, from cavebro.win/collection-z.json). That file ships with Nap and
// names nobody's items, so reading it tells no one anything. The picture
// itself comes from the media gateway by its hash — which does tell that host
// which item is being looked at — so it is fetched only once the holder turns
// artwork on (`artOn`), and its bytes are checked against the hash before
// they are shown.
import { boundedBytes, MAX_IMAGE, pngSize, safeRaster } from './media.js';

/// Collection Z's species share one index space (§86.1).
export const CAVE_Z = '024277b607ce4edbf78fe2855aba562096d00264729168bd0ddea71bdf5b5f1e';
export function itemName(collection, serial) {
  if (collection !== CAVE_Z) return `${collection.slice(0, 6)}… #${serial}`;
  const [species, start] = serial < 2222 ? ['Mole', 0] : serial < 3555 ? ['Owl', 2222] : ['Moth', 3555];
  return `Zyn ${species} #${String(serial - start + 1).padStart(4, '0')}`;
}

/// The collections whose pictures Nap knows, with how many each has.
const ART = new Map([[CAVE_Z, 4444]]);

/// The same page on cavebro.win, for a Collection Z item.
export function caveLink(config, collection, serial) {
  if (collection !== CAVE_Z) return null;
  return `https://cavebro.win/item?collection=${collection}&serial=${serial}${config?.id === 'testnet' ? '&network=testnet' : ''}`;
}

// The holder's choice, shared by every page of Nap on this device. Off until
// they say otherwise; storage that refuses means off.
const ART_KEY = 'nap_web_art';
export function artOn() {
  try { return localStorage.getItem(ART_KEY) === '1'; } catch { return false; }
}
export function setArtOn(on) {
  try { localStorage.setItem(ART_KEY, on ? '1' : '0'); } catch { /* this page only */ }
}

const indexes = new Map();
async function index(collection) {
  if (!ART.has(collection)) return null;
  if (!indexes.has(collection)) {
    indexes.set(collection, fetch(`/art/${collection}.bin`, { credentials: 'omit' })
      .then((r) => (r.ok ? r.arrayBuffer() : null))
      .then((b) => (b && b.byteLength === ART.get(collection) * 32 ? new Uint8Array(b) : null))
      .catch(() => null));
  }
  return indexes.get(collection);
}

const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/// The hash of an item's picture, or null when Nap does not know it.
export async function artHash(collection, serial) {
  const idx = await index(collection);
  if (!idx || !Number.isSafeInteger(serial) || serial < 0 || serial >= idx.length / 32) return null;
  return hexOf(idx.subarray(serial * 32, serial * 32 + 32));
}

// One fetch per picture per page: the popup redraws its panels as balances
// refresh, and each redraw must not ask the gateway again.
const pictures = new Map();

/// An object URL for the item's picture, its bytes checked against the hash;
/// null when there is none, it is not a PNG Nap can show, or artwork is off.
export function itemArt(config, collection, serial) {
  if (!artOn() || !config?.mediaGateway) return Promise.resolve(null);
  const key = `${collection}:${serial}`;
  if (!pictures.has(key)) {
    pictures.set(key, (async () => {
      const hash = await artHash(collection, serial);
      if (!hash) return null;
      const bytes = await boundedBytes(`${config.mediaGateway.replace(/\/$/, '')}/${hash}`, MAX_IMAGE);
      if (hexOf(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))) !== hash) return null;
      const size = pngSize(bytes);
      if (!size || !safeRaster({ mime: 'image/png', bytes: bytes.length, ...size }, bytes)) return null;
      return URL.createObjectURL(new Blob([bytes], { type: 'image/png' }));
    })().catch(() => { pictures.delete(key); return null; }));
  }
  return pictures.get(key);
}

/// Drop every picture this page holds (on lock).
export function forgetArt() {
  for (const p of pictures.values()) void p.then((url) => url && URL.revokeObjectURL(url));
  pictures.clear();
}

/// Fill every `[data-art="<collection>:<serial>"]` image under `root` that
/// has a picture.
export function fillArt(config, root) {
  if (!artOn()) return;
  for (const img of root.querySelectorAll('img[data-art]')) {
    const [collection, serial] = img.dataset.art.split(':');
    void itemArt(config, collection, Number(serial)).then((url) => {
      if (url && img.isConnected) { img.src = url; img.classList.add('real'); }
    });
  }
}
