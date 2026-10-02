// The unlocked wallet, while the browser (or the phone app) runs.
//
// A toolbar wallet opens and closes with every click; asking for the password
// (600,000 rounds of PBKDF2) each time would make it a lock screen with a
// wallet behind it. So once opened, the derived keys are held in
// `chrome.storage.session`: kept in memory, never written to disk, gone when
// the browser quits, and readable only by the extension's own pages — not by
// the content script that runs on websites. The phone app has no such store;
// there the app's own `sessionStorage` plays the part — it lives as long as
// the app's process, and the sites the Nap browser opens run in a separate
// web view with their own origin. It lapses after IDLE_MS without use, and
// Lock ends it at once. The website keeps asking, as before.
import { exportKeys, importKeys } from './core.js';
import { IN_APP } from './origin.js';

/// The same three calls over the app's sessionStorage.
const appStore = IN_APP && globalThis.sessionStorage ? {
  get: async (k) => { try { return { [k]: JSON.parse(sessionStorage.getItem(k) || 'null') }; } catch { return {}; } },
  set: async (o) => { for (const [k, v] of Object.entries(o)) sessionStorage.setItem(k, JSON.stringify(v)); },
  remove: async (k) => { sessionStorage.removeItem(k); },
} : null;
const store = globalThis.chrome?.storage?.session || appStore;
const KEY = 'nap.session';
export const IDLE_MS = 15 * 60 * 1000;
export const hasSession = !!store;

/// Hold the opened wallet for the extension's other pages and the next popup.
export async function saveSession(identity, receiving = []) {
  if (!store) return;
  await store.set({ [KEY]: { keys: exportKeys(identity, receiving), index: identity.accountIndex, until: Date.now() + IDLE_MS } }).catch(() => {});
}

/// The wallet opened earlier in this browser session, or null. Using it
/// pushes the idle deadline out again.
export async function loadSession() {
  if (!store) return null;
  try {
    const held = (await store.get(KEY))[KEY];
    if (!held?.keys) return null;
    if (!(held.until > Date.now())) { await store.remove(KEY); return null; }
    await store.set({ [KEY]: { ...held, until: Date.now() + IDLE_MS } });
    return importKeys(held.keys, held.index);
  } catch { return null; }
}

export async function endSession() {
  await store?.remove(KEY).catch(() => {});
}
