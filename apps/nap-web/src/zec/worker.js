// The Zcash wallet, off the page's thread.
//
// Proving a shielded payment takes the better part of a minute in a browser,
// on one core. Here it takes that minute without freezing the page.
//
// Messages in: `{id, op, args}` where `op` is an `engine` method. Out:
// `{id, step}` while it works, then `{id, ok, result}` or `{id, ok: false,
// error}`. The block server is the page's own origin (`url`), like every
// other endpoint the wallet talks to.

import init, * as zec from '../zec-pkg/nap_zec.js';
import { engine } from './engine.js';

let url = null;
const ready = init();

async function post(frame) {
  if (!url) throw new Error('No block server is configured for this network');
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: frame,
    cache: 'no-store',
  });
  if (!response.ok) throw new Error('The block server is not answering. Try again in a minute.');
  return new Uint8Array(await response.arrayBuffer());
}

let wallet = null;
// One job at a time: a sync and a send interleaved would both be reading
// and writing the same trees.
let queue = Promise.resolve();

self.onmessage = ({ data }) => {
  const { id, op, args = [] } = data || {};
  queue = queue.then(async () => {
    try {
      await ready;
      wallet ??= engine(zec, post);
      if (op === 'endpoint') { url = String(args[0] || ''); self.postMessage({ id, ok: true, result: null }); return; }
      if (typeof wallet[op] !== 'function') throw new Error(`unknown operation ${op}`);
      const step = (s) => self.postMessage({ id, step: s });
      // Every engine method that reports progress takes it as its last argument.
      const result = await wallet[op](...args, step);
      self.postMessage({ id, ok: true, result });
    } catch (e) {
      self.postMessage({ id, ok: false, error: String(e?.message || e) });
    }
  });
};
