// The sites that use Nap. Lending, bridging, the launchpad and the store
// live on them; Nap approves what they ask (Nap Connect) and holds what
// comes back. Nap has no bridge screen of its own: Bridge opens Lend's.
import { bridgesOf } from './bridges.js';

/// The apps, on the network the wallet is on.
export function appsFor(config) {
  const test = config?.id === 'testnet';
  const lend = test ? 'https://lend.zyn-network.com/' : 'https://lend.zyn-network.com/?network=mainnet';
  const coins = [...new Set(bridgesOf(config || {}).map((b) => b.symbol))];
  return [
    { name: 'Lend', what: 'Lending', url: lend },
    ...(coins.length ? [{ name: 'Bridge', what: `${coins.join(' · ')} in and out`, url: `${lend}#/bridge` }] : []),
    { name: 'Jade', what: 'Launchpad', url: /^https:\/\//.test(String(config?.launchpadUrl || '')) ? config.launchpadUrl : (test ? 'https://jade.zyn-network.com/?network=testnet' : 'https://jade.zyn-network.com/') },
    { name: 'Cave', what: 'Collection Z store', url: 'https://cavebro.win/' },
  ].map((a) => ({ ...a, host: new URL(a.url).host }));
}
