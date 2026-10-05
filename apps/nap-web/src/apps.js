// The sites that use Nap. Lending, bridging, the launchpad and the store
// live on them; Nap approves what they ask (Nap Connect) and holds what
// comes back.

/// The apps, on the network the wallet is on.
export function appsFor(config) {
  const test = config?.id === 'testnet';
  return [
    { name: 'Lend', what: 'Lending · bridges', url: test ? 'https://lend.zyn-network.com/' : 'https://lend.zyn-network.com/?network=mainnet' },
    { name: 'Jade', what: 'Launchpad', url: /^https:\/\//.test(String(config?.launchpadUrl || '')) ? config.launchpadUrl : (test ? 'https://jade.zyn-network.com/?network=testnet' : 'https://jade.zyn-network.com/') },
    { name: 'Cave', what: 'Collection Z store', url: 'https://cavebro.win/' },
  ].map((a) => ({ ...a, host: new URL(a.url).host }));
}
