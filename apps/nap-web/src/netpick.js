// The network control the market and the bridge share with the wallet.
//
// One key, `nap.network`, read by every page on this origin: choosing a chain
// here is choosing it for the wallet too, and the other way round. Not a
// secret — it names a public chain — so localStorage is the right place.

export const NETWORK_KEY = 'nap.network';

export const rememberNetwork = (id) => { try { localStorage.setItem(NETWORK_KEY, id); } catch { /* private window: this page only */ } };

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/// The header pill: a select when the deployment has more than one network,
/// a label when it has one. The chain number is detail, dropped on a phone.
export function networkPill(config) {
  const nets = config.networks || [];
  const chain = `<span class="net-chain">· chain ${esc(config.chain)}</span>`;
  if (nets.length < 2) return `<span class="network"><i></i>${esc(config.network)} ${chain}</span>`;
  return `<label class="network network-pick" title="Switch network"><i></i><span class="visually-hidden">Network</span><select id="network-pick">${nets.map((n) => `<option value="${esc(n.id)}"${n.id === config.id ? ' selected' : ''}>${esc(n.network)}</option>`).join('')}</select>${chain}</label>`;
}

/// Wire the pill. `onPick(id)` returns false to refuse (the select snaps back).
export function bindNetworkPick(root, config, onPick) {
  const pick = root.querySelector('#network-pick');
  if (!pick) return;
  pick.addEventListener('change', () => {
    if (onPick(pick.value) === false) pick.value = config.id;
  });
}
