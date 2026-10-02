// Nap moved from nap.cavebro.win to nap.zyn-network.com on 2 Oct 2026. The old
// host still serves the same pages — the 0.3.1 extension and the first phone
// build call it, and a wallet kept in a browser lives on the origin that kept
// it — so there is no redirect. Instead the old host says where Nap is now and
// how to get the wallet there. The packaged builds (extension, phone app) and
// the new host never show it.

export const OLD_HOST = 'nap.cavebro.win';
export const NEW_ORIGIN = 'https://nap.zyn-network.com';

/// The same page on the new host, or null when this page needs no notice.
export function movedLink(loc, packaged = false) {
  if (packaged || loc.hostname !== OLD_HOST) return null;
  return NEW_ORIGIN + loc.pathname + loc.search + loc.hash;
}

/// Put the notice at the top of the page. Plain text and one link; nothing of
/// the page's own is touched.
export function showMoved(packaged = false, loc = location, doc = document) {
  const href = movedLink(loc, packaged);
  if (!href || doc.querySelector('.nap-moved')) return null;
  const bar = doc.createElement('div');
  bar.className = 'nap-moved';
  bar.setAttribute('role', 'note');
  const link = doc.createElement('a');
  link.href = href;
  link.textContent = 'nap.zyn-network.com';
  bar.append('Nap is now at ', link, ' — restore with your 24 words there.');
  doc.body.prepend(bar);
  return bar;
}
