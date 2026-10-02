// A small "i" that opens a bubble. Headings stay short; anything that needs
// explaining goes behind one of these. One bubble on the page at a time.

const attr = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

/// The button, as markup. `text` is plain text: it is shown with textContent.
export const tip = (text, label = 'More about this') =>
  `<button type="button" class="tip" data-tip="${attr(text)}" aria-label="${attr(label)}" aria-expanded="false">i</button>`;

let bubble = null;
let owner = null;

function close() {
  if (!bubble) return;
  bubble.hidden = true;
  owner?.setAttribute('aria-expanded', 'false');
  owner = null;
}

function open(btn) {
  if (!bubble) {
    bubble = document.createElement('div');
    bubble.className = 'tip-bubble';
    bubble.id = 'tip-bubble';
    bubble.setAttribute('role', 'tooltip');
    bubble.hidden = true;
    document.body.append(bubble);
  }
  if (owner === btn) return close();
  close();
  owner = btn;
  bubble.textContent = btn.dataset.tip;
  bubble.hidden = false;
  btn.setAttribute('aria-expanded', 'true');
  btn.setAttribute('aria-describedby', 'tip-bubble');
  // Below the button, kept inside the viewport; above it if there is no room.
  const r = btn.getBoundingClientRect();
  const w = Math.min(320, innerWidth - 24);
  bubble.style.width = `${w}px`;
  const left = Math.max(12, Math.min(r.left + r.width / 2 - w / 2, innerWidth - w - 12));
  bubble.style.left = `${left + scrollX}px`;
  const below = r.bottom + 8;
  const h = bubble.offsetHeight;
  const top = below + h > innerHeight - 12 && r.top - h - 8 > 12 ? r.top - h - 8 : below;
  bubble.style.top = `${top + scrollY}px`;
}

/// Once per page: any `.tip` anywhere, now or later, opens its bubble.
export function installTips() {
  if (installTips.done) return;
  installTips.done = true;
  document.addEventListener('click', (e) => {
    const btn = e.target.closest?.('.tip');
    if (btn) {
      e.preventDefault();
      e.stopPropagation();
      open(btn);
    } else if (!e.target.closest?.('.tip-bubble')) close();
  }, true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
  addEventListener('resize', close);
}
