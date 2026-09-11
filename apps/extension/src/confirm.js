const id = Number(new URLSearchParams(location.search).get('id'));
chrome.runtime.sendMessage({ kind: 'confirm:get', id }).then((req) => {
  if (!req || req.error) { document.getElementById('desc').textContent = 'This request is gone.'; return; }
  document.getElementById('origin').textContent = req.origin;
  document.getElementById('desc').textContent = req.description;
  document.getElementById('params').textContent = JSON.stringify(req.params, null, 2);
});
const answer = (approved) => chrome.runtime.sendMessage({ kind: 'confirm:answer', id, approved }).then(() => window.close());
document.getElementById('approve').onclick = () => answer(true);
document.getElementById('reject').onclick = () => answer(false);
window.addEventListener('beforeunload', () => chrome.runtime.sendMessage({ kind: 'confirm:answer', id, approved: false }));
