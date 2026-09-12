const CACHE = 'nap-shell-v1';
const SHELL = ['/', '/config.json', '/manifest.webmanifest', '/nap-mark.png', '/fonts/BricolageGrotesque.ttf', '/fonts/IBMPlexSans.ttf', '/fonts/IBMPlexMono-Regular.ttf'];
self.addEventListener('install', (event) => event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL))));
self.addEventListener('activate', (event) => event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))));
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== location.origin || /^\/(rpc|claim|media)(\/|$)/.test(url.pathname)) return;
  event.respondWith(fetch(event.request).then((response) => {
    if (response.ok) caches.open(CACHE).then((cache) => cache.put(event.request, response.clone()));
    return response;
  }).catch(() => caches.match(event.request).then((hit) => hit || caches.match('/'))));
});
