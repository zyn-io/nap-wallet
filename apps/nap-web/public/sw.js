// Online-only until a versioned, atomic shell-cache design is tested. Never
// cache claim links, configuration, signed reads or transaction responses.
self.addEventListener('activate', (event) => event.waitUntil(
  caches.keys().then((keys) => Promise.all(keys.filter((key) => key.startsWith('nap-shell-')).map((key) => caches.delete(key))))
));
