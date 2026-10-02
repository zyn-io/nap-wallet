// Nap's phone app is the same wallet in a native shell (apps/nap-mobile): its
// pages load from the app itself — `tauri://localhost` on iOS,
// `http(s)://tauri.localhost` on Android — and reach these routes cross-origin.
// Those origins, and only those, may read the replies. A web page elsewhere
// still cannot: its origin is not on the list, so the browser keeps the reply
// from it, as before. (The extension needs none of this: its host permission
// exempts it.)
const APP_ORIGINS = new Set(['tauri://localhost', 'http://tauri.localhost', 'https://tauri.localhost']);

export async function onRequest({ request, next }) {
  const origin = request.headers.get('origin');
  const app = origin && APP_ORIGINS.has(origin);
  if (app && request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': origin,
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type, idempotency-key',
        'access-control-max-age': '86400',
        vary: 'origin',
      },
    });
  }
  const response = await next();
  if (!app) return response;
  const out = new Response(response.body, response);
  out.headers.set('access-control-allow-origin', origin);
  out.headers.append('vary', 'origin');
  return out;
}
