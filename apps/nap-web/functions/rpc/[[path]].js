// The wallet's only route to a chain.
//
// nap-web refuses any cross-origin endpoint — its CSP permits `connect-src
// 'self'` and `loadConfig` rejects a URL whose origin is not this one. That is
// deliberate: a browser wallet that could be pointed anywhere is a browser
// wallet that can be pointed somewhere bad. So the endpoint is a path here, and
// this relays it.
//
// Upstream is `ZYN_RPC_URL`, a project variable, so the gateway's address is
// not in the repo, not in a built asset, and not in any reply.

/// Which upstream path each route reaches. Naming them beats forwarding a
/// prefix: a chain the deployment has not declared cannot be reached by
/// guessing a URL.
///
/// `testnet` reaches `/object` — chain 212, the object ledger. It reached
/// `/testnet` until 22 Sep 2026, when chain 11 was retired; that upstream now
/// answers 410, so leaving this pointed at it would have kept the wallet's
/// testnet asking a chain that is gone. The route name is the wallet's word
/// for "the testnet", and the testnet is 212.
const ROUTES = { '': '', testnet: 'object' };

// Who is asking, for the gateway's rate limit. Every request from here
// reaches the gateway from a few Cloudflare addresses, so a limit keyed on
// the connection is one budget shared by every Nap user. The visitor's own
// address goes along instead, with ZYN_RELAY_KEY so the gateway can tell this
// relay from anyone setting the header. It is used for the limit only, and not logged.
function relayHeaders(request, env, contentType) {
  const headers = { 'content-type': contentType };
  const client = request.headers.get('cf-connecting-ip');
  if (env.ZYN_RELAY_KEY && client) {
    headers['x-zyn-relay-key'] = env.ZYN_RELAY_KEY;
    headers['x-zyn-client'] = client;
  }
  return headers;
}

export async function onRequest({ request, env, params }) {
  const base = env.ZYN_RPC_URL;
  if (!base) return json({ error: 'no chain endpoint configured' }, 503);

  const rest = Array.isArray(params.path) ? params.path.join('/') : (params.path || '');
  const upstream = ROUTES[rest];
  if (upstream === undefined) return json({ error: 'no such chain' }, 404);

  // JSON-RPC is POST. A GET here would be a browser following a link into the
  // chain, which is never what the wallet is doing.
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (request.method !== 'POST') {
    return new Response('method not allowed', { status: 405, headers: { allow: 'POST' } });
  }

  let response;
  try {
    response = await fetch(base.replace(/\/$/, '') + '/' + upstream, {
      method: 'POST',
      headers: relayHeaders(request, env, 'application/json'),
      body: await request.text(),
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    // Never the upstream's own words: they would name it.
    return json({ error: 'the chain is not answering' }, 502);
  }

  // The gateway's replies are already JSON-RPC, envelope and all, so they pass
  // through untouched — re-encoding would be a chance to corrupt a signature.
  return new Response(await response.text(), {
    status: response.status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}
