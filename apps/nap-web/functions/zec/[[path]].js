// The Zcash wallet's route to a block server.
//
// The same arrangement as `/rpc`: the page may only talk to its own origin,
// so the block server is a path here and this relays it. The body is one
// `zyn-lightd` request frame and the reply is the server's reply frame, both
// binary and both passed through untouched. What crosses is compact blocks,
// tree states, transactions by id, and finished transactions to broadcast —
// never a key, never a shielded address.
//
// Upstream is `ZYN_RPC_URL`, the same gateway `/rpc` uses; the block servers
// sit behind it at the paths below.

const ROUTES = { mainnet: 'zec', testnet: 'zec-testnet' };

/// A SEND carries a whole shielded transaction — tens of kilobytes. The
/// server refuses more than this too; refusing it here saves the trip.
const MAX_BODY = 1 << 20;

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
  if (!base) return text('no block server configured', 503);

  const rest = Array.isArray(params.path) ? params.path.join('/') : (params.path || '');
  const upstream = ROUTES[rest];
  if (upstream === undefined) return text('no such network', 404);

  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (request.method !== 'POST') {
    return new Response('method not allowed', { status: 405, headers: { allow: 'POST' } });
  }
  const body = await request.arrayBuffer();
  if (body.byteLength === 0 || body.byteLength > MAX_BODY) return text('request frame too large', 413);

  let response;
  try {
    response = await fetch(base.replace(/\/$/, '') + '/' + upstream, {
      method: 'POST',
      headers: relayHeaders(request, env, 'application/octet-stream'),
      body,
      // A first scan asks for blocks the server has not compacted yet, and
      // each one is a read from Zebra. Generous, but bounded.
      signal: AbortSignal.timeout(60_000),
    });
  } catch {
    return text('the block server is not answering', 502);
  }
  if (!response.ok) return text('the block server is not answering', 502);
  return new Response(await response.arrayBuffer(), {
    status: 200,
    headers: { 'content-type': 'application/octet-stream', 'cache-control': 'no-store' },
  });
}

function text(body, status) {
  return new Response(body, { status, headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' } });
}
