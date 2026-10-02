// The attendance-certificate service (DECISIONS §150; zynzapd's zyn-attend),
// one per network: `/attend/…` reaches ZYN_ATTEND_URL (mainnet) and
// `/attend/testnet/…` ZYN_ATTEND_TESTNET_URL. Only its two doors pass: POST
// /attend (a tap and an account) and GET /events (the public list). Unset, the
// wallet is told plainly that this network hands out no certificates.
const NETWORKS = { '': 'ZYN_ATTEND_URL', testnet: 'ZYN_ATTEND_TESTNET_URL' };
const DOORS = { attend: 'POST', events: 'GET' };

export async function onRequest({ request, env, params }) {
  const parts = Array.isArray(params.path) ? params.path : [params.path].filter(Boolean);
  const net = parts.length === 2 ? parts[0] : '';
  const door = parts[parts.length - 1];
  const base = env[NETWORKS[net]];
  if (!(net in NETWORKS) || !(door in DOORS)) return json({ error: 'no such door' }, 404);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (request.method !== DOORS[door]) return new Response('method not allowed', { status: 405, headers: { allow: DOORS[door] } });
  if (!base) return json({ error: 'Certificates are not handed out on this network yet.' }, 503);
  let response;
  try {
    response = await fetch(`${base.replace(/\/$/, '')}/${door}`, {
      method: DOORS[door],
      headers: { 'content-type': 'application/json' },
      body: door === 'attend' ? (await request.text()).slice(0, 8192) : undefined,
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    return json({ error: 'The certificate service is not answering.' }, 502);
  }
  return new Response(await response.text(), { status: response.status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}

function json(body, status) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}
