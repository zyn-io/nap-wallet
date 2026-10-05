// One Ethereum read the wallet needs: which token a bridge vault has
// registered under an asset id (`assets(uint32)`). Nap's pages talk to their
// own origin only (`connect-src 'self'`), so the read comes through here.
//
// Nothing else passes: one method (eth_call), one function selector, no
// value, no sender. It is not a general Ethereum endpoint.

const ROUTES = {
  mainnet: 'https://ethereum-rpc.publicnode.com',
  sepolia: 'https://ethereum-sepolia-rpc.publicnode.com',
};
/// `assets(uint32)`, the vault's registry.
const ASSETS = '0xf8a80dc8';

export async function onRequest({ request, params }) {
  const rest = Array.isArray(params.path) ? params.path.join('/') : (params.path || '');
  const upstream = ROUTES[rest];
  if (!upstream) return json({ error: 'no such chain' }, 404);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (request.method !== 'POST') return new Response('method not allowed', { status: 405, headers: { allow: 'POST' } });

  let body;
  try { body = JSON.parse(await request.text()); } catch { return json({ error: 'not JSON' }, 400); }
  const [call, block] = Array.isArray(body?.params) ? body.params : [];
  const keys = call && typeof call === 'object' ? Object.keys(call).sort().join() : '';
  if (body?.method !== 'eth_call' || keys !== 'data,to' || block !== 'latest'
    || !/^0x[0-9a-fA-F]{40}$/.test(String(call.to)) || !new RegExp(`^${ASSETS}[0-9a-f]{64}$`, 'i').test(String(call.data))) {
    return json({ error: 'only a vault registry read passes here' }, 400);
  }

  let response;
  try {
    response = await fetch(upstream, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: body.id ?? 1, method: 'eth_call', params: [{ to: call.to, data: call.data }, 'latest'] }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return json({ error: 'Ethereum is not answering' }, 502);
  }
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
