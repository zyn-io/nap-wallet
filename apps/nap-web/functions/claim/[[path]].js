// The gift coordinator, which is not deployed.
//
// Said plainly rather than left to 404 as a routing accident: a holder who
// follows a claim link deserves to know the service is absent, not that their
// link is malformed.

export async function onRequest({ env }) {
  const base = env.ZYN_CLAIM_URL;
  if (!base) {
    return new Response(JSON.stringify({ error: 'gift claiming is not open on this deployment' }), {
      status: 503,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  }
  return new Response(JSON.stringify({ error: 'gift claiming is not open on this deployment' }), {
    status: 503,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}
