// Content-addressed art, by hash.
//
// The wallet verifies the bytes against the name before rendering them, so this
// host is a byte source and not an authority — which is exactly why it can be a
// plain static site. Nothing here is trusted; the hash is.

export async function onRequest({ request, env, params }) {
  const name = Array.isArray(params.path) ? params.path.join('/') : (params.path || '');
  // A 64-hex name is the whole vocabulary. Anything else is not an artefact
  // this gateway knows how to be wrong about.
  if (!/^[0-9a-f]{64}$/i.test(name)) return new Response('not a content hash', { status: 404 });
  if (request.method !== 'GET') return new Response('method not allowed', { status: 405, headers: { allow: 'GET' } });

  const base = env.MEDIA_ORIGIN || 'https://cavebro.win/blobs';
  try {
    const upstream = await fetch(`${base.replace(/\/$/, '')}/${name.toLowerCase()}`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!upstream.ok) return new Response('no such blob', { status: 404 });
    return new Response(upstream.body, {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        // Immutable by construction: the name is the hash of the bytes.
        'cache-control': 'public, max-age=31536000, immutable',
        'x-content-type-options': 'nosniff',
      },
    });
  } catch {
    return new Response('the media gateway is not answering', { status: 502 });
  }
}
