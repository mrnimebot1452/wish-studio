// GET /api/wish/:token
// The only public door to wish content. The database function decides what may be
// returned; before the unlock time it never includes heading, message or signature.
const enc = new TextEncoder();
const sha256 = async (s) =>
  [...new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

async function rpc(env, fn, body) {
  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: env.SUPABASE_SECRET_KEY },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`rpc ${fn} failed: ${r.status}`);
  return r.status === 204 ? null : r.json();
}

export async function onRequestGet({ params, env, request, waitUntil }) {
  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'X-Robots-Tag': 'noindex, nofollow',
  };
  const reply = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers });

  const token = String(params.token || '');
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(token)) return reply({ error: 'not_found' }, 404);

  try {
    const tokenHash = await sha256(token);
    const wish = await rpc(env, 'public_get_wish', { p_token_hash: tokenHash });
    if (!wish) return reply({ error: 'not_found' }, 404);
    delete wish.wish_id;

    // Photos live in a private bucket. Only after unlock does the database return their paths;
    // here they become temporary (1 hour) signed links.
    if (!wish.locked && Array.isArray(wish.photos) && wish.photos.length) {
      const r = await fetch(`${env.SUPABASE_URL}/storage/v1/object/sign/wish-photos`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', apikey: env.SUPABASE_SECRET_KEY },
        body: JSON.stringify({ expiresIn: 3600, paths: wish.photos.map((p) => p.path) }),
      });
      const signed = r.ok ? await r.json() : [];
      const byPath = Object.fromEntries(signed.map((x) => [x.path, x.signedURL]));
      wish.photos = wish.photos
        .map((p) => ({ caption: p.caption, url: byPath[p.path] ? `${env.SUPABASE_URL}/storage/v1${byPath[p.path]}` : null }))
        .filter((p) => p.url);
    }

    // Count a view once per visitor per 30 minutes (the database enforces that).
    // The visitor id is a one-way hash with a daily-changing salt; no IP is stored.
    if (!new URL(request.url).searchParams.has('poll')) {
      const day = new Date().toISOString().slice(0, 10);
      const ip = request.headers.get('CF-Connecting-IP') || '';
      const ua = request.headers.get('User-Agent') || '';
      const visitor = await sha256(`${env.VISITOR_SALT}|${day}|${ip}|${ua}`);
      waitUntil(rpc(env, 'record_view', { p_token_hash: tokenHash, p_visitor_hash: visitor }).catch(() => {}));
    }
    return reply(wish);
  } catch (e) {
    return reply({ error: 'server_error' }, 500);
  }
}
