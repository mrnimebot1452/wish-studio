// POST /api/admin/create  and  POST /api/admin/link
// Only the single owner may call these: the caller's login token is verified with
// Supabase and checked against the app_owner table before anything happens.
const PUB = 'sb_publishable_ubyQDK6dEb-9z9OQYCH1rg_CavmDv7_'; // public key, safe to keep here
const enc = new TextEncoder();
const dec = new TextDecoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const aesKey = (env) =>
  crypto.subtle.importKey('raw', Uint8Array.from(env.TOKEN_ENC_KEY.match(/../g).map((h) => parseInt(h, 16))), 'AES-GCM', false, ['encrypt', 'decrypt']);
const sb = (env, path, init = {}) =>
  fetch(env.SUPABASE_URL + path, {
    ...init,
    headers: { apikey: env.SUPABASE_SECRET_KEY, 'Content-Type': 'application/json', ...(init.headers || {}) },
  });

async function isOwner(env, request) {
  const jwt = (request.headers.get('Authorization') || '').replace(/^Bearer /, '');
  if (!jwt) return false;
  const u = await fetch(env.SUPABASE_URL + '/auth/v1/user', { headers: { apikey: PUB, Authorization: 'Bearer ' + jwt } });
  if (!u.ok) return false;
  const user = await u.json();
  const o = await (await sb(env, '/rest/v1/app_owner?select=owner_id')).json();
  return Array.isArray(o) && o[0] && o[0].owner_id === user.id;
}

const FIELDS = ['occasion', 'custom_occasion', 'recipient_name', 'event_date', 'unlock_at', 'heading', 'message', 'signature',
  'theme', 'accent_color', 'animation_style', 'animation_intensity', 'show_intro', 'tap_to_continue', 'photo_link_url', 'status'];

export async function onRequestPost({ request, env, params }) {
  const out = (o, s = 200) =>
    new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  try {
    if (!(await isOwner(env, request))) return out({ error: 'forbidden' }, 403);
    const b = await request.json().catch(() => ({}));
    const key = await aesKey(env);

    if (params.action === 'link') {
      const r = await (await sb(env, `/rest/v1/wishes?id=eq.${encodeURIComponent(b.id)}&select=token_enc`)).json();
      if (!r[0]) return out({ error: 'not_found' }, 404);
      const [iv, ct] = r[0].token_enc.split('.');
      const token = dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(ct)));
      return out({ link: new URL('/w/' + token, request.url).href });
    }

    if (params.action === 'create') {
      const row = {};
      for (const f of FIELDS) if (b[f] !== undefined) row[f] = b[f];
      const token = b64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const iv = crypto.getRandomValues(new Uint8Array(12));
      row.token_hash = await sha(token);
      row.token_enc = b64(iv) + '.' + b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(token)));
      const r = await sb(env, '/rest/v1/wishes', { method: 'POST', headers: { Prefer: 'return=representation' }, body: JSON.stringify(row) });
      const j = await r.json();
      if (!r.ok) return out({ error: j.message || 'Invalid data' }, 400);
      return out({ id: j[0].id, link: new URL('/w/' + token, request.url).href });
    }
    return out({ error: 'not_found' }, 404);
  } catch (e) {
    return out({ error: 'server_error' }, 500);
  }
} 
