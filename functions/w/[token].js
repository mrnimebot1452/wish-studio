// GET /w/:token  ->  serves the wish page shell (it contains no wish content).
export async function onRequestGet({ request, env }) {
  const page = await env.ASSETS.fetch(new URL('/wish', request.url));
  const headers = new Headers(page.headers);
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Robots-Tag', 'noindex, nofollow');
  headers.set('Referrer-Policy', 'no-referrer');
  return new Response(page.body, { status: 200, headers });
}
