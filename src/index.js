/**
 * NYIT Pool — Cloudflare Worker entry point.
 *
 * Routing:
 *   /api/*  -> handled here (future home of the Table Queue backend)
 *   *       -> static assets from public/ (the pool timer SPA)
 *
 * Env bindings (see wrangler.jsonc):
 *   env.ASSETS — Static Assets binding
 *   env.DB     — D1 database (Table Queue storage, placeholder)
 */

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });

const QUEUE_SELECT = `
  SELECT id, team_name, players, status, created_at
  FROM queue_entries
  WHERE status IN ('playing', 'waiting')
  ORDER BY CASE status WHEN 'playing' THEN 0 ELSE 1 END, id
`;

async function handleApi(request, env, url) {
  const { pathname } = url;
  const method = request.method;

  // liveness probe
  if (pathname === '/api/health') {
    return json({ ok: true, time: new Date().toISOString() });
  }

  if (!env.DB) return json({ error: 'D1 not bound' }, 501);

  // ---- Table Queue ----
  if (pathname === '/api/queue') {
    if (method === 'GET') {
      const { results } = await env.DB.prepare(QUEUE_SELECT).all();
      return json({ queue: results });
    }

    if (method === 'POST') { // join the queue
      const body = await request.json().catch(() => null);
      const team = typeof body?.team_name === 'string' ? body.team_name.trim().slice(0, 32) : '';
      if (!team) return json({ error: 'team_name required' }, 400);
      const players = typeof body?.players === 'string' ? body.players.trim().slice(0, 128) : '';
      const { meta } = await env.DB
        .prepare('INSERT INTO queue_entries (team_name, players) VALUES (?, ?)')
        .bind(team, players)
        .run();
      return json({ ok: true, id: meta.last_row_id }, 201);
    }

    return json({ error: 'method not allowed' }, 405);
  }

  // finish current game and promote the first waiting team
  if (pathname === '/api/queue/next' && method === 'POST') {
    const { results } = await env.DB.prepare(QUEUE_SELECT).all();
    const playing = results.find(r => r.status === 'playing');
    const next = results.find(r => r.status === 'waiting');
    const stmts = [];
    if (playing) stmts.push(
      env.DB.prepare('UPDATE queue_entries SET status = ? WHERE id = ?').bind('done', playing.id));
    if (next) stmts.push(
      env.DB.prepare('UPDATE queue_entries SET status = ? WHERE id = ?').bind('playing', next.id));
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true, finished: playing ? playing.id : null, next: next ? next.id : null });
  }

  const entry = pathname.match(/^\/api\/queue\/(\d+)$/);
  if (entry) {
    const id = Number(entry[1]);

    if (method === 'PATCH') { // change status (only one team may be playing)
      const body = await request.json().catch(() => null);
      const status = body?.status;
      if (!['waiting', 'playing', 'done'].includes(status)) {
        return json({ error: 'status must be waiting | playing | done' }, 400);
      }
      const stmts = [];
      if (status === 'playing') stmts.push(
        env.DB.prepare("UPDATE queue_entries SET status = 'done' WHERE status = 'playing'"));
      stmts.push(
        env.DB.prepare('UPDATE queue_entries SET status = ? WHERE id = ?').bind(status, id));
      const results = await env.DB.batch(stmts);
      const changed = results[results.length - 1].meta.changes;
      if (!changed) return json({ error: 'not found' }, 404);
      return json({ ok: true, id, status });
    }

    if (method === 'DELETE') {
      const { meta } = await env.DB
        .prepare('DELETE FROM queue_entries WHERE id = ?').bind(id).run();
      if (!meta.changes) return json({ error: 'not found' }, 404);
      return json({ ok: true, id });
    }

    return json({ error: 'method not allowed' }, 405);
  }

  return json({ error: 'not found' }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        return json({ error: 'internal error', detail: String(err?.message || err) }, 500);
      }
    }

    // everything else: static assets (public/)
    return env.ASSETS.fetch(request);
  },
};
