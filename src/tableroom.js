/**
 * TableRoom — one SQLite-backed Durable Object per timer room (T16).
 *
 * The laptop timer screen is the single source of truth: it holds one persistent
 * hibernatable WebSocket (role=host) and runs ALL clock math locally. Phones are
 * plain HTTP button-pressers — POST /api/remote/cmd is routed here, forwarded to
 * the host socket over WS, and the host's ACK {state} becomes the POST response.
 * The hub / D1 are never touched: a phone tap costs zero D1 reads.
 *
 * Lifecycle:
 *   - Room is created implicitly by the first host HELLO {key}; the secret is
 *     stored in DO storage, so a laptop reload / WS drop reclaims the same room.
 *   - Host WS closes -> 60s grace alarm; reconnect within it keeps the room.
 *   - Any activity pushes a 4h idle alarm; the alarm wipes orphan rooms.
 *   - Only the host may close the room ({type:'CLOSE'}).
 *
 * Hibernation: sockets are accepted via ctx.acceptWebSocket and the host role
 * lives in the socket's attachment, so the DO can sleep between commands.
 */

const ACK_TIMEOUT_MS = 3000;   // phone gives up; matches the command stale window
const STALE_MS = 10_000;       // generous vs phone clock skew; no live host -> command dropped anyway
const GRACE_MS = 60_000;       // room survives a host WS drop this long (laptop reload)
const IDLE_WIPE_MS = 4 * 3600_000; // orphan-room cleanup

const ACTIONS = new Set(['pass', 'reset', 'pause', 'resume', 'ext', 'new_rack']);

const doJson = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });

export class TableRoom {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    // seq-key ('cid:seq') -> { resolve, timer } — filled by /cmd, drained by ACKs
    this.pending = new Map();
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;

    if (path === '/api/remote/ws') {
      if (request.headers.get('upgrade') !== 'websocket') {
        return doJson({ error: 'websocket required' }, 426);
      }
      const pair = new WebSocketPair();
      // hibernation API: accept the SERVER end, return the CLIENT end (pair[0])
      // in the 101 — returning the accepted socket throws
      this.ctx.acceptWebSocket(pair[1], ['lobby']);
      return new Response(null, { status: 101, webSocket: pair[0] });
    }

    if (path === '/api/remote/cmd' && request.method === 'POST') {
      const body = await request.json().catch(() => null);
      const action = String(body?.action || '');
      const seq = Number(body?.seq);
      const ts = Number(body?.ts) || 0;
      const cid = String(body?.cid || '');
      if (!ACTIONS.has(action)) return doJson({ ok: false, error: 'unknown action' });
      if (!Number.isInteger(seq) || seq <= 0) return doJson({ ok: false, error: 'bad seq' });
      if (!/^[a-z0-9]{1,16}$/.test(cid)) return doJson({ ok: false, error: 'bad cid' });
      if (Date.now() - ts > STALE_MS) return doJson({ ok: false, stale: true, error: 'command expired' });

      const host = this.hostSocket();
      if (!host) return doJson({ ok: false, error: 'laptop offline' });

      this.touchAlarm();
      return new Promise(resolve => {
        const key = cid + ':' + seq;
        const timer = setTimeout(() => {
          this.pending.delete(key);
          resolve(doJson({ ok: false, error: 'ack timeout' }));
        }, ACK_TIMEOUT_MS);
        this.pending.set(key, { resolve, timer });
        try {
          host.send(JSON.stringify({ type: 'CMD', action, seq, cid, ts }));
        } catch (err) {
          clearTimeout(timer);
          this.pending.delete(key);
          resolve(doJson({ ok: false, error: 'laptop offline' }));
        }
      });
    }

    if (path === '/api/remote/status' && request.method === 'GET') {
      const has = await this.ctx.storage.get('key').then(v => v != null);
      return doJson({ room: has, host: has && !!this.hostSocket() });
    }

    return doJson({ error: 'not found' }, 404);
  }

  /* -------- WebSocket hibernation handlers -------- */

  async webSocketMessage(ws, message) {
    let msg = null;
    try { msg = JSON.parse(message); } catch { ws.close(4000, 'bad json'); return; }

    if (msg?.type === 'HELLO') {
      const key = String(msg?.key || '');
      if (!/^[A-Za-z0-9_-]{16,64}$/.test(key)) { ws.close(4000, 'bad key'); return; }
      const stored = await this.ctx.storage.get('key');
      if (stored == null) {
        await this.ctx.storage.put('key', key);
      } else if (stored !== key) {
        ws.close(4001, 'room taken'); // same code regenerated on another laptop
        return;
      }
      // adopt/replace: newest same-key socket is the host; older one is retired
      for (const other of this.ctx.getWebSockets()) {
        if (other !== ws && other.deserializeAttachment()?.role === 'host') {
          other.serializeAttachment({ role: 'retired' });
          try { other.close(4002, 'replaced'); } catch {}
        }
      }
      ws.serializeAttachment({ role: 'host' });
      this.touchAlarm();
      ws.send(JSON.stringify({ type: 'READY' }));
      return;
    }

    const role = ws.deserializeAttachment()?.role;
    if (role !== 'host') { ws.close(4003, 'not host'); return; }

    if (msg?.type === 'ACK') {
      const key = String(msg?.cid || '') + ':' + Number(msg?.seq);
      const p = this.pending.get(key);
      if (p) {
        clearTimeout(p.timer);
        this.pending.delete(key);
        p.resolve(doJson({ ok: true, state: msg?.state ?? null, stale: !!msg?.stale }));
      }
      return;
    }
    if (msg?.type === 'CLOSE') {
      await this.wipe('host closed');
      return;
    }
  }

  async webSocketClose(ws) {
    if (ws.deserializeAttachment()?.role === 'host' && !this.hostSocket()) {
      // grace window for a laptop reload / Wi-Fi blip, then the room is gone
      await this.ctx.storage.setAlarm(Date.now() + GRACE_MS);
    }
  }

  async alarm() {
    if (this.hostSocket()) { // still live — just push the next idle check
      await this.ctx.storage.setAlarm(Date.now() + IDLE_WIPE_MS);
      return;
    }
    await this.wipe('idle');
  }

  /* -------- helpers -------- */

  hostSocket() {
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.deserializeAttachment()?.role === 'host') return ws;
    }
    return null;
  }

  async touchAlarm() {
    // keep the furthest deadline: never shorten an existing grace/idle alarm
    const next = Date.now() + IDLE_WIPE_MS;
    const cur = await this.ctx.storage.getAlarm();
    if (cur == null || cur > next || cur < Date.now()) await this.ctx.storage.setAlarm(next);
  }

  async wipe(reason) {
    await this.ctx.storage.deleteAll();
    for (const ws of this.ctx.getWebSockets()) {
      try { ws.close(4004, reason); } catch {}
    }
  }
}
