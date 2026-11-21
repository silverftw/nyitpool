/**
 * BearBreak — Cloudflare Worker.
 *
 *   /api/*  -> auth, queue parties, skip votes, match confirmation, leaderboard
 *   *       -> static assets (public/)
 *
 * Bindings (wrangler.jsonc): env.ASSETS (assets), env.DB (D1).
 * Secrets (`wrangler secret put ...` / .dev.vars for local):
 *   ADMIN_PIN       — admin override actions (X-Admin-Pin header)
 *   SESSION_SECRET  — HMAC key for session tokens (falls back to ADMIN_PIN)
 */

import { rate, composite, expected } from './glicko2.js';
import { TableRoom } from './tableroom.js';

// Durable Object class export (wrangler.jsonc: TABLE_ROOM -> TableRoom)
export { TableRoom };

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
const bad = (msg, status = 400) => json({ error: msg }, status);
const enc = new TextEncoder();
const clamp = (v, min, max) => Math.min(max, Math.max(min, v));

/* ============================ auth / crypto ============================ */

const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));      // standard (padded)
const b64url = buf =>                                                       // url-safe (tokens)
  b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = s => atob(s.replace(/-/g, '+').replace(/_/g, '/'));

async function pbkdf2(pin, saltB64) {
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 }, key, 256);
  return b64url(bits);
}

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function sign(payload, secret) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const sig = b64url(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)));
  return `${body}.${sig}`;
}

async function verify(token, secret) {
  if (typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret),
    Uint8Array.from(fromB64url(sig), c => c.charCodeAt(0)), enc.encode(body));
  if (!ok) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(
      Uint8Array.from(fromB64url(body), c => c.charCodeAt(0))));
    if (!payload.uid || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

const sessionSecret = env => env.SESSION_SECRET || env.ADMIN_PIN || 'dev-insecure-secret';

async function issueToken(uid, env) {
  return sign({ uid, exp: Date.now() + 30 * 24 * 3600 * 1000 }, sessionSecret(env));
}

/* ============================ auth IP watchlist ============================ */
/* 2026-11-21 admin-pin compromise: known attacker source IPs live in the
   ip_watchlist DB table (migration 0011), NOT in code — the repo is public
   and a public watchlist tells the attacker they're flagged. Rows are
   prefixes (residential/mobile IPv6 rotates), matched with startsWith; a hit
   is a lead, not proof. Every auth attempt from a watched prefix writes an
   audit_log row with the account + IP. Managed via /api/admin/watchlist;
   never auto-ban on a hit. */
function clientIp(request) {
  return request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip') || 'unknown';
}

async function watchedPrefix(db, ip) {
  const rows = await db.prepare('SELECT prefix FROM ip_watchlist').all();
  return rows.results.map(r => r.prefix).find(p => ip.startsWith(p)) || null;
}

/* Record an auth attempt: every one lands in audit_log (redacted) AND
   login_history (full detail, admin-only query) — see migration 0012. */
async function auditAuth(env, kind, username, request, ok, userId = null) {
  const ip = clientIp(request);
  let hit = null;
  try { hit = await watchedPrefix(env.DB, ip); } catch { /* watchlist must never break auth */ }
  await audit(env.DB, hit ? 'watchlist_hit' : 'auth_ip',
    userId, `${kind} @${username} ip=${ip}${hit ? ' matched=***' : ''}${ok ? '' : ' FAILED'}`);
  try {
    await env.DB.prepare(
      'INSERT INTO login_history (at, kind, username, user_id, ip, ok, matched_prefix) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(Date.now(), kind, username, userId, ip, ok ? 1 : 0, hit).run();
  } catch { /* history must never break auth */ }
  if (hit) console.warn(`WATCHLIST HIT: ${kind} @${username} ip=${ip}${ok ? '' : ' (failed auth)'}`);
}

async function currentUser(request, env) {
  const h = request.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const payload = await verify(token, sessionSecret(env));
  if (!payload) return null;
  return (await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.uid).first()) || null;
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);
  if (!user) throw new HttpError(401, 'sign in required');
  return user;
}

async function isAdmin(request, env) {
  const pin = request.headers.get('x-admin-pin');
  if (!pin || !env.ADMIN_PIN) return false;
  const a = await crypto.subtle.digest('SHA-256', enc.encode(pin));
  const b = await crypto.subtle.digest('SHA-256', enc.encode(env.ADMIN_PIN));
  return b64url(a) === b64url(b);
}

async function validQueueKey(request, env) {
  if (!env.QUEUE_KEY) return true; // no secret set -> open access
  const k = request.headers.get('x-queue-key') || '';
  const a = await crypto.subtle.digest('SHA-256', enc.encode(k));
  const b = await crypto.subtle.digest('SHA-256', enc.encode(env.QUEUE_KEY));
  return b64url(a) === b64url(b);
}

/* How long a scanned QR key stays valid, counted from the scan on that device.
   The secret is static, so the window is per-browser (memory-only): the server
   advertises the TTL here and the client enforces the countdown. */
const QUEUE_KEY_TTL_MS = 30 * 60 * 1000;

class HttpError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

/* ============================ queue mode: time windows + admin override ============================ */
/* Base mode comes from ET time windows (9am–9pm open; duo-only noon–6pm; closed otherwise).
   An admin (X-Admin-Pin) may override to 'open' | 'duo-only' | 'offline' — or 'auto' to
   hand control back to the clock. Effective mode = override ?? window mode. */

const TZ = 'America/New_York';
const DEFAULT_SCHED = { open: '09:00', duo_start: '12:00', duo_end: '18:00', close: '21:00' };
const SCHED_KEYS = ['open', 'duo_start', 'duo_end', 'close'];
const hm = s => { const [h, m] = String(s).split(':').map(Number); return h * 60 + m; };

/* TEST_TIME_OVERRIDE pins the clock for tests: "10:00" (time only) or
   "2026-11-27 10:00" (a full date, so weekday-dependent rules can be tested). */
const TTO_RE = /^(?:(\d{4}-\d{2}-\d{2})\s+)?(\d{1,2}):(\d{2})$/;

function nyMinutes(env) {
  const m = TTO_RE.exec(env.TEST_TIME_OVERRIDE || '');
  if (m) return (Number(m[2]) % 24) * 60 + Number(m[3]);
  const parts = new Intl.DateTimeFormat('en-US',
    { timeZone: TZ, hour: 'numeric', minute: 'numeric', hour12: false }).formatToParts(new Date());
  const h = Number(parts.find(p => p.type === 'hour').value) % 24;
  const min = Number(parts.find(p => p.type === 'minute').value);
  return h * 60 + min;
}

/* ET weekday, 0=Sun..6=Sat — used by the no-logging-Fridays rule */
function nyWeekday(env) {
  const m = TTO_RE.exec(env.TEST_TIME_OVERRIDE || '');
  if (m && m[1]) return new Date(m[1] + 'T12:00:00Z').getUTCDay();
  const w = new Intl.DateTimeFormat('en-US', { timeZone: TZ, weekday: 'short' }).format(new Date());
  return ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(w);
}

function windowMode(env, sched) {
  const t = nyMinutes(env);
  if (t < hm(sched.open) || t >= hm(sched.close)) return 'offline';
  if (hm(sched.duo_start) < hm(sched.duo_end) && t >= hm(sched.duo_start) && t < hm(sched.duo_end)) return 'duo-only';
  return 'open';
}

async function queueConfig(db) {
  const { results } = await db.prepare(
    "SELECT key, value FROM queue_settings WHERE key IN ('mode_override','sched_open','sched_close','sched_duo_start','sched_duo_end')"
  ).all();
  const map = Object.fromEntries(results.map(r => [r.key, r.value]));
  const schedule = {};
  for (const k of SCHED_KEYS) schedule[k] = map['sched_' + k] || DEFAULT_SCHED[k];
  return { override: map.mode_override || null, schedule };
}

async function setOverride(db, mode /* null = auto */) {
  if (mode == null) {
    await db.prepare("DELETE FROM queue_settings WHERE key = 'mode_override'").run();
    return;
  }
  await db.prepare(
    "INSERT INTO queue_settings (key, value, updated_at) VALUES ('mode_override', ?, ?) " +
    'ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
  ).bind(mode, Date.now()).run();
}

async function setSchedule(db, sched) {
  await db.batch(SCHED_KEYS.map(k =>
    db.prepare(
      `INSERT INTO queue_settings (key, value, updated_at) VALUES ('sched_${k}', ?, ?) ` +
      'ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
    ).bind(sched[k], Date.now())));
}

/* offline (window or override) wipes the live queue on touch */
async function clearQueue(db) {
  await db.batch([
    db.prepare("UPDATE queue_parties SET status = 'skipped' WHERE status IN ('waiting','playing')"),
    db.prepare('DELETE FROM skip_votes'),
  ]);
}

/* dead-row purge: 'skipped' parties are terminal and nothing reads them after
   the day closes (skip votes already die with the nightly clear), so the
   parties table would otherwise hold every party ever. Delete them at most
   once a day, keeping only the last 24h so a same-evening skip still exists
   while its players are around. FKs cascade — each dead party's skip_votes
   and team_up_requests go with it. */
const PURGE_INTERVAL_MS = 24 * 60 * 60 * 1000;
let lastPurgeAt = 0;
async function purgeDeadPartiesIfDue(db) {
  if (Date.now() - lastPurgeAt < PURGE_INTERVAL_MS) return;
  lastPurgeAt = Date.now(); // set first: concurrent polls must not double-run
  await db.prepare("DELETE FROM queue_parties WHERE status = 'skipped' AND created_at < ?")
    .bind(Date.now() - PURGE_INTERVAL_MS).run();
}

async function effectiveMode(db, env) {
  const { override, schedule } = await queueConfig(db);
  return { mode: override || windowMode(env, schedule), override, schedule };
}

/* ============================ queue helpers ============================ */

async function promoteNext(db) {
  // the table hosts TWO parties at once (winner stays, challenger from the queue);
  // promote the earliest waiting party with actual players while fewer than two
  // are playing — blank admin stub parties are skipped; half-empty duos go up
  // like anyone else and can pick up their P2 at the table
  const PROMOTE = `UPDATE queue_parties SET status = 'playing'
    WHERE id = (SELECT id FROM queue_parties WHERE status = 'waiting'
                AND (p1_user_id IS NOT NULL OR p1_guest_name IS NOT NULL
                     OR p2_user_id IS NOT NULL OR p2_guest_name IS NOT NULL)
                ORDER BY position LIMIT 1)
      AND (SELECT COUNT(*) FROM queue_parties WHERE status = 'playing') < 2`;
  await db.batch([db.prepare(PROMOTE), db.prepare(PROMOTE)]);
}

const PARTY_SELECT = `
  SELECT p.id, p.format, p.status, p.position, p.created_at,
         p.created_by_user_id, p.p1_user_id, p.p1_guest_name, p.p2_user_id, p.p2_guest_name,
         p.stuck, p.pickup_open,
         u1.nickname AS p1_nick, u1.username AS p1_user, u1.glicko_rating AS p1_elo, u1.glicko_rd AS p1_rd,
         u2.nickname AS p2_nick, u2.username AS p2_user, u2.glicko_rating AS p2_elo, u2.glicko_rd AS p2_rd,
         (SELECT COUNT(*) FROM skip_votes v WHERE v.party_id = p.id) AS votes,
         pi.created_at AS invite_at, tu.nickname AS invite_nick, tu.username AS invite_user
  FROM queue_parties p
  LEFT JOIN users u1 ON u1.id = p.p1_user_id
  LEFT JOIN users u2 ON u2.id = p.p2_user_id
  LEFT JOIN team_up_requests pi
    ON pi.id = (SELECT id FROM team_up_requests WHERE party_id = p.id AND kind = 'invite'
                AND status = 'pending' ORDER BY id DESC LIMIT 1)
  LEFT JOIN users tu ON tu.id = pi.target_user_id
`;

/* full detail for a pending/disputed match: rosters, both teams, outstanding
   confirmations — only served on the fetch-on-open /api/pending endpoint,
   never on the 5s notification poll (rosters: admins rule on disputes) */
const PENDING_DETAIL = `
  pm.id, pm.match_type, pm.format, pm.winner_team, pm.status, pm.created_at,
  (SELECT COUNT(*) FROM pending_match_players x
   WHERE x.pending_match_id = pm.id AND x.confirmed = 0) AS unconfirmed,
  (SELECT group_concat(
     CASE WHEN mp.user_id IS NOT NULL
          THEN (SELECT nickname || ' @' || username FROM users u WHERE u.id = mp.user_id)
          ELSE 'Guest: ' || mp.guest_name END, ' | ')
   FROM pending_match_players mp WHERE mp.pending_match_id = pm.id AND mp.team = 1) AS team1,
  (SELECT group_concat(
     CASE WHEN mp.user_id IS NOT NULL
          THEN (SELECT nickname || ' @' || username FROM users u WHERE u.id = mp.user_id)
          ELSE 'Guest: ' || mp.guest_name END, ' | ')
   FROM pending_match_players mp WHERE mp.pending_match_id = pm.id AND mp.team = 2) AS team2,
  (SELECT group_concat(
     CASE WHEN mp.user_id IS NOT NULL
          THEN (SELECT nickname || ' @' || username FROM users u WHERE u.id = mp.user_id)
          ELSE mp.guest_name END, ', ')
   FROM pending_match_players mp
   WHERE mp.pending_match_id = pm.id AND mp.confirmed = 0) AS awaiting_names,
  (SELECT group_concat(
     CASE WHEN mp.user_id IS NOT NULL
          THEN (SELECT nickname || ' @' || username FROM users u WHERE u.id = mp.user_id)
          ELSE mp.guest_name END, ', ')
   FROM pending_match_players mp
   WHERE mp.pending_match_id = pm.id AND mp.confirmed = 1) AS confirmed_names`;

function shapeParty(row) {
  const mk = (uid, nick, user, elo, guest) => uid
    ? { id: uid, name: nick, username: user, elo: Math.round(elo), registered: true }
    : guest
      ? { id: null, name: `Guest: ${guest}`, username: null, elo: null, registered: false }
      : null;
  return {
    id: row.id, format: row.format, status: row.status, votes: row.votes, position: row.position,
    stuck: !!row.stuck, pickup_open: !!row.pickup_open,
    pending_invite: row.invite_at
      ? { nickname: row.invite_nick, username: row.invite_user,
          expires_at: row.invite_at + TEAMUP_TTL_MS }
      : null,
    p1: mk(row.p1_user_id, row.p1_nick, row.p1_user, row.p1_elo, row.p1_guest_name),
    p2: mk(row.p2_user_id, row.p2_nick, row.p2_user, row.p2_elo, row.p2_guest_name),
  };
}

/* favored-side win probability for the two ON-THE-TABLE parties: Glicko-2 E
   between composite teams (same avg-rating/avg-RD trick the rating engine uses).
   Guests have no rating — a side with zero registered players hides the line. */
function tableWinProb(rows) {
  const playing = rows.filter(r => r.status === 'playing');
  if (playing.length !== 2) return null;
  const team = r => {
    const t = [];
    if (r.p1_user_id != null) t.push({ glicko_rating: r.p1_elo, glicko_rd: r.p1_rd });
    if (r.p2_user_id != null) t.push({ glicko_rating: r.p2_elo, glicko_rd: r.p2_rd });
    return t;
  };
  const t1 = team(playing[0]), t2 = team(playing[1]);
  if (!t1.length || !t2.length) return null;
  const e = expected(composite(t1), composite(t2));
  const fav = e >= 0.5 ? playing[0] : playing[1];
  // highest-elo REGISTERED player on the favored side names the team
  const has1 = fav.p1_user_id != null, has2 = fav.p2_user_id != null;
  const nickname = has2 && (!has1 || fav.p2_elo > fav.p1_elo) ? fav.p2_nick : fav.p1_nick;
  return { nickname, pct: Math.round(Math.max(e, 1 - e) * 100) };
}

/* admin roster edits: resolve a slot spec ({user_id}|{guest_name}|null) to columns */
const slotDesc = s => (s.userId ? 'u' + s.userId : (s.guest ? '"' + s.guest + '"' : 'empty'));
async function resolveSlot(db, spec) {
  if (spec == null) return { userId: null, guest: null };
  if (spec.user_id != null) {
    const u = await db.prepare('SELECT id FROM users WHERE id = ?').bind(Number(spec.user_id)).first();
    if (!u) throw new HttpError(400, 'player not found');
    return { userId: u.id, guest: null };
  }
  const g = String(spec.guest_name || '').trim().slice(0, 24);
  return g ? { userId: null, guest: g } : { userId: null, guest: null };
}
/* a registered player may only sit in ONE live party */
async function userInLiveParty(db, userId, excludeId) {
  return db.prepare(
    `SELECT id FROM queue_parties WHERE status IN ('waiting','playing')
     AND id != ? AND (p1_user_id = ? OR p2_user_id = ?)`
  ).bind(excludeId, userId, userId).first();
}

/* ---------- team-up requests ---------- */
/* "Team up" on a waiting open duo with a REGISTERED owner sends a request the
   owner accepts or declines (2 min TTL, lazy expiry) instead of claiming
   instantly. Guest-led / blank duos keep the old direct claim — a guest has
   no session to approve with. The accept path performs the exact old claim
   (including team-switch detach rules), so nothing else changes. */
const TEAMUP_TTL_MS = 2 * 60 * 1000;

/* the queue poll runs the lazy expiry sweep on EVERY poll from EVERY device;
   once a minute per isolate is plenty (the TTL is lazy already — mutation
   paths still sweep inline before acting, so answering stays fresh) */
const SWEEP_INTERVAL_MS = 60 * 1000;
let lastQueueSweepAt = 0;

function expireTeamUps(db) {
  // invite expiry (declines set it directly): a still-open duo whose invite
  // died parks in "stuck" until it finds a partner
  lastQueueSweepAt = Date.now(); // mutation sweeps count toward the poll gate too
  return db.batch([
    db.prepare(
      "UPDATE team_up_requests SET status = 'expired' WHERE status = 'pending' AND created_at <= ?"
    ).bind(Date.now() - TEAMUP_TTL_MS),
    db.prepare(
      `UPDATE queue_parties SET stuck = 1
       WHERE status = 'waiting' AND p2_user_id IS NULL AND p2_guest_name IS NULL AND stuck = 0
         AND id IN (SELECT party_id FROM team_up_requests
                    WHERE kind = 'invite' AND status = 'expired')`
    ),
  ]);
}

/* poll-path sweep: skip the pair of maintenance UPDATEs unless the last
   sweep (from a poll or a mutation) is older than SWEEP_INTERVAL_MS */
async function sweepQueueIfDue(db) {
  if (Date.now() - lastQueueSweepAt < SWEEP_INTERVAL_MS) return;
  await expireTeamUps(db);
}

/* the old instant claim: put `user` in the party's open P2 slot, switching
   teams (detaching from their current party) when they are queued elsewhere.
   Same split rules as leave: a solo / half-empty old party disbands, otherwise
   the slot just frees up. */
async function performClaim(env, user, party) {
  const elsewhere = await userInLiveParty(env.DB, user.id, party.id);
  const stmts = [];
  let switchFrom = null, oldDisbanded = false;
  if (elsewhere) {
    const old = await env.DB.prepare('SELECT * FROM queue_parties WHERE id = ?').bind(elsewhere.id).first();
    const hasP2 = !!(old.p2_user_id || old.p2_guest_name);
    const leaverIsP1 = old.p1_user_id === user.id;
    const disband = old.format === 'solo' || !hasP2;
    switchFrom = old.id;
    oldDisbanded = disband;
    if (disband) {
      stmts.push(env.DB.prepare("UPDATE queue_parties SET status = 'skipped' WHERE id = ?").bind(old.id));
      stmts.push(env.DB.prepare('DELETE FROM skip_votes WHERE party_id = ?').bind(old.id));
    } else if (leaverIsP1) {
      stmts.push(env.DB.prepare(
        `UPDATE queue_parties SET p1_user_id = p2_user_id, p1_guest_name = p2_guest_name,
         p2_user_id = NULL, p2_guest_name = NULL WHERE id = ?`
      ).bind(old.id));
    } else {
      stmts.push(env.DB.prepare(
        'UPDATE queue_parties SET p2_user_id = NULL, p2_guest_name = NULL WHERE id = ?'
      ).bind(old.id));
    }
    stmts.push(env.DB.prepare(
      'DELETE FROM skip_votes WHERE party_id = ? AND voter_user_id = ?').bind(old.id, user.id));
  }
  stmts.push(env.DB.prepare(
    'UPDATE queue_parties SET p2_user_id = ?, stuck = 0, pickup_open = 0 WHERE id = ?'
  ).bind(user.id, party.id));
  await env.DB.batch(stmts);
  if (oldDisbanded) await promoteNext(env.DB); // the old party may have freed a table seat
  return { switched: switchFrom != null, from: switchFrom, oldDisbanded };
}

/* ---------- duo invites (owner asks a specific player to fill P2) ---------- */
/* The reverse of a claim: the party owner (or the joiner at queue-join time)
   picks a registered teammate, who gets a popup to accept/decline. Guests can
   own invites too (guest-led duos) — requester is then null and the guest
   proves ownership by nickname, same as leave. */
async function createTeamUpInvite(env, party, requester /* user row or null */, targetId) {
  const target = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(Number(targetId)).first();
  if (!target) throw new HttpError(400, 'player not found');
  if (target.id === party.p1_user_id || target.id === party.p2_user_id) {
    throw new HttpError(400, 'that player is already on this party');
  }
  if (requester) {
    const live = await env.DB.prepare(
      "SELECT id, party_id FROM team_up_requests WHERE requester_user_id = ? AND status = 'pending' ORDER BY id LIMIT 1"
    ).bind(requester.id).first();
    if (live) {
      throw new HttpError(live.party_id === party.id ? 409 : 409,
        live.party_id === party.id
          ? 'you already have a request pending for this party'
          : 'you already have a pending team-up request');
    }
  }
  const now = Date.now();
  const { meta } = await env.DB.prepare(
    `INSERT INTO team_up_requests (party_id, requester_user_id, target_user_id, kind, created_at, status)
     VALUES (?, ?, ?, 'invite', ?, 'pending')`
  ).bind(party.id, requester ? requester.id : null, target.id, now).run();
  return { id: meta.last_row_id, party_id: party.id, target: target.id, expires_at: now + TEAMUP_TTL_MS };
}

/* a guest proves party ownership by the nickname they joined with (leave does
   the same); registered owners match by session */
function partyOwnerAuth(user, party, body) {
  if (user) return party.p1_user_id === user.id;
  return !party.p1_user_id && !!party.p1_guest_name
    && String(body?.guest_name || '').trim().toLowerCase() === party.p1_guest_name.toLowerCase();
}

/* ============================ audit log ============================ */

async function audit(db, type, actorUserId, detail = '') {
  try {
    await db.prepare('INSERT INTO audit_log (at, type, actor_user_id, detail) VALUES (?, ?, ?, ?)')
      .bind(Date.now(), type, actorUserId ?? null, String(detail).slice(0, 200)).run();
  } catch { /* audit must never break the request */ }
}

/* ============================ moderation events (T25 honeypot) ============================ */
/* The shared admin PIN is burned (2026-11-21 compromise). The 🔒 unlock prompt
   is now a honeypot: it NEVER unlocks. Anyone who submits the OLD pre-rotation
   PIN gets a mod_events infraction — tied to their account when signed in,
   IP-only otherwise. Honest typos (any other PIN) are not logged. The value is
   a plain const on purpose: it's a burned password, and the ROADMAP records it
   too — secrecy no longer matters, only the paper trail does. */
const OLD_ADMIN_PIN = '9182';

async function logModEvent(env, kind, userId, request, detail) {
  try {
    await env.DB.prepare(
      'INSERT INTO mod_events (kind, user_id, ip, detail, created_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(kind, userId, clientIp(request), detail, Date.now()).run();
  } catch { /* moderation logging must never break the request */ }
}

/* every recently skipped party with the voters named — shared verbatim by
   /api/admin/skip-history and the Moderation Notifications skip feed */
async function recentSkips(db) {
  const week = Date.now() - 7 * 24 * 3600 * 1000;
  const { results: rows } = await db.prepare(
    `SELECT p.id, p.format, MAX(v.created_at) AS skipped_at,
            p.p1_user_id, p.p1_guest_name, u1.nickname AS p1_nick, u1.username AS p1_user,
            p.p2_user_id, p.p2_guest_name, u2.nickname AS p2_nick, u2.username AS p2_user
     FROM queue_parties p
     JOIN skip_votes v ON v.party_id = p.id
     LEFT JOIN users u1 ON u1.id = p.p1_user_id
     LEFT JOIN users u2 ON u2.id = p.p2_user_id
     WHERE p.status = 'skipped' AND v.created_at > ?1
     GROUP BY p.id ORDER BY skipped_at DESC LIMIT 20`
  ).bind(week).all();
  const skips = [];
  for (const r of rows) {
    const { results: voters } = await db.prepare(
      `SELECT u.nickname, u.username FROM skip_votes v
       JOIN users u ON u.id = v.voter_user_id
       WHERE v.party_id = ? ORDER BY v.created_at`
    ).bind(r.id).all();
    const member = (uid, nick, uname, guest) => uid
      ? { name: nick, username: uname, registered: true }
      : guest ? { name: 'Guest: ' + guest, username: null, registered: false } : null;
    skips.push({
      party_id: r.id, format: r.format, skipped_at: r.skipped_at,
      members: [member(r.p1_user_id, r.p1_nick, r.p1_user, r.p1_guest_name),
                member(r.p2_user_id, r.p2_nick, r.p2_user, r.p2_guest_name)].filter(Boolean),
      voters,
    });
  }
  return skips;
}

/* ============================ match commit ============================ */

/* Recompute EVERY player's Glicko-2 + W/L from the full remaining match history.
   Used after admin deletes/edits a committed match: resets all players to
   defaults and replays every match in played_at order, so the changed match's
   gains/losses vanish exactly as if it never happened. */
async function replayAllRatings(db) {
  const users = (await db.prepare('SELECT id FROM users ORDER BY id LIMIT 500').all()).results;
  const state = new Map(); // id -> {rating, rd, vol, rw, rl, cw, cl, last}
  for (const u of users) {
    state.set(u.id, { rating: 1500, rd: 350, vol: 0.06, rw: 0, rl: 0, cw: 0, cl: 0, last: null });
  }
  const matches = (await db.prepare(
    'SELECT id, match_type, winner_team, played_at FROM matches ORDER BY played_at, id LIMIT 2000').all()).results;
  const players = (await db.prepare(
    'SELECT match_id, team, user_id FROM match_players WHERE user_id IS NOT NULL').all()).results;
  const byMatch = new Map();
  for (const p of players) {
    if (!byMatch.has(p.match_id)) byMatch.set(p.match_id, []);
    byMatch.get(p.match_id).push(p);
  }
  const avg = arr => ({
    rating: arr.reduce((s, x) => s + x.rating, 0) / (arr.length || 1),
    rd: arr.reduce((s, x) => s + x.rd, 0) / (arr.length || 1),
  });
  const r1 = v => Math.round(v * 10) / 10;
  const ctxStmts = []; // per-player rating_before/after for match history
  for (const m of matches) {
    const ps = byMatch.get(m.id) || [];
    const t1 = ps.filter(p => p.team === 1).map(p => state.get(p.user_id)).filter(Boolean);
    const t2 = ps.filter(p => p.team === 2).map(p => state.get(p.user_id)).filter(Boolean);
    for (const p of ps) {
      const st = state.get(p.user_id);
      if (!st) continue;
      const won = p.team === m.winner_team ? 1 : 0;
      st.last = m.played_at;
      if (m.match_type === 'ranked') {
        const opp = p.team === 1 ? avg(t2) : avg(t1);
        const before = st.rating;
        const after = rate(st, [{ rating: opp.rating, rd: opp.rd, score: won }]);
        st.rating = after.rating; st.rd = after.rd; st.vol = after.vol;
        won ? st.rw++ : st.rl++;
        ctxStmts.push(db.prepare(
          'UPDATE match_players SET rating_before = ?, rating_after = ? WHERE match_id = ? AND user_id = ?'
        ).bind(r1(before), r1(after.rating), m.id, p.user_id));
      } else {
        won ? st.cw++ : st.cl++;
      }
    }
    if (m.match_type !== 'ranked') { // casual rows carry no rating context — clear any stale values
      ctxStmts.push(db.prepare(
        'UPDATE match_players SET rating_before = NULL, rating_after = NULL WHERE match_id = ?').bind(m.id));
    }
  }
  const stmts = [];
  for (const [id, st] of state) {
    stmts.push(db.prepare(
      `UPDATE users SET glicko_rating = ?, glicko_rd = ?, glicko_vol = ?,
       ranked_wins = ?, ranked_losses = ?, casual_wins = ?, casual_losses = ?,
       last_played_at = ? WHERE id = ?`
    ).bind(r1(st.rating), r1(st.rd), Math.round(st.vol * 10000) / 10000,
      st.rw, st.rl, st.cw, st.cl, st.last, id));
  }
  const all = [...stmts, ...ctxStmts];
  for (let i = 0; i < all.length; i += 100) await db.batch(all.slice(i, i + 100)); // D1-friendly chunks
  return stmts.length; // users recomputed
}

async function commitMatch(db, pending) {
  const players = (await db.prepare(
    'SELECT * FROM pending_match_players WHERE pending_match_id = ?').bind(pending.id).all()).results;
  const ids = players.map(p => p.user_id).filter(Boolean);
  const users = ids.length
    ? (await db.batch(ids.map(id =>
        db.prepare('SELECT * FROM users WHERE id = ?').bind(id)))).map(r => r.results[0])
    : [];
  // rate() reads rating/rd/vol — alias the glicko_* columns so commits rate
  // from each player's CURRENT rating, not a fresh 1500/350
  const byId = new Map(users.map(u => [u.id, {
    ...u, rating: u.glicko_rating, rd: u.glicko_rd, vol: u.glicko_vol,
  }]));

  const stmts = [];
  const ctxStmts = []; // per-player rating_before/after for the new match rows
  let ratingDelta = null;

  if (pending.match_type === 'ranked') {
    const t1 = players.filter(p => p.team === 1 && p.user_id).map(p => byId.get(p.user_id));
    const t2 = players.filter(p => p.team === 2 && p.user_id).map(p => byId.get(p.user_id));
    const opp1 = composite(t2), opp2 = composite(t1);
    const deltas = [];
    for (const p of players) {
      if (!p.user_id) continue;
      const u = byId.get(p.user_id);
      const opp = p.team === 1 ? opp1 : opp2;
      const won = p.team === pending.winner_team ? 1 : 0;
      const after = rate(u, [{ rating: opp.rating, rd: opp.rd, score: won }]);
      deltas.push(after.rating - u.glicko_rating);
      stmts.push(db.prepare(
        `UPDATE users SET glicko_rating = ?, glicko_rd = ?, glicko_vol = ?,
         ranked_wins = ranked_wins + ?, ranked_losses = ranked_losses + ?,
         last_played_at = ? WHERE id = ?`
      ).bind(
        Math.round(after.rating * 10) / 10, Math.round(after.rd * 10) / 10,
        Math.round(after.vol * 10000) / 10000,
        won, 1 - won, Date.now(), u.id));
      ctxStmts.push(db.prepare(
        `UPDATE match_players SET rating_before = ?, rating_after = ?
         WHERE match_id = (SELECT MAX(id) FROM matches) AND user_id = ?`
      ).bind(
        Math.round(u.glicko_rating * 10) / 10, Math.round(after.rating * 10) / 10, u.id));
    }
    if (deltas.length) ratingDelta = Math.round((deltas.reduce((a, b) => a + b, 0) / deltas.length) * 10) / 10;
  } else {
    for (const p of players) {
      if (!p.user_id) continue;
      const won = p.team === pending.winner_team ? 1 : 0;
      stmts.push(db.prepare(
        `UPDATE users SET casual_wins = casual_wins + ?, casual_losses = casual_losses + ?,
         last_played_at = ? WHERE id = ?`
      ).bind(won, 1 - won, Date.now(), p.user_id));
    }
  }

  stmts.push(db.prepare(
    'INSERT INTO matches (match_type, format, winner_team, rating_delta, played_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(pending.match_type, pending.format, pending.winner_team, ratingDelta, Date.now()));
  stmts.push(db.prepare(`
    INSERT INTO match_players (match_id, team, user_id, guest_name)
    SELECT (SELECT MAX(id) FROM matches), team, user_id, guest_name
    FROM pending_match_players WHERE pending_match_id = ?`).bind(pending.id));
  stmts.push(...ctxStmts); // after the match_players INSERT so the rows exist
  stmts.push(db.prepare('DELETE FROM pending_matches WHERE id = ?').bind(pending.id));
  await db.batch(stmts);
  return { committed: true, rating_delta: ratingDelta };
}

/* ============================ routing ============================ */

async function handleApi(request, env, url) {
  const { pathname } = url;
  const method = request.method;

  /* ---------- timer remote control (T16): DO plumbing, zero D1 ----------
     Laptop WS host + phone POSTs live inside one TableRoom DO per room code.
     Room codes use the unambiguous alphabet (no 0/O/1/I): 4 chars. */
  const ROOM_RE = /^[A-HJ-NP-Z2-9]{4}$/;
  if (pathname === '/api/remote/ws' && method === 'GET') {
    const room = url.searchParams.get('room') || '';
    if (!ROOM_RE.test(room)) return bad('bad room code', 400);
    if ((request.headers.get('upgrade') || '').toLowerCase() !== 'websocket') {
      return bad('websocket required', 426);
    }
    const stub = env.TABLE_ROOM.get(env.TABLE_ROOM.idFromName('room:' + room));
    return stub.fetch(request); // WS upgrade passes through to the DO
  }
  if (pathname === '/api/remote/cmd' && method === 'POST') {
    const room = url.searchParams.get('room') || '';
    if (!ROOM_RE.test(room)) return bad('bad room code', 400);
    // sanity-check the body before waking the DO (unknown action / stale / bad seq die here)
    const body = await request.json().catch(() => null);
    const action = String(body?.action || '');
    const seq = Number(body?.seq);
    const ts = Number(body?.ts) || 0;
    const cid = String(body?.cid || '');
    if (!['pass', 'reset', 'pause', 'resume', 'ext', 'new_rack'].includes(action)) {
      return bad('unknown action');
    }
    if (!Number.isInteger(seq) || seq <= 0) return bad('bad seq');
    if (!/^[a-z0-9]{1,16}$/.test(cid)) return bad('bad cid');
    // generous 10s window (phone clock skew); the DO drops anything without a
    // live host socket anyway, so commands can never execute late
    if (Date.now() - ts > 10000) return json({ ok: false, stale: true, error: 'command expired' });
    const stub = env.TABLE_ROOM.get(env.TABLE_ROOM.idFromName('room:' + room));
    return stub.fetch(new Request('https://tableroom/api/remote/cmd', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action, seq, ts, cid }),
    }));
  }
  if (pathname === '/api/remote/status' && method === 'GET') {
    const room = url.searchParams.get('room') || '';
    if (!ROOM_RE.test(room)) return bad('bad room code', 400);
    const stub = env.TABLE_ROOM.get(env.TABLE_ROOM.idFromName('room:' + room));
    return stub.fetch(new Request('https://tableroom/api/remote/status'));
  }

  if (pathname === '/api/health') {
    return json({ ok: true, time: new Date().toISOString() });
  }

  /* ---------- auth ---------- */
  if (pathname === '/api/auth/register' && method === 'POST') {
    // accounts are NOT gated by QUEUE_KEY — only joining the queue is
    const body = await request.json().catch(() => null);
    const username = String(body?.username || '').trim().toLowerCase();
    const nickname = String(body?.nickname || '').trim();
    const pin = String(body?.pin || '');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return bad('username: 3-20 chars, a-z 0-9 _');
    if (!nickname || nickname.length > 24) return bad('nickname required (max 24 chars)');
    if (!/^\d{4,6}$/.test(pin)) return bad('pin must be 4-6 digits');
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)).buffer);
    const pinHash = await pbkdf2(pin, salt);
    try {
      const { meta } = await env.DB.prepare(
        'INSERT INTO users (username, nickname, pin_hash, pin_salt, created_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(username, nickname, pinHash, salt, Date.now()).run();
      await audit(env.DB, 'register', meta.last_row_id, '@' + username);
      await auditAuth(env, 'register', username, request, true, meta.last_row_id);
      return json({ token: await issueToken(meta.last_row_id, env),
        user: { id: meta.last_row_id, username, nickname } }, 201);
    } catch (e) {
      if (String(e).includes('UNIQUE')) return bad('username already taken', 409);
      throw e;
    }
  }

  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await request.json().catch(() => null);
    const username = String(body?.username || '').trim().toLowerCase();
    const pin = String(body?.pin || '');
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user) { await auditAuth(env, 'login', username, request, false); return bad('wrong username or pin', 401); }
    const hash = await pbkdf2(pin, user.pin_salt);
    if (hash !== user.pin_hash) { await auditAuth(env, 'login', username, request, false, user.id); return bad('wrong username or pin', 401); }
    await auditAuth(env, 'login', username, request, true, user.id);
    return json({ token: await issueToken(user.id, env),
      user: { id: user.id, username: user.username, nickname: user.nickname } });
  }

  if (pathname === '/api/auth/me' && method === 'GET') {
    const user = await requireUser(request, env);
    return json({ user: { id: user.id, username: user.username, nickname: user.nickname } });
  }

  /* ---------- account editor ---------- */
  if (pathname === '/api/account' && method === 'PATCH') {
    const user = await requireUser(request, env);
    const body = await request.json().catch(() => null);

    // username / PIN changes require the current PIN
    if (body?.username != null || body?.new_pin != null) {
      const hp = await pbkdf2(String(body?.current_pin || ''), user.pin_salt);
      if (hp !== user.pin_hash) return bad('current PIN is wrong', 403);
    }

    const resp = { ok: true };
    if (body?.nickname != null) {
      const nick = String(body.nickname).trim();
      if (!nick || nick.length > 24) return bad('nickname required (max 24 chars)');
      await env.DB.prepare('UPDATE users SET nickname = ? WHERE id = ?').bind(nick, user.id).run();
      resp.nickname = nick;
    }
    if (body?.username != null) {
      const username = String(body.username).trim().toLowerCase();
      if (!/^[a-z0-9_]{3,20}$/.test(username)) return bad('username: 3-20 chars, a-z 0-9 _');
      try {
        await env.DB.prepare('UPDATE users SET username = ? WHERE id = ?').bind(username, user.id).run();
      } catch (e) {
        if (String(e).includes('UNIQUE')) return bad('username already taken', 409);
        throw e;
      }
      resp.username = username;
    }
    if (body?.new_pin != null) {
      const np = String(body.new_pin);
      if (!/^\d{4,6}$/.test(np)) return bad('new PIN must be 4-6 digits');
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)).buffer);
      const hash = await pbkdf2(np, salt);
      await env.DB.prepare('UPDATE users SET pin_hash = ?, pin_salt = ? WHERE id = ?')
        .bind(hash, salt, user.id).run();
      resp.pin_changed = true;
    }
    return json(resp);
  }

  /* ---------- user search (teammate / match pickers) ---------- */
  if (pathname === '/api/users' && method === 'GET') {
    const q = '%' + (url.searchParams.get('q') || '').toLowerCase() + '%';
    const { results } = await env.DB.prepare(
      'SELECT id, username, nickname, ROUND(glicko_rating) AS elo FROM users WHERE username LIKE ? OR nickname LIKE ? ORDER BY nickname LIMIT 8'
    ).bind(q, q).all();
    return json({ users: results });
  }

  /* ---------- admin: queue mode override ---------- */
  if (pathname === '/api/admin/queue-mode' && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const body = await request.json().catch(() => null);
    const mode = body?.mode;
    if (!['auto', 'open', 'duo-only', 'offline'].includes(mode)) {
      return bad('mode must be auto, open, duo-only or offline');
    }
    await setOverride(env.DB, mode === 'auto' ? null : mode);
    if (mode === 'offline') await clearQueue(env.DB);
    await audit(env.DB, 'queue_mode', null, 'mode=' + mode);
    const eff = await effectiveMode(env.DB, env);
    return json({ ok: true, mode: eff.mode, override: eff.override, schedule: eff.schedule });
  }

  /* ---------- admin: schedule editor + queue wipe ---------- */
  if (pathname === '/api/admin/queue-config' && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const body = await request.json().catch(() => null);
    const sched = body?.schedule;
    if (!sched || typeof sched !== 'object') return bad('schedule required');
    for (const k of SCHED_KEYS) {
      if (!/^\d{2}:\d{2}$/.test(String(sched[k] || ''))) return bad(`${k} must be HH:MM`);
    }
    if (hm(sched.open) >= hm(sched.close)) return bad('open must be before close');
    if (hm(sched.duo_start) < hm(sched.duo_end)) { // active duo-only window must fit inside open hours
      if (hm(sched.duo_start) < hm(sched.open) || hm(sched.duo_end) > hm(sched.close)) {
        return bad('duo-only window must sit inside open hours');
      }
    } // duo_start === duo_end disables the duo-only restriction entirely
    await setSchedule(env.DB, sched);
    await audit(env.DB, 'queue_config', null, JSON.stringify(sched));
    const eff = await effectiveMode(env.DB, env);
    return json({ ok: true, mode: eff.mode, override: eff.override, schedule: eff.schedule });
  }

  if (pathname === '/api/admin/clear-queue' && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    await clearQueue(env.DB);
    await audit(env.DB, 'queue_wipe', null, 'queue cleared');
    return json({ ok: true, cleared: true });
  }

  /* ---------- party queue ---------- */
  if (pathname === '/api/queue' && method === 'GET') {
    const eff = await effectiveMode(env.DB, env);
    if (eff.mode === 'offline') await clearQueue(env.DB); // window closed or admin offline
    await purgeDeadPartiesIfDue(env.DB); // day-end cleanup of terminal party rows
    const { results } = await env.DB.prepare(
      PARTY_SELECT + ` WHERE p.status IN ('playing', 'waiting')
                       ORDER BY CASE p.status WHEN 'playing' THEN 0 ELSE 1 END, p.position`
    ).all();
    // team-up requests: expire stale ones (throttled — see sweepQueueIfDue),
    // then surface this caller's popup (they own a requested duo) and their
    // own sent request, if any
    await sweepQueueIfDue(env.DB);
    const user = await currentUser(request, env);
    let teamupIn = null, teamupOut = null, inviteIn = null, skipBanned = false;
    if (user) {
      const inRow = await env.DB.prepare(
        `SELECT r.id, r.party_id, r.created_at, u.id AS requester_id, u.nickname, u.username,
                u.glicko_rating AS req_elo
         FROM team_up_requests r
         JOIN queue_parties p ON p.id = r.party_id
         JOIN users u ON u.id = r.requester_user_id
         WHERE r.kind = 'claim' AND r.status = 'pending' AND p.status = 'waiting'
           AND p.p1_user_id = ? AND p.p2_user_id IS NULL AND p.p2_guest_name IS NULL
         ORDER BY r.id LIMIT 1`
      ).bind(user.id).first();
      if (inRow) teamupIn = {
        id: inRow.id, party_id: inRow.party_id,
        created_at: inRow.created_at, expires_at: inRow.created_at + TEAMUP_TTL_MS,
        requester: { id: inRow.requester_id, nickname: inRow.nickname, username: inRow.username,
          elo: Math.round(inRow.req_elo) },
      };
      const outRow = await env.DB.prepare(
        `SELECT id, party_id, created_at FROM team_up_requests
         WHERE requester_user_id = ? AND status = 'pending' AND kind = 'claim' ORDER BY id DESC LIMIT 1`
      ).bind(user.id).first();
      if (outRow) teamupOut = { id: outRow.id, party_id: outRow.party_id,
        created_at: outRow.created_at, expires_at: outRow.created_at + TEAMUP_TTL_MS };
      // an invite waiting on ME (I'm the requested teammate) -> accept popup
      const invRow = await env.DB.prepare(
        `SELECT r.id, r.party_id, r.created_at, u.nickname AS req_nick, p.p1_guest_name AS req_guest
         FROM team_up_requests r
         JOIN queue_parties p ON p.id = r.party_id
         LEFT JOIN users u ON u.id = r.requester_user_id
         WHERE r.kind = 'invite' AND r.status = 'pending' AND r.target_user_id = ?
           AND p.status = 'waiting' AND p.p2_user_id IS NULL AND p.p2_guest_name IS NULL
         ORDER BY r.id LIMIT 1`
      ).bind(user.id).first();
      if (invRow) inviteIn = {
        id: invRow.id, party_id: invRow.party_id,
        inviter: invRow.req_nick || invRow.req_guest || 'Someone',
        created_at: invRow.created_at, expires_at: invRow.created_at + TEAMUP_TTL_MS,
      };
      // am I banned from skip-voting? (cheap PK lookup riding the poll — the
      // client hides the Skip buttons; the vote route is the 403 backstop)
      skipBanned = !!(await env.DB.prepare('SELECT user_id FROM skip_bans WHERE user_id = ?')
        .bind(user.id).first());
    }
    return json({ parties: results.map(shapeParty), table_win_prob: tableWinProb(results),
      mode: eff.mode, override: eff.override, schedule: eff.schedule,
      key_required: !!env.QUEUE_KEY, key_valid: await validQueueKey(request, env),
      key_ttl_ms: QUEUE_KEY_TTL_MS, teamup_in: teamupIn, teamup_out: teamupOut, invite_in: inviteIn,
      skip_banned: !!skipBanned });
  }

  if (pathname === '/api/queue/join' && method === 'POST') {
    // Registered users join as themselves; guests (no token) join under a
    // nickname — both need a valid QUEUE_KEY when one is set.
    const user = await currentUser(request, env);
    if (!(await validQueueKey(request, env))) {
      return bad('scan the table QR code to join the queue', 403);
    }
    const eff = await effectiveMode(env.DB, env);
    if (eff.mode === 'offline') return bad('queue is offline right now', 403);
    const body = await request.json().catch(() => null);
    const format = body?.format;
    if (!['solo', 'duo'].includes(format)) return bad('format must be solo or duo');
    if (format === 'solo' && (body?.p2_user_id || body?.p2_guest_name)) {
      return bad('solo parties have no second player');
    }
    if (format === 'solo' && eff.mode === 'duo-only') {
      return bad('queue is duo-only right now', 403);
    }
    let p1UserId = null, p1Guest = null;
    if (user) {
      p1UserId = user.id;
    } else {
      p1Guest = String(body?.p1_guest_name || '').trim().slice(0, 24);
      if (!p1Guest) return bad('guests join with a nickname — pick one first');
    }
    let p2UserId = null, p2Guest = null;
    if (body?.p2_user_id) {
      const mate = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(Number(body.p2_user_id)).first();
      if (!mate) return bad('teammate not found');
      if (user && mate.id === user.id) return bad("can't team with yourself");
      p2UserId = mate.id;
    } else if (body?.p2_guest_name) {
      p2Guest = String(body.p2_guest_name).trim().slice(0, 24);
      if (!p2Guest) return bad('guest name required');
    }
    if (p1Guest && p2Guest && p1Guest.toLowerCase() === p2Guest.toLowerCase()) {
      return bad("both duo slots can't be the same name");
    }
    // one party per player: registered by id, guests by nickname
    const mine = user
      ? await env.DB.prepare(
          `SELECT id FROM queue_parties WHERE status IN ('waiting','playing')
           AND (p1_user_id = ? OR p2_user_id = ?)`
        ).bind(user.id, user.id).first()
      : await env.DB.prepare(
          `SELECT id FROM queue_parties WHERE status IN ('waiting','playing')
           AND (LOWER(COALESCE(p1_guest_name, '')) = LOWER(?) OR LOWER(COALESCE(p2_guest_name, '')) = LOWER(?))`
        ).bind(p1Guest, p1Guest).first();
    if (mine) return bad('you are already in the queue', 409);
    const max = await env.DB.prepare(
      'SELECT COALESCE(MAX(position), 0) AS m FROM queue_parties').first();
    // a REGISTERED teammate gets an invite to accept, not an instant slot — the
    // party queues short-handed until they answer (guests are instant as before)
    const { meta } = await env.DB.prepare(
      `INSERT INTO queue_parties (format, created_by_user_id, p1_user_id, p1_guest_name, p2_user_id, p2_guest_name, position, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(format, user ? user.id : null, p1UserId, p1Guest, p2UserId ? null : p2UserId,
      p2UserId ? null : p2Guest, max.m + 1, Date.now()).run();
    let invite = null;
    if (p2UserId) {
      await expireTeamUps(env.DB); // joining invalidates my old pending requests
      if (user) {
        await env.DB.prepare(
          "UPDATE team_up_requests SET status = 'expired' WHERE requester_user_id = ? AND status = 'pending'"
        ).bind(user.id).run();
      }
      const party = { id: meta.last_row_id, p1_user_id: p1UserId, p2_user_id: null, position: max.m + 1 };
      try {
        invite = await createTeamUpInvite(env, party, user, p2UserId);
      } catch (ex) {
        // teammate can't be invited (pending request elsewhere etc.) — drop the
        // half-party again so the joiner isn't stuck queued alone
        await env.DB.prepare("UPDATE queue_parties SET status = 'skipped' WHERE id = ?")
          .bind(meta.last_row_id).run();
        return bad(ex.message, ex.status || 409);
      }
      await audit(env.DB, 'duo_invite', user ? user.id : null,
        'party=' + meta.last_row_id + ' target=' + p2UserId + ' at-join');
      return json({ ok: true, id: meta.last_row_id, invite }, 201);
    }
    await promoteNext(env.DB); // free table -> earliest party starts
    await audit(env.DB, 'queue_join', user ? user.id : null,
      'party=' + meta.last_row_id + ' ' + format + (p1Guest ? ' guest=' + p1Guest : ''));
    return json({ ok: true, id: meta.last_row_id }, 201);
  }

  let m = pathname.match(/^\/api\/queue\/(\d+)\/teammate$/);
  if (m && method === 'PATCH') {
    const body = await request.json().catch(() => null);
    const party = await env.DB.prepare('SELECT * FROM queue_parties WHERE id = ?').bind(Number(m[1])).first();
    if (!party) return bad('not found', 404);
    if (party.format !== 'duo') return bad('solo parties have no teammate slot');
    if (party.status !== 'waiting') return bad('party already in play');
    const user = await currentUser(request, env);
    const owner = partyOwnerAuth(user, party, body); // registered P1 or guest P1 by nickname
    const open = party.p2_user_id === null && party.p2_guest_name === null;
    const claiming = open && !owner && user && body?.p2_user_id == null
      && !body?.p2_guest_name && !body?.guest_name;
    if (!owner && !claiming) {
      if (!open && body?.p2_user_id == null && !body?.p2_guest_name) {
        return bad('party already has a teammate', 409); // a claim attempt on a filled party
      }
      return bad('only the owner (or a claiming teammate) can set Player 2', 403);
    }
    if (claiming) {
      // duos with a registered owner take team-up REQUESTS — the owner
      // approves — UNLESS the owner opened a pickup broadcast, in which case
      // ANY registered player claims instantly (queued players jump to this
      // party, detaching from their old one). Guest-led and blank admin stub
      // duos keep the old direct claim (no session to approve with).
      if (party.p1_user_id != null && !party.pickup_open) {
        return bad('send a team-up request — the party owner approves joins', 409);
      }
      // claiming joins this party even when already queued elsewhere — it's a
      // team switch: detach from the old party first (same split rules as leave)
      const r = await performClaim(env, user, party);
      await env.DB.prepare(
        "UPDATE team_up_requests SET status = 'expired' WHERE party_id = ? AND status = 'pending'"
      ).bind(party.id).run();
      await promoteNext(env.DB); // the party may now be complete and next in line
      await audit(env.DB, 'teammate', user.id,
        'party=' + party.id + (party.pickup_open ? ' pickup-claim' : '') + (r.switched
          ? ' switch-from=' + r.from + (r.oldDisbanded ? ' old-disbanded' : '')
          : ' claim'));
      return json({ ok: true, switched: r.switched, from: r.from });
    } else if (body?.p2_user_id) {
      // consent for registered teammates: an invite they accept, not an instant slot
      const mate = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(Number(body.p2_user_id)).first();
      if (!mate) return bad('teammate not found');
      if (mate.id === party.p1_user_id) return bad('that player is already on this party');
      try {
        const invite = await createTeamUpInvite(env, party, user, mate.id);
        await audit(env.DB, 'duo_invite', user ? user.id : null, 'party=' + party.id + ' target=' + mate.id);
        return json({ ok: true, invited: true, invite });
      } catch (ex) { return bad(ex.message, ex.status || 409); }
    } else if (body?.p2_guest_name) {
      const g = String(body.p2_guest_name).trim().slice(0, 24);
      if (!g) return bad('guest name required');
      // guest names are queue identities too (see join) — one slot per name
      const clash = await env.DB.prepare(
        `SELECT id FROM queue_parties WHERE status IN ('waiting','playing') AND id != ?
         AND (LOWER(COALESCE(p1_guest_name, '')) = LOWER(?) OR LOWER(COALESCE(p2_guest_name, '')) = LOWER(?))`
      ).bind(party.id, g, g).first();
      if (clash) return bad(`"${g}" is already queued in party #${clash.id}`, 409);
      // slot filled -> party un-sticks and any pending invite/claim is void
      await env.DB.batch([
        env.DB.prepare(
          'UPDATE queue_parties SET p2_guest_name = ?, p2_user_id = NULL, stuck = 0, pickup_open = 0 WHERE id = ?'
        ).bind(g, party.id),
        env.DB.prepare(
          "UPDATE team_up_requests SET status = 'expired' WHERE party_id = ? AND status = 'pending'"
        ).bind(party.id),
      ]);
      await promoteNext(env.DB);
    } else if (owner && body?.p2_guest_name === '') {
      await env.DB.prepare('UPDATE queue_parties SET p2_guest_name = NULL, p2_user_id = NULL WHERE id = ?')
        .bind(party.id).run();
    } else return bad('provide p2_user_id or p2_guest_name');
    await audit(env.DB, 'teammate', user ? user.id : null, 'party=' + party.id);
    return json({ ok: true });
  }

  m = pathname.match(/^\/api\/queue\/(\d+)\/vote-skip$/);
  if (m && method === 'POST') {
    const user = await requireUser(request, env);
    const id = Number(m[1]);
    const party = await env.DB.prepare('SELECT * FROM queue_parties WHERE id = ?').bind(id).first();
    if (!party || !['waiting', 'playing'].includes(party.status)) return bad('not found', 404);
    // ban checked live at vote time — an unban takes effect on the very next vote
    if (await env.DB.prepare('SELECT user_id FROM skip_bans WHERE user_id = ?').bind(user.id).first()) {
      return bad('you are not allowed to skip parties', 403);
    }
    if (party.p1_user_id === user.id || party.p2_user_id === user.id) {
      return bad("can't vote to skip your own party");
    }
    await env.DB.prepare('INSERT OR IGNORE INTO skip_votes (party_id, voter_user_id, created_at) VALUES (?, ?, ?)')
      .bind(id, user.id, Date.now()).run();
    const { n } = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM skip_votes WHERE party_id = ?').bind(id).first();
    await audit(env.DB, 'skip_vote', user.id, 'party=' + id + ' votes=' + n);
    if (n >= 3) {
      // skip_votes rows are KEPT — they're the record of who voted, shown to
      // the skipped players in their account area (/api/me/skip-history)
      await env.DB.prepare("UPDATE queue_parties SET status = 'skipped' WHERE id = ?")
        .bind(id).run();
      await promoteNext(env.DB); // refill the table if a playing party was skipped
      await audit(env.DB, 'party_skipped', null, 'party=' + id + ' by 3 votes');
      return json({ skipped: true, votes: 3 });
    }
    return json({ skipped: false, votes: n });
  }

  /* ---------- team-up requests (owned duos approve joins) ---------- */
  m = pathname.match(/^\/api\/queue\/(\d+)\/teamup$/);
  if (m && method === 'POST') {
    const user = await requireUser(request, env);
    await expireTeamUps(env.DB); // lazy 2-minute expiry
    const party = await env.DB.prepare('SELECT * FROM queue_parties WHERE id = ?').bind(Number(m[1])).first();
    if (!party) return bad('not found', 404);
    if (party.format !== 'duo') return bad('solo parties have no teammate slot');
    if (party.status !== 'waiting') return bad('party already in play');
    if (party.p2_user_id != null || party.p2_guest_name != null) {
      return bad('party already has a teammate', 409);
    }
    if (party.p1_user_id == null) {
      return bad('this duo has no registered owner to approve — claim Player 2 directly');
    }
    if (party.p1_user_id === user.id) return bad("that's your own party", 409);
    // one live request per requester (server-enforced)
    const live = await env.DB.prepare(
      "SELECT id, party_id FROM team_up_requests WHERE requester_user_id = ? AND status = 'pending' ORDER BY id LIMIT 1"
    ).bind(user.id).first();
    if (live) {
      return bad(live.party_id === party.id
        ? 'you already have a request pending for this party'
        : 'you already have a pending team-up request', 409);
    }
    const now = Date.now();
    const { meta } = await env.DB.prepare(
      "INSERT INTO team_up_requests (party_id, requester_user_id, created_at, status) VALUES (?, ?, ?, 'pending')"
    ).bind(party.id, user.id, now).run();
    await audit(env.DB, 'teamup_request', user.id, 'party=' + party.id);
    return json({ ok: true, id: meta.last_row_id, party_id: party.id, expires_at: now + TEAMUP_TTL_MS }, 201);
  }

  m = pathname.match(/^\/api\/teamup\/(\d+)\/respond$/);
  if (m && method === 'POST') {
    const user = await requireUser(request, env);
    await expireTeamUps(env.DB); // lazy 2-minute expiry (also parks invite parties)
    const body = await request.json().catch(() => null);
    const action = body?.action;
    if (!['accept', 'decline'].includes(action)) return bad('action must be accept or decline');
    const tr = await env.DB.prepare('SELECT * FROM team_up_requests WHERE id = ?').bind(Number(m[1])).first();
    if (!tr) return bad('not found', 404);
    if (tr.status !== 'pending') {
      return bad(tr.status === 'expired' ? 'team-up request expired' : `team-up request already ${tr.status}`,
        tr.status === 'expired' ? 410 : 409);
    }
    const party = await env.DB.prepare('SELECT * FROM queue_parties WHERE id = ?').bind(tr.party_id).first();
    if (!party) return bad('not found', 404);
    // claims are answered by the party owner; invites by the invited player
    const mayRespond = tr.kind === 'invite'
      ? tr.target_user_id === user.id
      : party.p1_user_id === user.id;
    if (!mayRespond) {
      return bad(tr.kind === 'invite' ? 'only the invited player can respond' : 'only the party owner can respond', 403);
    }
    if (action === 'decline') {
      await env.DB.prepare("UPDATE team_up_requests SET status = 'declined' WHERE id = ?").bind(tr.id).run();
      // a declined invite parks the party in stuck mode: it keeps its position
      // but waits for a partner before it can reach the table
      if (tr.kind === 'invite' && party.status === 'waiting'
          && party.p2_user_id == null && party.p2_guest_name == null && !party.stuck) {
        await env.DB.prepare('UPDATE queue_parties SET stuck = 1 WHERE id = ?').bind(party.id).run();
      }
      await audit(env.DB, tr.kind === 'invite' ? 'duo_invite_decline' : 'teamup_decline',
        user.id, 'request=' + tr.id + ' party=' + party.id);
      return json({ ok: true, declined: true });
    }
    // accept: the party may have filled or started while the request sat there
    if (party.status !== 'waiting') {
      await env.DB.prepare("UPDATE team_up_requests SET status = 'expired' WHERE id = ?").bind(tr.id).run();
      return bad('party already in play', 409);
    }
    if (party.p2_user_id != null || party.p2_guest_name != null) {
      await env.DB.prepare("UPDATE team_up_requests SET status = 'expired' WHERE id = ?").bind(tr.id).run();
      return bad('party already has a teammate', 409);
    }
    // claims join the requester; invites join the responder (the invited target)
    const joiner = tr.kind === 'invite'
      ? user
      : await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(tr.requester_user_id).first();
    if (!joiner) return bad('requester account no longer exists', 410);
    // the accept performs the exact old claim — same switch/detach rules
    const r = await performClaim(env, joiner, party);
    await env.DB.batch([
      env.DB.prepare("UPDATE team_up_requests SET status = 'accepted' WHERE id = ?").bind(tr.id),
      env.DB.prepare(
        "UPDATE team_up_requests SET status = 'expired' WHERE party_id = ? AND status = 'pending'"
      ).bind(party.id),
    ]);
    await promoteNext(env.DB); // the party just became complete — it may be next up
    await audit(env.DB, tr.kind === 'invite' ? 'duo_invite_accept' : 'teamup_accept', user.id,
      'request=' + tr.id + ' party=' + party.id + ' player=' + joiner.id
      + (r.switched ? ' switch-from=' + r.from + (r.oldDisbanded ? ' old-disbanded' : '') : ''));
    return json({ ok: true, switched: r.switched, from: r.from });
  }

  /* ---------- duo find-a-partner: targeted invite + open pickup ---------- */
  m = pathname.match(/^\/api\/queue\/(\d+)\/invite$/);
  if (m && method === 'POST') {
    const body = await request.json().catch(() => null);
    const party = await env.DB.prepare('SELECT * FROM queue_parties WHERE id = ?').bind(Number(m[1])).first();
    if (!party) return bad('not found', 404);
    if (party.format !== 'duo') return bad('solo parties have no teammate slot');
    if (party.status !== 'waiting') return bad('party already in play');
    if (party.p2_user_id != null || party.p2_guest_name != null) {
      return bad('party already has a teammate', 409);
    }
    const user = await currentUser(request, env);
    if (!partyOwnerAuth(user, party, body)) return bad('only the party owner can invite', 403);
    if (!body?.user_id) return bad('pick a player to invite');
    await expireTeamUps(env.DB);
    try {
      // the search-form option: any registered player, queued or not — they
      // get the same invite popup and join on accept (switching if queued)
      const invite = await createTeamUpInvite(env, party, user, body.user_id);
      await audit(env.DB, 'duo_invite', user ? user.id : null,
        'party=' + party.id + ' target=' + body.user_id + ' search');
      return json({ ok: true, invite }, 201);
    } catch (ex) { return bad(ex.message, ex.status || 409); }
  }

  m = pathname.match(/^\/api\/queue\/(\d+)\/pickup$/);
  if (m && method === 'POST') {
    const body = await request.json().catch(() => null);
    const party = await env.DB.prepare('SELECT * FROM queue_parties WHERE id = ?').bind(Number(m[1])).first();
    if (!party) return bad('not found', 404);
    if (party.format !== 'duo') return bad('solo parties have no teammate slot');
    if (party.status !== 'waiting') return bad('party already in play');
    if (party.p2_user_id != null || party.p2_guest_name != null) {
      return bad('party already has a teammate', 409);
    }
    const user = await currentUser(request, env);
    if (!partyOwnerAuth(user, party, body)) return bad('only the party owner can open a pickup', 403);
    const open = body?.open !== false; // absent = open (toggling off passes false)
    await env.DB.prepare('UPDATE queue_parties SET pickup_open = ? WHERE id = ?')
      .bind(open ? 1 : 0, party.id).run();
    await audit(env.DB, open ? 'pickup_open' : 'pickup_close', user ? user.id : null, 'party=' + party.id);
    return json({ ok: true, pickup_open: open });
  }

  m = pathname.match(/^\/api\/queue\/(\d+)$/);
  if (m && method === 'DELETE') {
    const user = await currentUser(request, env);
    const id = Number(m[1]);
    const party = await env.DB.prepare('SELECT * FROM queue_parties WHERE id = ?').bind(id).first();
    if (!party) return bad('not found', 404);
    const isP1User = user && party.p1_user_id === user.id;
    const isP2User = user && party.p2_user_id === user.id;
    const admin = await isAdmin(request, env);
    // guests prove ownership by the nickname they joined with
    const body = await request.json().catch(() => null);
    const guestName = String(body?.guest_name || '').trim().toLowerCase();
    const guestLead = !user && !party.p1_user_id && !!party.p1_guest_name &&
      guestName === party.p1_guest_name.toLowerCase();
    if (!isP1User && !isP2User && !guestLead && !admin) return bad('not your party', 403);

    // one person leaving detaches only them: the party survives with the other
    // player; a pure-admin removal (or a party left with nobody) disbands it
    const hasP2 = !!(party.p2_user_id || party.p2_guest_name);
    const leaverIsP1 = isP1User || guestLead;
    const adminWipe = admin && !isP1User && !isP2User && !guestLead;
    const disband = adminWipe || party.format === 'solo' || !hasP2;
    const stmts = [];
    if (disband) {
      stmts.push(env.DB.prepare("UPDATE queue_parties SET status = 'skipped' WHERE id = ?").bind(id));
      stmts.push(env.DB.prepare('DELETE FROM skip_votes WHERE party_id = ?').bind(id));
      // the party row survives as 'skipped' — void its requests so pending
      // senders aren't blocked by a dead party for the TTL
      stmts.push(env.DB.prepare(
        "UPDATE team_up_requests SET status = 'expired' WHERE party_id = ? AND status = 'pending'"
      ).bind(id));
    } else if (leaverIsP1) {
      // P1 walks — P2 takes over the party (registered or guest), P2 slot opens
      stmts.push(env.DB.prepare(
        `UPDATE queue_parties SET p1_user_id = p2_user_id, p1_guest_name = p2_guest_name,
         p2_user_id = NULL, p2_guest_name = NULL WHERE id = ?`
      ).bind(id));
      if (user) {
        stmts.push(env.DB.prepare(
          'DELETE FROM skip_votes WHERE party_id = ? AND voter_user_id = ?').bind(id, user.id));
      }
    } else {
      // P2 walks — P1 keeps the party, the slot opens for a new teammate
      stmts.push(env.DB.prepare(
        'UPDATE queue_parties SET p2_user_id = NULL, p2_guest_name = NULL WHERE id = ?'
      ).bind(id));
      if (user) {
        stmts.push(env.DB.prepare(
          'DELETE FROM skip_votes WHERE party_id = ? AND voter_user_id = ?').bind(id, user.id));
      }
    }
    await env.DB.batch(stmts);
    if (disband) await promoteNext(env.DB); // table seat freed — next party steps up
    await audit(env.DB, 'queue_leave', user ? user.id : null,
      'party=' + id + (adminWipe ? ' admin=1' : '')
      + (guestLead ? ' guest=' + party.p1_guest_name : '')
      + (disband ? ' disbanded' : (leaverIsP1 ? ' p1-left p2-takes-over' : ' p2-left')));
    return json({ ok: true, disbanded: disband });
  }

  /* ---------- admin: party roster edits + manual table control ---------- */
  if (pathname === '/api/admin/parties' && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    // blank duo stub — admin fills the roster afterwards (never auto-promoted)
    const max = await env.DB.prepare(
      'SELECT COALESCE(MAX(position), 0) AS m FROM queue_parties').first();
    const { meta } = await env.DB.prepare(
      `INSERT INTO queue_parties (format, status, created_by_user_id, position, created_at)
       VALUES ('duo', 'waiting', NULL, ?, ?)`
    ).bind(max.m + 1, Date.now()).run();
    await audit(env.DB, 'admin_party_add', null, 'party=' + meta.last_row_id + ' blank duo');
    return json({ ok: true, id: meta.last_row_id }, 201);
  }

  m = pathname.match(/^\/api\/admin\/parties\/(\d+)$/);
  if (m && method === 'PUT') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const party = await env.DB.prepare(
      "SELECT * FROM queue_parties WHERE id = ? AND status IN ('waiting','playing')"
    ).bind(Number(m[1])).first();
    if (!party) return bad('party not found (or no longer live)', 404);
    const body = await request.json().catch(() => null);
    let s1, s2;
    try {
      s1 = await resolveSlot(env.DB, body?.p1);
      s2 = await resolveSlot(env.DB, body?.p2);
    } catch (e) { return bad(e.message); }
    if (!s1.userId && !s1.guest && !s2.userId && !s2.guest) {
      return bad('party needs at least one player');
    }
    if (s1.userId && s1.userId === s2.userId) return bad("can't put the same player on both sides");
    for (const s of [s1, s2]) {
      if (s.userId) {
        const other = await userInLiveParty(env.DB, s.userId, party.id);
        if (other) return bad(`player is already in party #${other.id} — remove them there first`, 409);
      }
    }
    const format = body?.format != null ? body.format : ((s2.userId || s2.guest) ? 'duo' : party.format);
    if (!['solo', 'duo'].includes(format)) return bad('format must be solo or duo');
    if (format === 'solo' && (s2.userId || s2.guest)) return bad('solo parties have no second player');
    await env.DB.prepare(
      `UPDATE queue_parties SET format = ?, p1_user_id = ?, p1_guest_name = ?, p2_user_id = ?, p2_guest_name = ?
       WHERE id = ?`
    ).bind(format, s1.userId, s1.guest, s2.userId, s2.guest, party.id).run();
    await audit(env.DB, 'admin_party_edit', null,
      `party=${party.id} ${format} p1=${slotDesc(s1)} p2=${slotDesc(s2)}`);
    return json({ ok: true, id: party.id, format });
  }

  if (pathname === '/api/admin/parties/reorder' && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const body = await request.json().catch(() => null);
    const id = Number(body?.id);
    const direction = body?.direction;
    if (!['up', 'down'].includes(direction)) return bad('direction must be up or down');
    const rows = (await env.DB.prepare(
      "SELECT id, position FROM queue_parties WHERE status = 'waiting' ORDER BY position, id"
    ).all()).results;
    const i = rows.findIndex(r => r.id === id);
    if (i === -1) return bad('party is not waiting in the queue', 400);
    const j = direction === 'up' ? i - 1 : i + 1;
    if (j >= 0 && j < rows.length) {
      await env.DB.batch([
        env.DB.prepare('UPDATE queue_parties SET position = ? WHERE id = ?').bind(rows[j].position, rows[i].id),
        env.DB.prepare('UPDATE queue_parties SET position = ? WHERE id = ?').bind(rows[i].position, rows[j].id),
      ]);
      await audit(env.DB, 'admin_party_reorder', null, `party=${id} ${direction} (swap with party=${rows[j].id})`);
    }
    return json({ ok: true, id });
  }

  m = pathname.match(/^\/api\/admin\/parties\/(\d+)\/promote$/);
  if (m && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const party = await env.DB.prepare(
      "SELECT * FROM queue_parties WHERE id = ? AND status = 'waiting'"
    ).bind(Number(m[1])).first();
    if (!party) return bad('party not found (or not waiting)', 404);
    const { n } = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM queue_parties WHERE status = 'playing'").first();
    if (n >= 2) return bad('table is full — take a party off first', 409);
    await env.DB.prepare("UPDATE queue_parties SET status = 'playing' WHERE id = ?").bind(party.id).run();
    await audit(env.DB, 'admin_party_promote', null, 'party=' + party.id);
    return json({ ok: true, id: party.id });
  }

  m = pathname.match(/^\/api\/admin\/parties\/(\d+)\/demote$/);
  if (m && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const party = await env.DB.prepare(
      "SELECT * FROM queue_parties WHERE id = ? AND status = 'playing'"
    ).bind(Number(m[1])).first();
    if (!party) return bad('party not found (or not playing)', 404);
    const max = await env.DB.prepare(
      'SELECT COALESCE(MAX(position), 0) AS m FROM queue_parties').first();
    await env.DB.batch([
      env.DB.prepare("UPDATE queue_parties SET status = 'waiting', position = ? WHERE id = ?")
        .bind(max.m + 1, party.id),
      env.DB.prepare('DELETE FROM skip_votes WHERE party_id = ?').bind(party.id),
    ]);
    await promoteNext(env.DB); // demoting freed a table seat — refill it like every other seat-freeing path
    await audit(env.DB, 'admin_party_demote', null, 'party=' + party.id + ' to back of line');
    return json({ ok: true, id: party.id });
  }

  /* ---------- match logging & confirmation ---------- */
  if (pathname === '/api/matches/submit' && method === 'POST') {
    // club policy: logging only Mon–Thu — no new matches Fri/Sat/Sun; the desk
    // can still approve/edit/fix weekend data via the admin paths below
    const wd = nyWeekday(env);
    if (wd === 0 || wd >= 5) return bad('match logging is off on Fridays and weekends', 403);
    const user = await requireUser(request, env);
    const body = await request.json().catch(() => null);
    const format = body?.format;
    const winnerTeam = Number(body?.winner_team);
    // matches are always ranked now — casual submissions were removed, so a
    // stale client can't silently log unrated games
    if (body?.match_type != null && body.match_type !== 'ranked') {
      return bad('casual matches are no longer submitted — every match is ranked');
    }
    const matchType = 'ranked';
    if (!['1v1', '2v2', '2v1'].includes(format)) return bad('format must be 1v1, 2v2 or 2v1');
    if (![1, 2].includes(winnerTeam)) return bad('winner_team must be 1 or 2');

    const sizes = { '1v1': [1, 1], '2v2': [2, 2], '2v1': [2, 1] };
    const t1 = Array.isArray(body?.teams?.[1]) ? body.teams[1] : null;
    const t2 = Array.isArray(body?.teams?.[2]) ? body.teams[2] : null;
    if (!t1 || !t2 || t1.length !== sizes[format][0] || t2.length !== sizes[format][1]) {
      return bad(`teams must match format ${format}`);
    }
    const slots = [...t1.map(p => ({ ...p, team: 1 })), ...t2.map(p => ({ ...p, team: 2 }))];
    for (const s of slots) {
      if (!s || (s.user_id == null && !String(s.guest_name || '').trim())) {
        return bad('each player needs a user or guest name');
      }
    }
    const uidSet = new Set(slots.filter(s => s.user_id != null).map(s => Number(s.user_id)));
    if (uidSet.size !== slots.filter(s => s.user_id != null).length) return bad('duplicate player');
    if (!uidSet.has(user.id)) return bad('you must be one of the players');

    const found = (await env.DB.batch([...uidSet].map(id =>
      env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(id)))).map(r => r.results[0]);
    if (found.some(u => !u)) return bad('unknown user in match');

    const reg1 = t1.filter(s => s.user_id != null).length;
    const reg2 = t2.filter(s => s.user_id != null).length;
    if (!reg1 || !reg2) return bad('each team needs at least one registered player');

    const { meta } = await env.DB.prepare(
      'INSERT INTO pending_matches (match_type, format, winner_team, submitted_by_user_id, created_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(matchType, format, winnerTeam, user.id, Date.now()).run();
    const pid = meta.last_row_id;

    await env.DB.batch(slots.map(s => {
      const confirmed = (s.user_id != null && Number(s.user_id) !== user.id) ? 0 : 1; // guests & submitter auto-confirm
      return env.DB.prepare(
        'INSERT INTO pending_match_players (pending_match_id, team, user_id, guest_name, confirmed) VALUES (?, ?, ?, ?, ?)'
      ).bind(pid, s.team, s.user_id != null ? Number(s.user_id) : null,
        s.user_id != null ? null : String(s.guest_name).trim().slice(0, 24), confirmed);
    }));

    await audit(env.DB, 'match_submit', user.id, 'pending=' + pid + ' ' + matchType + ' ' + format + ' winner=' + winnerTeam);
    const others = slots.filter(s => s.user_id != null && Number(s.user_id) !== user.id);
    if (!others.length) {
      const pending = await env.DB.prepare('SELECT * FROM pending_matches WHERE id = ?').bind(pid).first();
      const res = await commitMatch(env.DB, pending);
      await audit(env.DB, 'match_commit', user.id, 'pending=' + pid + ' auto');
      return json({ committed: true, match_type: matchType, rating_delta: res.rating_delta }, 201);
    }
    return json({ committed: false, pending_id: pid, awaiting: others.length }, 201);
  }

  /* my recent 3-vote skips: parties I was in that got voted off, with the
     voters named — skip_votes survive the skip precisely for this */
  if (pathname === '/api/me/skip-history' && method === 'GET') {
    const user = await requireUser(request, env);
    const week = Date.now() - 7 * 24 * 3600 * 1000;
    const { results: rows } = await env.DB.prepare(
      `SELECT p.id, p.format, MAX(v.created_at) AS skipped_at,
              p.p1_user_id, p.p1_guest_name, u1.nickname AS p1_nick, u1.username AS p1_user,
              p.p2_user_id, p.p2_guest_name, u2.nickname AS p2_nick, u2.username AS p2_user
       FROM queue_parties p
       JOIN skip_votes v ON v.party_id = p.id
       LEFT JOIN users u1 ON u1.id = p.p1_user_id
       LEFT JOIN users u2 ON u2.id = p.p2_user_id
       WHERE p.status = 'skipped' AND (p.p1_user_id = ?1 OR p.p2_user_id = ?1)
         AND v.created_at > ?2
       GROUP BY p.id ORDER BY skipped_at DESC LIMIT 20`
    ).bind(user.id, week).all();
    const skips = [];
    for (const r of rows) {
      const { results: voters } = await env.DB.prepare(
        `SELECT u.nickname, u.username FROM skip_votes v
         JOIN users u ON u.id = v.voter_user_id
         WHERE v.party_id = ? ORDER BY v.created_at`
      ).bind(r.id).all();
      const member = (uid, nick, uname, guest) => uid
        ? { name: nick, username: uname, registered: true }
        : guest ? { name: 'Guest: ' + guest, username: null, registered: false } : null;
      skips.push({
        party_id: r.id, format: r.format, skipped_at: r.skipped_at,
        members: [member(r.p1_user_id, r.p1_nick, r.p1_user, r.p1_guest_name),
                  member(r.p2_user_id, r.p2_nick, r.p2_user, r.p2_guest_name)].filter(Boolean),
        voters,
      });
    }
    return json({ skips });
  }

  /* the same skip record for admins: every recently skipped party with the
     voters named — identical shape to /api/me/skip-history minus the
     "party must include me" filter */
  if (pathname === '/api/admin/skip-history' && method === 'GET') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    return json({ skips: await recentSkips(env.DB) });
  }

  /* ---------- skip ban list: revoke a user's skip-vote rights ----------
     Registered users only — guests have no persistent identity to ban.
     The vote route re-checks the table live, so add/remove is instant. */
  if (pathname === '/api/admin/skip-bans' && method === 'GET') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const { results } = await env.DB.prepare(
      `SELECT b.user_id, b.created_at, b.note, u.nickname, u.username
       FROM skip_bans b JOIN users u ON u.id = b.user_id
       ORDER BY b.created_at DESC, b.user_id DESC LIMIT 200`
    ).all();
    return json({ bans: results });
  }

  /* ---------- admin: IP watchlist (see migration 0011) ---------- */
  if (pathname === '/api/admin/watchlist' && method === 'GET') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const { results } = await env.DB.prepare(
      'SELECT prefix, note, created_at FROM ip_watchlist ORDER BY created_at DESC'
    ).all();
    return json({ watchlist: results });
  }
  if (pathname === '/api/admin/watchlist' && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const body = await request.json().catch(() => null);
    const prefix = String(body?.prefix || '').trim();
    if (!prefix) return bad('prefix required');
    const action = body?.remove ? 'DELETE' : 'INSERT';
    if (action === 'DELETE') {
      await env.DB.prepare('DELETE FROM ip_watchlist WHERE prefix = ?').bind(prefix).run();
      await audit(env.DB, 'watchlist_remove', null, prefix.slice(0, 30));
      return json({ ok: true, removed: prefix });
    }
    await env.DB.prepare(
      'INSERT OR REPLACE INTO ip_watchlist (prefix, note, created_at) VALUES (?, ?, ?)'
    ).bind(prefix, String(body?.note || '').slice(0, 120), Date.now()).run();
    await audit(env.DB, 'watchlist_add', null, prefix.slice(0, 30));
    return json({ ok: true, added: prefix });
  }

  /* ---------- admin: login history (see migration 0012) ---------- */
  if (pathname === '/api/admin/login-history' && method === 'GET') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const url = new URL(request.url);
    const ip = url.searchParams.get('ip');
    const username = url.searchParams.get('username');
    const limit = Math.min(Number(url.searchParams.get('limit')) || 200, 1000);
    let sql = 'SELECT at, kind, username, user_id, ip, ok, matched_prefix FROM login_history';
    const conds = [], binds = [];
    if (ip) { conds.push('ip = ?'); binds.push(ip); }
    if (username) { conds.push('username = ?'); binds.push(username.toLowerCase()); }
    if (conds.length) sql += ' WHERE ' + conds.join(' AND ');
    sql += ' ORDER BY at DESC LIMIT ?'; binds.push(limit);
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json({ logins: results });
  }

  /* ---------- admin: moderation notifications (T25) ----------
     Three feeds in one response: skip history (identical shape to
     /api/admin/skip-history), flagged-IP sign-in attempts (audit rows the
     PR #64 auth trap writes as 'auth_ip'/'watchlist_hit') and old-admin-PIN
     honeypot hits from mod_events. */
  if (pathname === '/api/admin/mod-events' && method === 'GET') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const { results: flagged } = await env.DB.prepare(
      `SELECT a.at, a.type, a.detail, u.nickname AS actor, u.username AS actor_user
       FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
       WHERE a.type IN ('auth_ip', 'watchlist_hit')
       ORDER BY a.at DESC LIMIT 20`
    ).all();
    const { results: pinTries } = await env.DB.prepare(
      `SELECT m.id, m.created_at, m.user_id, m.ip, m.detail, u.nickname, u.username
       FROM mod_events m LEFT JOIN users u ON u.id = m.user_id
       WHERE m.kind = 'old_admin_pin'
       ORDER BY m.created_at DESC LIMIT 20`
    ).all();
    return json({ skips: await recentSkips(env.DB),
      flagged_logins: flagged, old_pin_attempts: pinTries });
  }

  /* ---------- admin unlock honeypot (T25) ----------
     The client's 🔒 prompt posts here. The shared PIN NEVER unlocks anymore:
     every attempt fails with the exact pre-honeypot failure message so the
     prompt UX is unchanged (no tip-off), and submitting the OLD compromised
     PIN additionally lands a mod_events infraction — account-tied when the
     caller has a session, IP-only when anonymous. All the other admin routes
     still honor X-Admin-Pin for the current PIN until T24 removes the PIN
     system entirely; only this validation path is dead by design. */
  if (pathname === '/api/admin/unlock' && method === 'POST') {
    const body = await request.json().catch(() => null);
    const pin = String(body?.pin ?? '') || request.headers.get('x-admin-pin') || '';
    const user = await currentUser(request, env); // optional — the honeypot must also catch anonymous tries
    if (pin === OLD_ADMIN_PIN) {
      await logModEvent(env, 'old_admin_pin', user ? user.id : null, request, 'entered old admin PIN');
    }
    return bad('Wrong admin PIN.', 403);
  }

  if (pathname === '/api/admin/skip-bans' && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const body = await request.json().catch(() => null);
    const uid = Number(body?.user_id);
    if (!uid) return bad('user_id required');
    const target = await env.DB.prepare('SELECT id, nickname, username FROM users WHERE id = ?').bind(uid).first();
    if (!target) return bad('player not found', 404);
    const note = body?.note != null ? String(body.note).trim().slice(0, 140) : null;
    try {
      await env.DB.prepare('INSERT INTO skip_bans (user_id, created_at, note) VALUES (?, ?, ?)')
        .bind(uid, Date.now(), note || null).run();
    } catch (ex) {
      if (String(ex.message).includes('UNIQUE')) return bad('player is already banned', 409);
      throw ex;
    }
    await audit(env.DB, 'skip_ban', null, 'user=' + uid + ' @' + target.username + (note ? ' note=' + note : ''));
    return json({ ok: true, user_id: uid }, 201);
  }

  m = pathname.match(/^\/api\/admin\/skip-bans\/(\d+)$/);
  if (m && method === 'DELETE') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const uid = Number(m[1]);
    const res = await env.DB.prepare('DELETE FROM skip_bans WHERE user_id = ?').bind(uid).run();
    if (!res.meta.changes) return bad('player is not banned', 404);
    await audit(env.DB, 'skip_unban', null, 'user=' + uid);
    return json({ ok: true });
  }

  if (pathname === '/api/notifications' && method === 'GET') {
    const user = await requireUser(request, env);
    // the 5s poll only needs ids + status (badge counts, unlock state) — full
    // rosters live on /api/pending so closed screens stop paying for them
    const { results } = await env.DB.prepare(
      `SELECT pm.id, pm.status
       FROM pending_matches pm JOIN pending_match_players mp ON mp.pending_match_id = pm.id
       WHERE mp.user_id = ? AND mp.confirmed = 0`
    ).bind(user.id).all();
    // honeypot on the poll path: the pre-T25 client validated the admin PIN by
    // polling here with the x-admin-pin header — a replayed old client lands
    // exactly here, so the burned PIN is logged before the gate is read
    if ((request.headers.get('x-admin-pin') || '') === OLD_ADMIN_PIN) {
      await logModEvent(env, 'old_admin_pin', user.id, request, 'entered old admin PIN');
    }
    const admin = await isAdmin(request, env);
    let adminList = null;
    if (admin) {
      adminList = (await env.DB.prepare(
        `SELECT id, status FROM pending_matches WHERE status IN ('pending','disputed')
         ORDER BY status DESC, id DESC`
      ).all()).results;
    }
    return json({ notifications: results, admin: adminList, admin_unlocked: admin });
  }

  if (pathname === '/api/pending' && method === 'GET') {
    // fetch-on-open detail (Me-tab confirmations + the admin pending section);
    // same lists the old /api/notifications carried, now off the poll path
    const user = await requireUser(request, env);
    const mine = (await env.DB.prepare(
      `SELECT ${PENDING_DETAIL}
       FROM pending_matches pm JOIN pending_match_players mp ON mp.pending_match_id = pm.id
       WHERE mp.user_id = ? AND mp.confirmed = 0`
    ).bind(user.id).all()).results;
    // same poll-path honeypot as /api/notifications (see there)
    if ((request.headers.get('x-admin-pin') || '') === OLD_ADMIN_PIN) {
      await logModEvent(env, 'old_admin_pin', user.id, request, 'entered old admin PIN');
    }
    const admin = await isAdmin(request, env);
    let adminList = null;
    if (admin) {
      adminList = (await env.DB.prepare(
        `SELECT ${PENDING_DETAIL} FROM pending_matches pm
         WHERE pm.status IN ('pending','disputed') ORDER BY pm.status DESC, pm.id DESC`
      ).all()).results;
    }
    return json({ mine, admin: adminList, admin_unlocked: admin });
  }

  m = pathname.match(/^\/api\/matches\/(\d+)\/respond$/);
  if (m && method === 'POST') {
    const user = await requireUser(request, env);
    const body = await request.json().catch(() => null);
    const action = body?.action;
    if (!['confirm', 'dispute'].includes(action)) return bad('action must be confirm or dispute');
    const pending = await env.DB.prepare('SELECT * FROM pending_matches WHERE id = ?').bind(Number(m[1])).first();
    if (!pending || !['pending', 'disputed'].includes(pending.status)) return bad('not found', 404);
    const me = await env.DB.prepare(
      'SELECT * FROM pending_match_players WHERE pending_match_id = ? AND user_id = ?'
    ).bind(pending.id, user.id).first();
    if (!me) return bad('you are not in this match', 403);
    if (action === 'dispute') {
      await env.DB.prepare("UPDATE pending_matches SET status = 'disputed' WHERE id = ?").bind(pending.id).run();
      await audit(env.DB, 'match_dispute', user.id, 'pending=' + pending.id);
      return json({ ok: true, status: 'disputed' });
    }
    await env.DB.prepare('UPDATE pending_match_players SET confirmed = 1 WHERE id = ?').bind(me.id).run();
    await audit(env.DB, 'match_confirm', user.id, 'pending=' + pending.id);
    // one confirmation from the team facing the submitter logs the match —
    // teammate confirms alone never commit (submitter & guests auto-confirm)
    const submitter = await env.DB.prepare(
      'SELECT team FROM pending_match_players WHERE pending_match_id = ? AND user_id = ?'
    ).bind(pending.id, pending.submitted_by_user_id).first();
    if (submitter && me.team !== submitter.team) {
      const res = await commitMatch(env.DB, pending);
      await audit(env.DB, 'match_commit', user.id, 'pending=' + pending.id + ' enemy-confirm');
      return json({ committed: true, rating_delta: res.rating_delta });
    }
    const left = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM pending_match_players WHERE pending_match_id = ? AND confirmed = 0'
    ).bind(pending.id).first();
    if (left.n === 0) {
      const res = await commitMatch(env.DB, pending);
      await audit(env.DB, 'match_commit', user.id, 'pending=' + pending.id + ' unanimous');
      return json({ committed: true, rating_delta: res.rating_delta });
    }
    return json({ committed: false, unconfirmed: left.n });
  }

  m = pathname.match(/^\/api\/matches\/(\d+)\/admin-approve$/);
  if (m && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const pending = await env.DB.prepare(
      "SELECT * FROM pending_matches WHERE id = ? AND status IN ('pending','disputed')"
    ).bind(Number(m[1])).first();
    if (!pending) return bad('not found', 404);
    const res = await commitMatch(env.DB, pending);
    await audit(env.DB, 'admin_approve', null, 'pending=' + pending.id + ' force-committed');
    return json({ committed: true, rating_delta: res.rating_delta });
  }

  /* ---------- leaderboard & history ---------- */
  if (pathname === '/api/leaderboard' && method === 'GET') {
    // Placement players (<10 ranked games) sort below every placed player,
    // even with a higher rating; each group is ordered by rating DESC.
    const { results } = await env.DB.prepare(
      `SELECT id, username, nickname, glicko_rating, glicko_rd,
              ranked_wins, ranked_losses, casual_wins, casual_losses
       FROM users
       ORDER BY (ranked_wins + ranked_losses) >= 10 DESC, glicko_rating DESC
       LIMIT 50`
    ).all();
    return json({ leaderboard: results });
  }

  if (pathname === '/api/matches' && method === 'GET') {
    // filters: ?player=<username or nickname, exact> &since=<epoch ms> &until=<epoch ms> &limit= &page=
    const player = url.searchParams.get('player');
    const since = Number(url.searchParams.get('since')) || 0;
    const until = Number(url.searchParams.get('until')) || 0;
    // ?page= callers (the Log tab pager) get 10-per-page unless they pass limit;
    // legacy consumers without page keep the old flat limit-20 shape
    const paged = url.searchParams.has('page');
    const page = Math.max(1, Number(url.searchParams.get('page')) || 1);
    const limit = clamp(Number(url.searchParams.get('limit')) || (paged ? 10 : 20), 1, 100);
    // rosters come from ONE indexed IN() pass below (team1/team2 strings are
    // rebuilt in JS from it) — the old per-match group_concat subqueries
    // full-scanned match_players without an index: ~10k rows read per call
    let sql = `SELECT m.id, m.match_type, m.format, m.winner_team, m.rating_delta, m.played_at
       FROM matches m WHERE m.played_at >= ?`;
    const params = [since];
    if (until) { sql += ' AND m.played_at <= ?'; params.push(until); }
    if (player) {
      sql += ` AND EXISTS (SELECT 1 FROM match_players mp JOIN users u ON u.id = mp.user_id
                WHERE mp.match_id = m.id AND (LOWER(u.username) = LOWER(?) OR LOWER(u.nickname) = LOWER(?)))`;
      params.push(player, player);
    }
    // fetch one extra row to flag has_more — avoids a COUNT(*) that would scan
    // the whole filtered set just to size the pager
    sql += ' ORDER BY m.played_at DESC LIMIT ? OFFSET ?';
    params.push(limit + 1, (page - 1) * limit);
    const { results } = await env.DB.prepare(sql).bind(...params).all();
    const hasMore = results.length > limit;
    if (hasMore) results.length = limit;
    // per-player rosters with rating context (rating_before/after, NULL for guests
    // and for rows predating migration 0006 until the next rating replay)
    if (results.length) {
      const ph = results.map(() => '?').join(',');
      const pr = (await env.DB.prepare(
        `SELECT mp.match_id, mp.team, mp.user_id, u.nickname, u.username, mp.guest_name,
                mp.rating_before, mp.rating_after
         FROM match_players mp LEFT JOIN users u ON u.id = mp.user_id
         WHERE mp.match_id IN (${ph}) ORDER BY mp.match_id, mp.team, mp.id`
      ).bind(...results.map(m => m.id)).all()).results;
      const byMatch = new Map();
      for (const r of pr) {
        if (!byMatch.has(r.match_id)) byMatch.set(r.match_id, []);
        byMatch.get(r.match_id).push({
          team: r.team,
          user_id: r.user_id,
          name: r.user_id ? r.nickname : (r.guest_name != null ? 'Guest: ' + r.guest_name : '?'),
          username: r.username || null,
          guest: !r.user_id,
          rating_before: r.rating_before,
          rating_after: r.rating_after,
        });
      }
      for (const m of results) {
        m.players = byMatch.get(m.id) || [];
        // legacy roster strings (same shape the group_concat subqueries made)
        m.team1 = m.players.filter(p => p.team === 1).map(p => p.name).join(' | ');
        m.team2 = m.players.filter(p => p.team === 2).map(p => p.name).join(' | ');
      }
    }
    return json({ matches: results, page, has_more: hasMore });
  }

  if (pathname === '/api/admin/audit' && method === 'GET') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    // ?page= -> 10-per-page slices (pager reads only its page server-side);
    // no page -> legacy flat 200-row response for existing consumers
    const paged = url.searchParams.has('page');
    const page = Math.max(1, Number(url.searchParams.get('page')) || 1);
    const limit = paged ? 10 : 200;
    const { results } = await env.DB.prepare(
      `SELECT a.id, a.at, a.type, a.detail, u.nickname AS actor, u.username AS actor_user,
              (a.actor_user_id IS NULL) AS is_admin
       FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
       ORDER BY a.id DESC LIMIT ? OFFSET ?`
    ).bind(limit + 1, (page - 1) * limit).all();
    const hasMore = results.length > limit;
    if (hasMore) results.length = limit;
    return json({ audit: results, page, has_more: hasMore });
  }

  if (pathname === '/api/admin/queue-key' && method === 'GET') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    return json({ key: env.QUEUE_KEY || null });
  }

  /* ---------- admin: edit / delete committed matches, reject pending ---------- */
  m = pathname.match(/^\/api\/admin\/matches\/(\d+)$/);
  if (m && method === 'PUT') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const id = Number(m[1]);
    const row = await env.DB.prepare('SELECT * FROM matches WHERE id = ?').bind(id).first();
    if (!row) return bad('not found', 404);
    const body = await request.json().catch(() => null);
    const winner = body?.winner_team != null ? Number(body.winner_team) : row.winner_team;
    const type = body?.match_type != null ? body.match_type : row.match_type;
    if (body?.match_type === 'casual' && row.match_type !== 'casual') return bad('matches are ranked-only since #21; converting ranked → casual is disabled', 400); // existing casual rows keep flipping →R only
    if (![1, 2].includes(winner)) return bad('winner_team must be 1 or 2');
    if (!['ranked', 'casual'].includes(type)) return bad('match_type must be ranked or casual');
    await env.DB.prepare('UPDATE matches SET winner_team = ?, match_type = ? WHERE id = ?')
      .bind(winner, type, id).run();
    await replayAllRatings(env.DB); // ratings/W-L recomputed from full history
    await audit(env.DB, 'admin_match_edit', null,
      'match=' + id + ' winner ' + row.winner_team + '->' + winner + (type !== row.match_type ? ' type->' + type : '') + ' · ratings replayed');
    return json({ ok: true, id, winner_team: winner, match_type: type });
  }

  if (m && method === 'DELETE') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const id = Number(m[1]);
    const { meta } = await env.DB.prepare('DELETE FROM matches WHERE id = ?').bind(id).run();
    if (!meta.changes) return bad('not found', 404);
    await env.DB.prepare('DELETE FROM match_players WHERE match_id = ?').bind(id).run();
    await replayAllRatings(env.DB); // undo the match's rating/W-L effects exactly
    await audit(env.DB, 'admin_match_delete', null, 'match=' + id + ' removed · ratings replayed');
    return json({ ok: true, id });
  }

  m = pathname.match(/^\/api\/admin\/matches\/(\d+)\/reject$/);
  if (m && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const id = Number(m[1]);
    const pending = await env.DB.prepare('SELECT * FROM pending_matches WHERE id = ?').bind(id).first();
    if (!pending || !['pending', 'disputed'].includes(pending.status)) return bad('not found', 404);
    await env.DB.batch([
      env.DB.prepare('DELETE FROM pending_match_players WHERE pending_match_id = ?').bind(id),
      env.DB.prepare('DELETE FROM pending_matches WHERE id = ?').bind(id),
    ]);
    await audit(env.DB, 'admin_match_reject', null, 'pending=' + id + ' rejected' + (pending.status === 'disputed' ? ' (was disputed)' : ''));
    return json({ ok: true, id, rejected: true });
  }

  /* ---------- admin: global rating recalculation ---------- */
  if (pathname === '/api/admin/recalc-ratings' && method === 'POST') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const n = await replayAllRatings(env.DB); // reset everyone, replay full history
    await audit(env.DB, 'admin_recalc', null, 'ratings replayed for ' + n + ' users');
    return json({ ok: true, users: n });
  }

  if (pathname === '/api/admin/players' && method === 'GET') {
    if (!(await isAdmin(request, env))) return bad('admin pin required', 403);
    const { results } = await env.DB.prepare(
      `SELECT id, username, nickname, glicko_rating, glicko_rd,
              ranked_wins, ranked_losses, casual_wins, casual_losses, created_at, last_played_at
       FROM users ORDER BY id LIMIT 200`
    ).all();
    return json({ players: results });
  }

  return bad('not found', 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        if (err instanceof HttpError) return bad(err.message, err.status);
        // forgotten remote migration: surface the fix instead of a bare 500
        if (/NOT NULL constraint failed: queue_parties\.created_by_user_id/.test(String(err))) {
          return bad('database schema is out of date — run: npm run db:migrate (applies 0005)', 503);
        }
        return json({ error: 'internal error', detail: String(err?.message || err) }, 500);
      }
    }
    // NOTE: /remote (the phone controller, QR target) is served straight from
    // public/remote.html by the assets layer's pretty-URL handling — no worker
    // code needed for it.
    return env.ASSETS.fetch(request);
  },
};
