-- Moderation events (T25 honeypot): infractions logged by the server when
-- someone submits the burned pre-rotation admin PIN (2026-11-21 compromise)
-- to the always-failing unlock prompt. Signed-in attempts tie the account;
-- anonymous attempts are IP-only. Flagged-IP login attempts deliberately do
-- NOT live here — PR #64's auth trap already writes those as audit_log rows
-- ('auth_ip' / 'watchlist_hit') and the admin feed surfaces them from there.
-- No FK on user_id: this is a forensic log, IPs stay meaningful even if a
-- user row ever goes away (audit_log's no-cascade FK already blocks deletes).
CREATE TABLE IF NOT EXISTS mod_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,              -- 'old_admin_pin' (honeypot hit)
  user_id INTEGER,
  ip TEXT,
  detail TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mod_events_kind ON mod_events (kind, created_at);
