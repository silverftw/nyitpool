-- Persistent login history: username + IP for every auth attempt, kept
-- indefinitely (Workers Logs only retains 7 days and never stored bodies,
-- so pre-trap logins were unrecoverable). Written by auditAuth().
CREATE TABLE IF NOT EXISTS login_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL,              -- 'login' | 'register'
  username TEXT NOT NULL,
  user_id INTEGER,
  ip TEXT NOT NULL,
  ok INTEGER NOT NULL,             -- 1 success, 0 failed
  matched_prefix TEXT              -- watchlist prefix if the IP matched, else NULL
);
CREATE INDEX IF NOT EXISTS idx_login_history_ip ON login_history (ip, at);
CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history (user_id, at);
