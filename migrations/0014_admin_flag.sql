-- T24: admin becomes a per-user permission. The shared ADMIN_PIN system is
-- removed (2026-11-21 compromise killed its premise); a signed-in session on
-- an is_admin=1 account IS the admin gate — no unlock step, no PIN header.
-- Flag accounts with: UPDATE users SET is_admin = 1 WHERE username IN (...)
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
