-- IP watchlist for the 2026-11-21 admin-pin compromise follow-up.
-- Stored in DB, NOT code: repo is public and a public watchlist tells the
-- attacker they're flagged + hands them the forensics map. Rows are prefixes
-- (IPv6 rotates), matches are startsWith in src/index.js. Hits are leads,
-- never auto-bans. Managed via /api/admin/watchlist.
CREATE TABLE IF NOT EXISTS ip_watchlist (
  prefix TEXT PRIMARY KEY,
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
