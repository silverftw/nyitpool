-- Match-log format derivation (one form, 4 free slots): '1v2' joins the
-- legal format labels. SQLite can't ALTER a CHECK constraint, so both tables
-- carrying the old format CHECK are rebuilt (copy → drop → rename).
-- defer_foreign_keys rides out the DROP window: match_players and
-- pending_match_players reference these tables by name, and D1 checks
-- deferred FKs at COMMIT — by then the original names exist again.

PRAGMA defer_foreign_keys = ON;

CREATE TABLE matches_new (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  match_type   TEXT    NOT NULL CHECK (match_type IN ('ranked', 'casual')),
  format       TEXT    NOT NULL CHECK (format IN ('1v1', '1v2', '2v1', '2v2')),
  winner_team  INTEGER NOT NULL CHECK (winner_team IN (1, 2)),
  rating_delta REAL,                    -- mean rating change (ranked only)
  played_at    INTEGER NOT NULL
);
INSERT INTO matches_new (id, match_type, format, winner_team, rating_delta, played_at)
  SELECT id, match_type, format, winner_team, rating_delta, played_at FROM matches;
DROP TABLE matches;
ALTER TABLE matches_new RENAME TO matches;
CREATE INDEX IF NOT EXISTS idx_matches_played ON matches (played_at);

CREATE TABLE pending_matches_new (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  match_type           TEXT NOT NULL CHECK (match_type IN ('ranked', 'casual')),
  format               TEXT NOT NULL CHECK (format IN ('1v1', '1v2', '2v1', '2v2')),
  winner_team          INTEGER NOT NULL CHECK (winner_team IN (1, 2)),
  submitted_by_user_id INTEGER NOT NULL REFERENCES users(id),
  status               TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'disputed', 'approved', 'rejected')),
  created_at           INTEGER NOT NULL
);
INSERT INTO pending_matches_new (id, match_type, format, winner_team, submitted_by_user_id, status, created_at)
  SELECT id, match_type, format, winner_team, submitted_by_user_id, status, created_at FROM pending_matches;
DROP TABLE pending_matches;
ALTER TABLE pending_matches_new RENAME TO pending_matches;
