-- Match-log format derivation (one form, 4 free slots): '1v2' joins the
-- legal format labels. SQLite can't ALTER a CHECK constraint, so both
-- tables carrying the old format CHECK (matches, pending_matches) are
-- rebuilt via copy → rename-swap → drop.
--
-- CASCADE HAZARD (learned the hard way on prod, 2026-11-24): DROP TABLE
-- runs an implicit DELETE FROM first, and with FKs enabled that DELETE
-- fires ON DELETE CASCADE inside the CHILD tables. The first draft of
-- this migration erased every match_players / pending_match_players row
-- (both cascade off the rebuilt parents). defer_foreign_keys does NOT
-- prevent it — it defers the constraint CHECK, not the CASCADE action —
-- and legacy_alter_table is a silent no-op inside the migration
-- transaction, so the rename-swap doesn't dodge it either.
--
-- The robust recipe: stage the child rows in plain FK-free _backup
-- tables, DROP the child tables FIRST (their implicit DELETE can only
-- touch their own staged rows), rebuild the parents (by then nothing
-- references them, so the rename-swap's drops cascade nowhere), then
-- recreate the children from their backups with the original DDL and
-- re-point at the fresh parents. defer_foreign_keys rides out the
-- dangling-FK window; D1 checks deferred FKs at COMMIT, when every id
-- resolves against the new tables again.

PRAGMA defer_foreign_keys = ON;

-- 1. stage + drop children (match_players children: none; pending_match_players children: none)
CREATE TABLE mp_bk AS SELECT id, match_id, team, user_id, guest_name, rating_before, rating_after FROM match_players;
CREATE TABLE pmp_bk AS SELECT id, pending_match_id, team, user_id, guest_name, confirmed FROM pending_match_players;
DROP TABLE match_players;
DROP TABLE pending_match_players;

-- 2. rebuild matches (format CHECK widened)
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
ALTER TABLE matches RENAME TO matches_0015_old;
ALTER TABLE matches_new RENAME TO matches;
DROP TABLE matches_0015_old;
CREATE INDEX IF NOT EXISTS idx_matches_played ON matches (played_at);

-- 3. rebuild pending_matches (format CHECK widened)
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
ALTER TABLE pending_matches RENAME TO pending_matches_0015_old;
ALTER TABLE pending_matches_new RENAME TO pending_matches;
DROP TABLE pending_matches_0015_old;

-- 4. recreate children from backups, original DDL (0002 + 0006), fresh parents
CREATE TABLE match_players (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  match_id      INTEGER NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  team          INTEGER NOT NULL CHECK (team IN (1, 2)),
  user_id       INTEGER REFERENCES users(id),
  guest_name    TEXT,
  rating_before REAL,
  rating_after  REAL
);
INSERT INTO match_players (id, match_id, team, user_id, guest_name, rating_before, rating_after)
  SELECT id, match_id, team, user_id, guest_name, rating_before, rating_after FROM mp_bk;
CREATE INDEX IF NOT EXISTS idx_mp_user ON match_players (user_id);

CREATE TABLE pending_match_players (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  pending_match_id INTEGER NOT NULL REFERENCES pending_matches(id) ON DELETE CASCADE,
  team             INTEGER NOT NULL CHECK (team IN (1, 2)),
  user_id          INTEGER REFERENCES users(id),
  guest_name       TEXT,
  confirmed        INTEGER NOT NULL DEFAULT 0
);
INSERT INTO pending_match_players (id, pending_match_id, team, user_id, guest_name, confirmed)
  SELECT id, pending_match_id, team, user_id, guest_name, confirmed FROM pmp_bk;
CREATE INDEX IF NOT EXISTS idx_pmp_user ON pending_match_players (user_id, confirmed);

-- 5. staging tables out (own rows only, no children)
DROP TABLE mp_bk;
DROP TABLE pmp_bk;
