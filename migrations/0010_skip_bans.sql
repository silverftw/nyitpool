-- T21: skip ban list — users banned from voting to skip parties.
-- Registered users only: guests have no persistent identity to ban.
-- user_id is the PK (one row per user, unique) and the FK cascade removes
-- the ban if the account itself is deleted.
CREATE TABLE IF NOT EXISTS skip_bans (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  note TEXT
);
