-- Duo join consent: joining (or filling a duo) with a REGISTERED teammate now
-- sends that player an invite they must accept — the party waits in the queue
-- with a "pending request" tag instead of jumping on the table. A declined or
-- expired invite parks the party in "stuck" mode: it keeps its position but is
-- skipped for promotion until it finds a partner (player or guest).
--
-- team_up_requests is rebuilt to carry two request kinds:
--   'claim'  — existing flow: a queued player asks to join an owned open duo
--   'invite' — reverse direction: a party owner (or joiner) asks a specific
--              player to fill their P2 slot; target_user_id decides, and
--              requester_user_id is nullable so guest-led parties can invite.
CREATE TABLE team_up_requests_new (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  party_id          INTEGER NOT NULL REFERENCES queue_parties(id) ON DELETE CASCADE,
  requester_user_id INTEGER REFERENCES users(id),
  target_user_id    INTEGER REFERENCES users(id),
  kind              TEXT NOT NULL DEFAULT 'claim' CHECK (kind IN ('claim', 'invite')),
  created_at        INTEGER NOT NULL,
  status            TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted', 'declined', 'expired'))
);
INSERT INTO team_up_requests_new (id, party_id, requester_user_id, kind, created_at, status)
  SELECT id, party_id, requester_user_id, 'claim', created_at, status FROM team_up_requests;
DROP TABLE team_up_requests;
ALTER TABLE team_up_requests_new RENAME TO team_up_requests;
CREATE INDEX IF NOT EXISTS idx_team_up_party
  ON team_up_requests (party_id, status);
-- one live request per requester: pending rows only (expiry is lazy)
CREATE INDEX IF NOT EXISTS idx_team_up_requester_pending
  ON team_up_requests (requester_user_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_team_up_target_pending
  ON team_up_requests (target_user_id) WHERE status = 'pending';

-- stuck = invite declined/expired and P2 still open (cleared when the party
-- fills); pickup_open = owner broadcast "anyone in the queue can claim my P2"
ALTER TABLE queue_parties ADD COLUMN stuck INTEGER NOT NULL DEFAULT 0;
ALTER TABLE queue_parties ADD COLUMN pickup_open INTEGER NOT NULL DEFAULT 0;
