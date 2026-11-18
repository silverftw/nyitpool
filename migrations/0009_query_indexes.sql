-- Row-read blowout fix (2026-11-18 D1 quota incident): /api/matches and the
-- pending-match detail correlated-scan match_players / pending_match_players
-- by match id with no index — every history poll read ~10k rows and the 5s
-- polling burned the 5M rows/day free-tier budget by evening.
CREATE INDEX IF NOT EXISTS idx_mp_match ON match_players (match_id);
CREATE INDEX IF NOT EXISTS idx_pmp_match ON pending_match_players (pending_match_id);
-- history: since/until range + ORDER BY played_at DESC LIMIT both ride this
CREATE INDEX IF NOT EXISTS idx_matches_played ON matches (played_at);
-- team_up_requests rows are never deleted; lazy expiry + the stuck-party
-- IN() subquery scan the whole table on EVERY /api/queue poll, so that cost
-- grows forever as invites accumulate. Index the hot predicates.
CREATE INDEX IF NOT EXISTS idx_tur_pending_age ON team_up_requests (created_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_tur_kind_status ON team_up_requests (kind, status);
