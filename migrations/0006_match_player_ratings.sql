-- Per-player rating context for committed matches: the Glicko rating each
-- registered player had right before and right after this match. Written on
-- commit and rewritten wholesale by the rating replay (recalc / admin edits).
-- NULL for guests and for rows committed before this migration (the replay
-- backfills everything on its next run).
ALTER TABLE match_players ADD COLUMN rating_before REAL;
ALTER TABLE match_players ADD COLUMN rating_after REAL;
