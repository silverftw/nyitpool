# BearBreak

Billiards-table portal for the NYIT pool hall: shot clocks, chess-clock game banks, a live table queue with accounts, match confirmations, and Glicko-2 rankings.

Single-page timer app (`public/index.html`, vanilla JS, no build step) served by a Cloudflare Worker that also exposes `/api/*` endpoints backed by D1.

## Structure

```
nyitpool/
├── public/index.html    # the timer SPA (served as static assets)
├── src/index.js         # Worker: /api/* routes, everything else -> static assets
├── migrations/          # D1 schema migrations (Table Queue)
├── wrangler.jsonc       # Workers + assets + D1 config
└── package.json         # wrangler scripts
```

## Local dev

```bash
npm install
npm run db:migrate:local   # apply D1 schema to the local dev database
npm run dev                # http://127.0.0.1:8787  (timer + /api/*)
```

Plain static preview without the Worker: serve `public/` with any static server (e.g. `npx serve public`).

## First deploy (wrangler)

```bash
npx wrangler login
npm run db:create          # copy the printed database_id into wrangler.jsonc
npm run db:migrate         # apply schema to remote D1
npm run deploy
```

## Automatic deploys from GitHub (recommended)

Connect the repo to Cloudflare **Workers Builds** so every `git push` to `main` deploys automatically:

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Import from Git** (or open the existing `nyitpool` worker → **Settings → Builds → Connect to Git**).
2. Authorize the GitHub app and select `silverftw/nyitpool`.
3. Branch: `main` · Build command: *(none)* · Deploy command: `npx wrangler deploy`.
4. Push — watch the build in the dashboard; the worker URL updates on every push.

## Secrets (required before first deploy of the companion)

```bash
npx wrangler secret put SESSION_SECRET   # HMAC key for session tokens
```

Local dev: create `.dev.vars` (gitignored) with `SESSION_SECRET=...`.

Admin is a per-user permission: `UPDATE users SET is_admin = 1 WHERE username IN (...)`
(migration 0014 adds the column). A signed-in session on a flagged account is always
admin — no unlock step, no shared PIN (removed 2026-11-21).

## Mobile Companion (Table Queue tile)

- **Accounts**: username + 4–6 digit PIN (PBKDF2-SHA256 hash, HMAC-signed session token kept in localStorage).
- **Live queue**: the table hosts **two parties** — a party is a team: **Solo** (one player) or **Duo** (one or two; teammate/guest attachable, open slots claimable while waiting). Winner stays, loser's seat refills from the line. Solo vs Duo at the table = 2v1 (log it as `2v1`).
- **Queue hours (ET)**: open **9am–9pm**; solo play allowed **9–12am** and **6–9pm**, **duo-only noon–6pm**. At close the queue clears itself and joins are refused (403) — enforced server-side in `America/New_York`.
- **Admin override**: sign in with an account flagged `is_admin` (see Secrets above) — the header shows the **ADMIN** tag; the admin page has a **Queue status** switcher: 🕰 **Auto** (clock rules) / 🟢 **Open** / 🕒 **Duo only** / ⛔ **Offline** (wipes the live queue). Override beats the clock until set back to Auto. `POST /api/admin/queue-mode` `{mode}` with the admin session's Bearer token.
- **3-vote consensus skip**: any three accounts can skip a party out of the line.
- **Match logging**: ranked (all registered) or casual — any guest forces casual. Other registered players confirm in the notification drawer; a single confirmation from the opposing team logs the match. Disputes escalate to admin force-approve.
- **Glicko-2 ratings**: per-player updates vs composite-team opponents for 2v2/2v1; tiers: Provisional / Cue Rookie / Table Regular / Rack Shark / 8-Ball Elite.
- The desktop/laptop **Table Timer stays 100% client-side and login-free**.

## API

Auth: `POST /api/auth/register|login`, `GET /api/auth/me` (Bearer token). Admin actions need a signed-in `is_admin` session's Bearer token.

- `GET /api/queue` — active parties (playing first, then waiting, with skip-vote counts)
- `POST /api/queue/join` `{format, p2_user_id? | p2_guest_name?}`
- `PATCH /api/queue/:id/teammate` — creator sets Player 2, or a registered player claims the open slot (`{}`)
- `POST /api/queue/:id/vote-skip` — one vote per account; ≥3 skips the party
- `DELETE /api/queue/:id` — leave own party (admin: any)
- `POST /api/matches/submit` `{match_type, format, winner_team, teams:{1:[…],2:[…]}}` (players: `{user_id}` or `{guest_name}`)
- `GET /api/notifications` — my pending confirmations (+ all pending/disputed for admin sessions)
- `POST /api/matches/:id/respond` `{action: "confirm"|"dispute"}`
- `POST /api/matches/:id/admin-approve` — admin force-commit
- `GET /api/leaderboard` — rankings
- `GET /api/matches?player=<username|nickname>&since=<epoch ms>&until=<epoch ms>&limit=` — filtered match history (submission/commit time in `played_at`)
- `GET /api/users?q=` — shared player search (nickname + username, includes elo)
- `GET /api/admin/audit` — audit log (register/join/leave/votes/skips/mode changes/match lifecycle, latest 200)
- `GET /api/admin/players` — all players with ratings and records
- Match rule: every team needs **at least one registered player** — all-guest sides (incl. 1 registered vs 1 lone guest) are rejected 400

## Production

Live at **https://app.nyitpool.workers.dev** — every merge to `main` auto-deploys via Cloudflare Workers Builds.

## Timer controls

`SPACE` pass turn / start · `ENTER` reset shot clock (or refund turn time in game mode) · `P` pause — all work while paused too. Web Audio cues + Screen Wake Lock included.
