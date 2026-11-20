/**
 * Glicko-2 rating engine — BearBreak.
 * Reference: Mark Glickman, "Example of the Glicko-2 system" (http://www.glicko.net/glicko/glicko2.pdf)
 *
 * Parameters: tau = 0.5, scale = 173.7178.
 * Defaults: rating 1500, RD 350, volatility 0.06.
 *
 * Team support: for 2v2 / 2v1 matches, the opposing registered players are collapsed
 * into a composite opponent (mean rating, mean RD) and every registered player is
 * updated individually against that composite.
 */

const TAU = 0.5;
const SCALE = 173.7178;

export const GLICKO_DEFAULTS = { rating: 1500, rd: 350, vol: 0.06 };

/** Glicko-2 g factor: how much an opponent's RD dampens the expected-score curve. */
const gFactor = rd => {
  const phi = rd / SCALE;
  return 1 / Math.sqrt(1 + (3 * phi * phi) / (Math.PI * Math.PI));
};

/** Expected score for `a` against opponent `b` — the Glicko-2 E(a,b). */
export function expected(a, b) {
  return 1 / (1 + Math.exp(-gFactor(b.rd) * (a.rating / SCALE - b.rating / SCALE)));
}

/** Rate one player from a list of games [{ rating, rd, score }] (score: 1 win / 0 loss / .5 draw). */
export function rate(player, games) {
  const p = { ...GLICKO_DEFAULTS, ...player };

  if (!games.length) { // inactivity: RD grows, rating & volatility unchanged
    const phi = p.rd / SCALE;
    const rdStar = Math.sqrt(phi * phi + p.vol * p.vol) * SCALE;
    return { rating: p.rating, rd: rdStar, vol: p.vol };
  }

  let mu = p.rating / SCALE;
  let phi = p.rd / SCALE;

  let vInv = 0;
  let dSum = 0;
  for (const gm of games) {
    const gj = gFactor(gm.rd);
    const ej = expected(p, gm);
    vInv += gj * gj * ej * (1 - ej);
    dSum += gj * (gm.score - ej);
  }
  const v = 1 / vInv;
  const delta = v * dSum;

  // volatility via Illinois algorithm
  const a = Math.log(p.vol * p.vol);
  const CONV = 1e-6;
  const f = x =>
    (Math.exp(x) * (delta * delta - phi * phi - v - Math.exp(x))) /
      (2 * Math.pow(phi * phi + v + Math.exp(x), 2)) -
    (x - a) / (TAU * TAU);

  let A = a;
  let B;
  if (delta * delta > phi * phi + v) {
    B = Math.log(delta * delta - phi * phi - v);
  } else {
    let k = 1;
    while (f(a - k * TAU) < 0) k++;
    B = a - k * TAU;
  }
  let fA = f(A);
  let fB = f(B);
  while (Math.abs(B - A) > CONV) {
    const C = A + ((A - B) * fA) / (fB - fA);
    const fC = f(C);
    if (fB * fC < 0) { A = B; fA = fB; }
    else { fA = fA / 2; }
    B = C;
    fB = fC;
  }

  const volPrime = Math.exp(A / 2);
  const phiStar = Math.sqrt(phi * phi + volPrime * volPrime);
  const phiPrime = 1 / Math.sqrt(1 / (phiStar * phiStar) + 1 / v);

  let muSum = 0;
  for (const gm of games) {
    const gj = gFactor(gm.rd);
    const ej = expected(p, gm);
    muSum += gj * (gm.score - ej);
  }
  const muPrime = mu + phiPrime * phiPrime * muSum;

  return { rating: muPrime * SCALE, rd: phiPrime * SCALE, vol: volPrime };
}

/** Collapse a team of registered players into one composite opponent. */
export function composite(teamPlayers) {
  if (!teamPlayers.length) return { ...GLICKO_DEFAULTS };
  const rating = teamPlayers.reduce((s, p) => s + p.glicko_rating, 0) / teamPlayers.length;
  const rd = teamPlayers.reduce((s, p) => s + p.glicko_rd, 0) / teamPlayers.length;
  return { rating, rd };
}

/** Rank badge tier for a user row. */
export function rankBadge(rating, rd, rankedGames) {
  if (rd > 110 || rankedGames < 5) return 'Provisional';
  if (rating >= 1700) return 'Elite';
  if (rating >= 1550) return 'Rack Shark';
  if (rating >= 1400) return 'Table Regular';
  return 'Cue Rookie';
}
