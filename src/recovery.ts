// RecoveryTrackerV1 (SPEC §8.4). All functions are pure.
import { LIMITS } from "./constants.js";
import { iso, isTimestamp, ms } from "./codec.js";
import type { Clock } from "./context.js";
import { fail } from "./errors.js";
import { canonicalJson } from "./jcs.js";
import { parseStrict, readParams, trackerSchema } from "./schemas.js";
import { restamp } from "./state.js";
import type { RecoveryTrackerV1 } from "./types.js";

const DAY = 24 * 60 * 60 * 1000;

/** Strict parse plus invariants; returns a fresh copy. */
export function parseTrackerObject(x: unknown): RecoveryTrackerV1 {
  const t = parseStrict(trackerSchema, x, "state", {
    v: 1,
  }) as RecoveryTrackerV1;
  if (t.attempts > 0 && t.lastAt === undefined)
    fail("E2EE_INVALID_STATE", "attempts without lastAt");
  return t;
}

export function parseTracker(raw: unknown): RecoveryTrackerV1 {
  if (typeof raw !== "string")
    return fail("E2EE_INVALID_STATE", "tracker is not a string");
  let x: unknown;
  try {
    x = JSON.parse(raw);
  } catch {
    // Invalid JSON leaves x undefined, which fails as INVALID_STATE below.
  }
  return parseTrackerObject(x);
}

export const serializeTracker = (t: unknown): string =>
  canonicalJson(parseTrackerObject(t));

/**
 * Load (or start) a tracker, pick the tracker clock and apply the §9.3 step 1 re-stamping against it.
 * The tracker clock is max(now, seenAt): it never runs back within FUTURE_STAMP_TOLERANCE_MS, so a
 * clock stepped back and then corrected cannot age the window early (SPEC §8.4).
 */
function load(
  t: unknown,
  wall: Clock,
  allowNull: boolean,
): [RecoveryTrackerV1, Clock] {
  const x =
    t === null && allowNull
      ? ({ v: 1, sightings: [], attempts: 0, window: [] } as RecoveryTrackerV1)
      : parseTrackerObject(t);
  const hi = Math.max(wall.ms, ms(restamp(x.seenAt ?? wall.iso, wall)));
  const now = { ms: hi, iso: iso(hi) };
  x.seenAt = now.iso;
  x.sightings = x.sightings.map((s) => restamp(s, now));
  x.window = x.window.map((s) => restamp(s, now));
  if (x.lastAt !== undefined) x.lastAt = restamp(x.lastAt, now);
  if (x.lastRefreshAt !== undefined)
    x.lastRefreshAt = restamp(x.lastRefreshAt, now);
  return [x, now];
}

const pruneWindow = (t: RecoveryTrackerV1, now: Clock): void => {
  t.window = t.window.filter((w) => now.ms - ms(w) <= DAY);
};

export function recordRecoverySignal(
  wall: Clock,
  t: unknown,
  reason: unknown,
): RecoveryTrackerV1 {
  const [x, now] = load(t, wall, true);
  if (reason !== "handshake-required" && reason !== "evicted-session")
    fail("E2EE_INVALID_INPUT", "invalid recovery reason");
  x.sightings.push(now.iso);
  while (x.sightings.length > 4) x.sightings.shift();
  return x;
}

export function recoveryDecision(
  wall: Clock,
  t: unknown,
): { due: boolean; tracker: RecoveryTrackerV1 } {
  const [x, now] = load(t, wall, false);
  pruneWindow(x, now);
  const elapsed =
    x.lastAt === undefined ? Infinity : Math.max(0, now.ms - ms(x.lastAt));
  const effective = Math.max(0, x.attempts - Math.floor(elapsed / DAY));
  const backoff =
    effective === 0
      ? 0
      : Math.min(
          LIMITS.RECOVERY_BACKOFF_MAX_MS,
          LIMITS.RECOVERY_BACKOFF_BASE_MS * 2 ** (effective - 1),
        );
  // SPEC §8.4 (a): two sightings ≥ 10 min apart, or one ≥ 10 min old, counting sightings ≤ now.
  // The first case implies the second (the older of the two is ≥ 10 min old), so one test covers both.
  const sighted = x.sightings.some(
    (v) => ms(v) <= now.ms && now.ms - ms(v) >= LIMITS.RECOVERY_SIGHTING_MS,
  );
  const due =
    sighted &&
    elapsed >= backoff &&
    x.window.length < LIMITS.MAX_RECOVERIES_PER_DAY;
  if (due) {
    x.attempts = Math.min(effective + 1, LIMITS.MAX_INT);
    x.lastAt = now.iso;
    x.window.push(now.iso);
    x.sightings = [];
  }
  return { due, tracker: x };
}

export function onDecrypt(
  wall: Clock,
  t: unknown,
  info: unknown,
): RecoveryTrackerV1 {
  const [x, now] = load(t, wall, false);
  const i = readParams(info, [
    "advancedReceiveChain",
    "sessionCreatedAt",
  ] as const);
  if (
    typeof i.advancedReceiveChain !== "boolean" ||
    !isTimestamp(i.sessionCreatedAt)
  )
    return fail("E2EE_INVALID_INPUT", "invalid decrypt info");
  pruneWindow(x, now);
  if (i.advancedReceiveChain) {
    x.sightings = [];
    if (x.lastAt === undefined || ms(i.sessionCreatedAt) >= ms(x.lastAt))
      x.attempts = 0;
  }
  return x;
}

/** SPEC §8.4: a refresh is also a re-initiation, so it shares the recovery window. */
export function refreshDecision(
  wall: Clock,
  t: unknown,
): { due: boolean; tracker: RecoveryTrackerV1 } {
  const [x, now] = load(t, wall, true);
  pruneWindow(x, now);
  const due =
    (x.lastRefreshAt === undefined ||
      now.ms - ms(x.lastRefreshAt) >= LIMITS.REFRESH_INTERVAL_MS) &&
    x.window.length < LIMITS.MAX_RECOVERIES_PER_DAY;
  if (due) {
    x.lastRefreshAt = now.iso;
    x.window.push(now.iso);
  }
  return { due, tracker: x };
}
