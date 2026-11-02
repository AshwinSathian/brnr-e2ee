// S-2, S-3: the forced re-initiation bound of SPEC §8.4 (3 per 24 h) holds for refreshes and clock steps.
import { describe, expect, it } from "vitest";
import type { E2ee, RecoveryTrackerV1 } from "../../src/index.js";
import { expectCode, makeE2ee, testClock, T0 } from "../helpers.js";
import { adFrom, initiate, party, receive, send } from "../parties.js";

const MIN = 60_000;
const H = 60 * MIN;
const iso = (t: number) => new Date(t).toISOString();

/** Up to three forced recoveries: forged trigger, wait 10 min, decide, wait out the backoff. */
function burst(
  e: E2ee,
  clock: ReturnType<typeof testClock>,
  t0: RecoveryTrackerV1 | null,
) {
  let t = t0;
  let n = 0;
  for (let i = 0; i < 3; i++) {
    t = e.recordRecoverySignal(t, "handshake-required");
    clock.advance(10 * MIN);
    const d = e.recoveryDecision(t);
    t = d.tracker;
    if (d.due) n++;
    clock.advance(2 ** i * H);
  }
  return { t: t!, n };
}

describe("S-2: refreshes count against the recovery window", () => {
  it("a forged SKIP_TOO_LARGE refresh after three recoveries is not due", () => {
    const clock = testClock();
    const alice = party("alice", clock);
    const bob = party("bob", clock);
    initiate(bob, alice);
    receive(alice, bob, send(bob, "hi"));
    const m = send(bob, "x");
    const forged = { ...m, header: { ...m.header, n: m.header.n + 1001 } };
    expectCode(
      () =>
        alice.e.decrypt({
          state: alice.state!,
          message: forged,
          expectedAd: adFrom(bob),
        }),
      "E2EE_SKIP_TOO_LARGE",
    );
    const start = clock.ms;
    const { t, n } = burst(alice.e, clock, null);
    expect(n).toBe(3);
    const r = alice.e.refreshDecision(t);
    expect(clock.ms - start).toBeLessThan(24 * H);
    expect(r.due).toBe(false);
    expect(r.tracker.lastRefreshAt).toBeUndefined();
  });

  it("a refresh takes a window slot, leaving room for two recoveries", () => {
    const clock = testClock();
    const { e } = makeE2ee("s2", clock);
    const r = e.refreshDecision(null);
    expect(r.due).toBe(true);
    expect(r.tracker.window).toEqual([iso(T0)]);
    expect(burst(e, clock, r.tracker).n).toBe(2);
  });
});

describe("S-3: the tracker clock does not run back", () => {
  it("a clock stepped back (≤ 24 h) and then corrected allows no extra recoveries in a real day", () => {
    const clock = testClock();
    const { e } = makeE2ee("s3", clock);
    const realStart = clock.ms;
    const t0 = e.recordRecoverySignal(null, "evicted-session"); // seenAt = T0
    clock.set(realStart - 20 * H); // stepped back
    const a = burst(e, clock, t0); // real ~7.7 h pass
    const real = realStart + (clock.ms - (realStart - 20 * H));
    clock.set(real); // corrected
    const b = burst(e, clock, a.t);
    expect(clock.ms - realStart).toBeLessThan(24 * H);
    expect(a.n).toBe(0);
    expect(a.n + b.n).toBeLessThanOrEqual(3);
  });

  it("while the clock is behind seenAt, stamps use seenAt; a seenAt over 24 h ahead is forgotten", () => {
    const clock = testClock();
    const { e } = makeE2ee("s3b", clock);
    const ahead = (d: number): RecoveryTrackerV1 => ({
      v: 1,
      sightings: [],
      attempts: 0,
      window: [],
      seenAt: iso(T0 + d),
    });
    expect(
      e.recordRecoverySignal(ahead(24 * H), "handshake-required"),
    ).toMatchObject({
      sightings: [iso(T0 + 24 * H)],
      seenAt: iso(T0 + 24 * H),
    });
    expect(
      e.recordRecoverySignal(ahead(24 * H + 1), "handshake-required"),
    ).toMatchObject({ sightings: [iso(T0)], seenAt: iso(T0) });
    expect(
      e.recordRecoverySignal(ahead(-H), "handshake-required"),
    ).toMatchObject({ sightings: [iso(T0)], seenAt: iso(T0) });
    expectCode(
      () => e.parseTracker(JSON.stringify({ ...ahead(0), seenAt: "x" })),
      "E2EE_INVALID_STATE",
    );
  });
});
