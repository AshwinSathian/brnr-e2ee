import { describe, expect, it } from "vitest";
import type { RecoveryTrackerV1 } from "../../src/index.js";
import { expectCode, makeE2ee, T0, testClock } from "../helpers.js";

const MIN = 60_000;
const H = 60 * MIN;
const D = 24 * H;
const iso = (t: number) => new Date(t).toISOString();

function setup() {
  const clock = testClock();
  const { e } = makeE2ee("rec", clock);
  return { e, clock };
}

describe("RecoveryTrackerV1 (SPEC §8.4)", () => {
  it("records sightings FIFO 4, from null", () => {
    const { e, clock } = setup();
    let t = e.recordRecoverySignal(null, "handshake-required");
    expect(t).toEqual({
      v: 1,
      sightings: [iso(T0)],
      attempts: 0,
      window: [],
      seenAt: iso(T0),
    });
    for (let i = 1; i <= 5; i++) {
      clock.advance(MIN);
      t = e.recordRecoverySignal(t, "evicted-session");
    }
    expect(t.sightings).toEqual([2, 3, 4, 5].map((i) => iso(T0 + i * MIN)));
    expectCode(
      () => e.recordRecoverySignal(t, "other" as never),
      "E2EE_INVALID_INPUT",
    );
  });

  it("due needs two sightings ≥10 min apart or one standing ≥10 min", () => {
    const { e, clock } = setup();
    let t = e.recordRecoverySignal(null, "handshake-required");
    expect(e.recoveryDecision(t).due).toBe(false);
    clock.advance(9 * MIN);
    t = e.recordRecoverySignal(t, "handshake-required");
    expect(e.recoveryDecision(t).due).toBe(false);
    clock.advance(MIN);
    const r = e.recoveryDecision(t);
    expect(r.due).toBe(true);
    expect(r.tracker).toEqual({
      v: 1,
      sightings: [],
      attempts: 1,
      lastAt: iso(clock.ms),
      window: [iso(clock.ms)],
      seenAt: iso(clock.ms),
    });
    expect(
      e.recoveryDecision({ v: 1, sightings: [], attempts: 0, window: [] }).due,
    ).toBe(false);
    // Two sightings 10 min apart, both recent relative to each other.
    const t2: RecoveryTrackerV1 = {
      v: 1,
      sightings: [iso(clock.ms - 10 * MIN), iso(clock.ms)],
      attempts: 0,
      window: [],
    };
    expect(e.recoveryDecision(t2).due).toBe(true);
  });

  it("backoff doubles from 1 h, capped at 24 h, and decays by one per day", () => {
    const { e, clock } = setup();
    const base = (attempts: number, lastAgo: number): RecoveryTrackerV1 => ({
      v: 1,
      sightings: [iso(clock.ms - 10 * MIN)],
      attempts,
      lastAt: iso(clock.ms - lastAgo),
      window: [],
    });
    expect(e.recoveryDecision(base(1, H - 1)).due).toBe(false);
    expect(e.recoveryDecision(base(1, H)).due).toBe(true);
    expect(e.recoveryDecision(base(2, 2 * H - 1)).due).toBe(false);
    expect(e.recoveryDecision(base(2, 2 * H)).tracker.attempts).toBe(3);
    expect(e.recoveryDecision(base(9, 24 * H - 1)).due).toBe(false);
    // After one day, effective attempts drop by one: 9 → 8, backoff still 24 h → due at exactly 24 h.
    const r = e.recoveryDecision(base(9, 24 * H));
    expect(r).toMatchObject({ due: true, tracker: { attempts: 9 } });
    expect(e.recoveryDecision(base(3, 3 * D)).tracker.attempts).toBe(1);
    // Not due: unchanged except the pruned window.
    const nd = base(1, 0);
    nd.window = [iso(clock.ms - D - 1), iso(clock.ms - D)];
    expect(e.recoveryDecision(nd)).toEqual({
      due: false,
      tracker: { ...nd, window: [iso(clock.ms - D)], seenAt: iso(clock.ms) },
    });
  });

  it("hard cap: at most 3 recoveries in 24 h", () => {
    const { e, clock } = setup();
    const t: RecoveryTrackerV1 = {
      v: 1,
      sightings: [iso(clock.ms - 10 * MIN)],
      attempts: 0,
      window: [iso(clock.ms - 3 * H), iso(clock.ms - 2 * H), iso(clock.ms - H)],
    };
    expect(e.recoveryDecision(t).due).toBe(false);
    clock.advance(21 * H + 1);
    expect(
      e.recoveryDecision({ ...t, sightings: [iso(clock.ms - 10 * MIN)] }).due,
    ).toBe(true);
  });

  it("onDecrypt clears sightings and resets attempts only on proof", () => {
    const { e, clock } = setup();
    const t: RecoveryTrackerV1 = {
      v: 1,
      sightings: [iso(T0)],
      attempts: 2,
      lastAt: iso(T0),
      window: [iso(T0)],
    };
    expect(
      e.onDecrypt(t, {
        advancedReceiveChain: false,
        sessionCreatedAt: iso(T0),
      }),
    ).toEqual({ ...t, seenAt: iso(T0) });
    expect(
      e.onDecrypt(t, {
        advancedReceiveChain: true,
        sessionCreatedAt: iso(T0 - 1),
      }),
    ).toEqual({ ...t, sightings: [], seenAt: iso(T0) });
    expect(
      e.onDecrypt(t, { advancedReceiveChain: true, sessionCreatedAt: iso(T0) }),
    ).toEqual({ ...t, sightings: [], attempts: 0, seenAt: iso(T0) });
    const noLast: RecoveryTrackerV1 = {
      v: 1,
      sightings: [iso(T0)],
      attempts: 0,
      window: [],
    };
    expect(
      e.onDecrypt(noLast, {
        advancedReceiveChain: true,
        sessionCreatedAt: iso(T0),
      }).sightings,
    ).toEqual([]);
    clock.advance(D + 1);
    expect(
      e.onDecrypt(t, { advancedReceiveChain: false, sessionCreatedAt: iso(T0) })
        .window,
    ).toEqual([]);
    for (const info of [
      null,
      {},
      { advancedReceiveChain: 1, sessionCreatedAt: iso(T0) },
      { advancedReceiveChain: true, sessionCreatedAt: "x" },
    ])
      expectCode(() => e.onDecrypt(t, info as never), "E2EE_INVALID_INPUT");
  });

  it("refreshDecision: at most one per 24 h", () => {
    const { e, clock } = setup();
    const r1 = e.refreshDecision(null);
    expect(r1).toEqual({
      due: true,
      tracker: {
        v: 1,
        sightings: [],
        attempts: 0,
        window: [iso(T0)],
        lastRefreshAt: iso(T0),
        seenAt: iso(T0),
      },
    });
    clock.advance(D - 1);
    expect(e.refreshDecision(r1.tracker).due).toBe(false);
    clock.advance(1);
    expect(e.refreshDecision(r1.tracker)).toMatchObject({
      due: true,
      tracker: { lastRefreshAt: iso(T0 + D) },
    });
  });

  it("re-stamps stamps more than 24 h in the future", () => {
    const { e } = setup();
    const far = iso(T0 + D + 1);
    const near = iso(T0 + D);
    const t: RecoveryTrackerV1 = {
      v: 1,
      sightings: [far, near],
      attempts: 1,
      lastAt: far,
      window: [far],
      lastRefreshAt: far,
    };
    const r = e.recordRecoverySignal(t, "handshake-required");
    expect(r).toEqual({
      v: 1,
      sightings: [iso(T0), near, iso(T0)],
      attempts: 1,
      lastAt: iso(T0),
      window: [iso(T0)],
      lastRefreshAt: iso(T0),
      seenAt: iso(T0),
    });
  });

  it("parse and serialise with invariants", () => {
    const { e } = setup();
    const t: RecoveryTrackerV1 = {
      v: 1,
      sightings: [iso(T0)],
      attempts: 1,
      lastAt: iso(T0),
      window: [],
    };
    expect(e.parseTracker(e.serializeTracker(t))).toEqual(t);
    expect(e.serializeTracker(t)).toBe(
      JSON.stringify({
        attempts: 1,
        lastAt: iso(T0),
        sightings: [iso(T0)],
        v: 1,
        window: [],
      }),
    );
    expectCode(
      () => e.parseTracker(JSON.stringify({ ...t, v: 2 })),
      "E2EE_UNSUPPORTED_VERSION",
    );
    for (const bad of [
      { ...t, lastAt: undefined, attempts: 1 },
      { ...t, attempts: -1 },
      { ...t, sightings: Array(5).fill(iso(T0)) },
      { ...t, window: Array(4).fill(iso(T0)) },
      { ...t, lastAt: "2026-02-30T00:00:00.000Z" },
      { ...t, extra: 1 },
    ])
      expectCode(
        () => e.parseTracker(JSON.stringify(bad)),
        "E2EE_INVALID_STATE",
      );
    expectCode(() => e.parseTracker("{"), "E2EE_INVALID_STATE");
    expectCode(() => e.parseTracker(5 as never), "E2EE_INVALID_STATE");
    expectCode(() => e.parseTracker("[]"), "E2EE_INVALID_STATE");
    expectCode(
      () => e.serializeTracker({ ...t, attempts: 1.5 }),
      "E2EE_INVALID_STATE",
    );
    expectCode(() => e.recoveryDecision(null as never), "E2EE_INVALID_STATE");
  });
});
