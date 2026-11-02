// Sessions, routing, activation, eviction, pruning and state validation (SPEC §6.3, §6.4, §8, §9).
import { describe, expect, it } from "vitest";
import {
  LIMITS,
  SUITES,
  type MessageV2,
  type SessionState,
} from "../../src/index.js";
import { b64uEncode } from "../../src/codec.js";
import { expectCode, T0, testClock } from "../helpers.js";
import {
  adFrom,
  bundleOf,
  CONV,
  commit,
  initiate,
  party,
  receive,
  send,
  type Party,
} from "../parties.js";

type J = Record<string, unknown> & {
  sessions: Array<Record<string, unknown>>;
  skipped: Array<{
    sid: string;
    dh: string;
    keys: Array<[number, string, string]>;
  }>;
  activeSid: string;
};
const json = (p: Party): J => JSON.parse(p.e.serializeState(p.state!)) as J;
const fromJson = (p: Party, j: unknown): SessionState =>
  p.e.parseState(JSON.stringify(j));
const DAY = 24 * 60 * 60 * 1000;

function twoWithClock(): [Party, Party, ReturnType<typeof testClock>] {
  const clock = testClock();
  return [party("alice", clock), party("bob", clock), clock];
}

const accept = (
  to: Party,
  from: Party,
  m: MessageV2,
  over: Record<string, unknown> = {},
) =>
  to.e.acceptSession({
    conversationId: CONV,
    self: to.device,
    expectedPeerBoxPk: from.device.boxPk,
    expectedPeerSignPk: from.device.signPk,
    message: m,
    lookupSpk: (id: number) => to.spks.get(id),
    lookupOtp: (id: number) => to.otps.get(id),
    seenHandshake: (id: number, d: string) => to.replay.has(`${id}:${d}`),
    ...(to.state ? { existing: to.state } : {}),
    ...over,
  } as never);

describe("simultaneous initiation and resets (R1-1, R1-2, R1-3)", () => {
  it("R1-1: both initiate, each sends ≥2 before learning; nothing lost; converges", () => {
    const [a, b] = twoWithClock();
    initiate(a, b);
    initiate(b, a);
    const as = [send(a, "a1"), send(a, "a2")];
    const bs = [send(b, "b1"), send(b, "b2")];
    expect(receive(b, a, as[0]!)).toBe("a1");
    expect(receive(a, b, bs[0]!)).toBe("b1");
    expect(receive(b, a, as[1]!)).toBe("a2");
    expect(receive(a, b, bs[1]!)).toBe("b2");
    // Each side activated the other's session; one quiet round trip converges.
    const a3 = send(a, "a3");
    expect(receive(b, a, a3)).toBe("a3");
    const b3 = send(b, "b3");
    expect(receive(a, b, b3)).toBe("b3");
    expect(json(a).activeSid).toBe(json(b).activeSid);
    expect(json(a).sessions).toHaveLength(2);
  });

  it("R1-2: delayed handshake after the other session has received; converges", () => {
    const [a, b] = twoWithClock();
    initiate(a, b);
    initiate(b, a);
    const late = send(b, "late");
    receive(b, a, send(a, "x"));
    receive(a, b, send(b, "y"));
    expect(receive(a, b, late)).toBe("late");
    receive(b, a, send(a, "z"));
    receive(a, b, send(b, "w"));
    expect(json(a).activeSid).toBe(json(b).activeSid);
  });

  it("R1-3: peer resets after accepting during the simultaneous case; converges", () => {
    const [a, b] = twoWithClock();
    initiate(a, b);
    initiate(b, a);
    receive(b, a, send(a, "a1"));
    b.state = null; // reset
    initiate(b, a);
    expect(receive(a, b, send(b, "after reset"))).toBe("after reset");
    receive(b, a, send(a, "a2"));
    receive(a, b, send(b, "b2"));
    expect(json(a).activeSid).toBe(json(b).activeSid);
  });
});

describe("routing (SPEC §8.2)", () => {
  it("unknown sid without handshake → E2EE_HANDSHAKE_REQUIRED; with a new one → SESSION_CONFLICT with details", () => {
    const [a, b] = twoWithClock();
    initiate(a, b);
    receive(b, a, send(a, "x"));
    receive(a, b, send(b, "y"));
    // A second, unrelated session from a (e.g. after a's reset).
    a.state = null;
    initiate(a, b);
    const m = send(a, "new");
    const err = expectCode(
      () => b.e.decrypt({ state: b.state!, message: m, expectedAd: adFrom(a) }),
      "E2EE_SESSION_CONFLICT",
    );
    expect(err.details).toEqual({
      handshake: m.handshake,
      hsDigest: b.e.handshakeDigest(m.handshake!),
    });
    const { handshake: _h, ...noHs } = m;
    expectCode(
      () =>
        b.e.decrypt({ state: b.state!, message: noHs, expectedAd: adFrom(a) }),
      "E2EE_HANDSHAKE_REQUIRED",
    );
  });

  it("evicted session with a known handshake → DUPLICATE_MESSAGE reason evicted-session", () => {
    const [a, b, clock] = twoWithClock();
    const old = (() => {
      initiate(a, b);
      return send(a, "first");
    })();
    receive(b, a, old);
    for (let i = 0; i < 3; i++) {
      clock.advance(1000);
      initiate(a, b);
      receive(b, a, send(a, `re${i}`));
    }
    expect(json(b).sessions).toHaveLength(3);
    const err = expectCode(
      () =>
        b.e.decrypt({ state: b.state!, message: old, expectedAd: adFrom(a) }),
      "E2EE_DUPLICATE_MESSAGE",
    );
    expect(err.details).toEqual({ reason: "evicted-session" });
  });

  it("reflection and sid mismatch → E2EE_INVALID_INPUT", () => {
    const [a, b] = twoWithClock();
    initiate(a, b);
    const m = send(a, "x");
    receive(b, a, m);
    const reflected = {
      ...m,
      handshake: { ...m.handshake!, initiatorBoxPk: b.device.boxPk },
    };
    expectCode(
      () =>
        b.e.decrypt({
          state: b.state!,
          message: reflected,
          expectedAd: adFrom(a),
        }),
      "E2EE_INVALID_INPUT",
    );
    const wrongSid = { ...m, header: { ...m.header, sid: "AAAAAAAAAAA" } };
    expectCode(
      () =>
        b.e.decrypt({
          state: b.state!,
          message: wrongSid,
          expectedAd: adFrom(a),
        }),
      "E2EE_INVALID_INPUT",
    );
  });
});

describe("activation (SPEC §7.6 step 7, R2-3)", () => {
  it("a skipped-key decrypt does not activate its session", () => {
    const [a, b] = twoWithClock();
    initiate(a, b);
    const x1 = send(a, "x1");
    const x2 = send(a, "x2");
    receive(b, a, x2); // x1 stored as skipped
    initiate(a, b);
    receive(b, a, send(a, "on y"));
    const ySid = json(b).activeSid;
    const r = b.e.decrypt({
      state: b.state!,
      message: x1,
      expectedAd: adFrom(a),
    });
    expect(r.advancedReceiveChain).toBe(false);
    commit(b, r.state);
    expect(json(b).activeSid).toBe(ySid);
  });

  it("eviction picks the oldest non-active lastUsedAt, ties by smaller sid", () => {
    const [a, b, clock] = twoWithClock();
    for (let i = 0; i < 3; i++) {
      initiate(a, b);
      clock.advance(1000);
    }
    const before = json(a).sessions.map((s) => s["sid"]);
    initiate(a, b);
    const after = json(a).sessions.map((s) => s["sid"]);
    expect(after).toEqual([before[1], before[2], after[2]]);
    expect(after[2]).not.toBe(before[0]);
    // Ties: equal lastUsedAt → smaller sid evicted.
    const j = json(a);
    for (const s of j.sessions) s["lastUsedAt"] = new Date(T0).toISOString();
    a.state = fromJson(a, j);
    const nonActive = j.sessions
      .filter((s) => s["sid"] !== j.activeSid)
      .map((s) => s["sid"] as string);
    nonActive.sort((x, y) =>
      Buffer.compare(Buffer.from(x, "base64url"), Buffer.from(y, "base64url")),
    );
    initiate(a, b);
    expect(json(a).sessions.map((s) => s["sid"])).not.toContain(nonActive[0]);
    expect(json(a).sessions.map((s) => s["sid"])).toContain(nonActive[1]);
  });
});

describe("re-stamping and pruning (SPEC §9.3)", () => {
  it("drops skipped keys older than the TTL and keeps at most 2,000, oldest first", () => {
    const [a, b, clock] = twoWithClock();
    initiate(a, b);
    for (let i = 0; i < 1000; i++) send(a, "d");
    receive(b, a, send(a, "x")); // 1000 skipped at T0
    clock.advance(1000);
    receive(a, b, send(b, "r"));
    for (let i = 0; i < 1000; i++) send(a, "d");
    receive(b, a, send(a, "y")); // 1000 more
    expect(json(b).skipped.reduce((n, g) => n + g.keys.length, 0)).toBe(2000);
    clock.advance(1000);
    receive(a, b, send(b, "r2"));
    for (let i = 0; i < 10; i++) send(a, "d");
    receive(b, a, send(a, "z")); // 10 more → 10 oldest dropped
    const j = json(b);
    expect(j.skipped.reduce((n, g) => n + g.keys.length, 0)).toBe(2000);
    const stamps = j.skipped.flatMap((g) => g.keys.map((k) => k[2]));
    expect(stamps.filter((s) => s === new Date(T0).toISOString())).toHaveLength(
      990,
    );
    clock.advance(LIMITS.SKIPPED_KEY_TTL_MS);
    receive(b, a, send(a, "later"));
    expect(json(b).skipped.reduce((n, g) => n + g.keys.length, 0)).toBe(10);
  });

  it("drops idle non-active sessions after the TTL, keeps the active one", () => {
    const [a, b, clock] = twoWithClock();
    initiate(a, b);
    clock.advance(1000);
    initiate(a, b);
    expect(json(a).sessions).toHaveLength(2);
    clock.advance(LIMITS.SKIPPED_KEY_TTL_MS + 1);
    send(a, "x");
    expect(json(a).sessions).toHaveLength(1);
  });

  it("re-stamps stamps more than 24 h ahead; inspectSession clamps to now", () => {
    const [a, b, clock] = twoWithClock();
    initiate(a, b);
    const j = json(a);
    const far = new Date(T0 + DAY + 1).toISOString();
    const near = new Date(T0 + DAY).toISOString();
    j.sessions[0]!["createdAt"] = far;
    j.sessions[0]!["lastUsedAt"] = near;
    (j.sessions[0]!["pending"] as { createdAt: string }).createdAt = far;
    a.state = fromJson(a, j);
    const info = a.e.inspectSession(a.state);
    expect(info.sessions[0]).toMatchObject({
      createdAt: new Date(T0).toISOString(),
      lastUsedAt: new Date(T0).toISOString(),
    });
    send(a, "x");
    const k = json(a).sessions[0]!;
    expect(k["createdAt"]).toBe(new Date(T0).toISOString());
    expect(k["lastUsedAt"]).toBe(near);
    expect((k["pending"] as { createdAt: string }).createdAt).toBe(
      new Date(T0).toISOString(),
    );
    void clock;
  });

  it("inspectSession exposes pending info and no key material", () => {
    const [a, b] = twoWithClock();
    initiate(a, b, true);
    const info = a.e.inspectSession(a.state!);
    expect(info.sessions[0]!.pending).toEqual({
      spkId: 1,
      otpId: 1,
      createdAt: new Date(T0).toISOString(),
    });
    expect(JSON.stringify(info)).not.toMatch(/"(sk|rk|cks|ckr)"/);
    initiate(a, b, false);
    expect(a.e.inspectSession(a.state!).sessions[1]!.pending).toEqual({
      spkId: 1,
      createdAt: new Date(T0).toISOString(),
    });
  });
});

describe("F-1: handshake replay set (SPEC §8.6)", () => {
  it("3-DH founding message replayed after FIFO roll-over → DUPLICATE (evicted-session), also with null state", () => {
    const [a, b] = twoWithClock();
    initiate(a, b, false);
    const founding = send(a, "first");
    receive(b, a, founding);
    for (let i = 0; i < 33; i++) {
      initiate(a, b, false);
      receive(b, a, send(a, `re${i}`));
    }
    expect(
      (json(b)["acceptedHandshakes"] as string[]).includes(
        b.e.handshakeDigest(founding.handshake!),
      ),
    ).toBe(false);
    const e1 = expectCode(
      () => receive(b, a, founding),
      "E2EE_DUPLICATE_MESSAGE",
    );
    expect(e1.details).toEqual({ reason: "evicted-session" });
    b.state = null;
    const e2 = expectCode(
      () => receive(b, a, founding),
      "E2EE_DUPLICATE_MESSAGE",
    );
    expect(e2.details).toEqual({ reason: "evicted-session" });
  });

  it("acceptSession records the replay record and the OTP delete", () => {
    const [a, b] = twoWithClock();
    initiate(a, b, true);
    const m = send(a, "x");
    const cand = accept(b, a, m);
    const r = b.e.decrypt({ state: cand, message: m, expectedAd: adFrom(a) });
    const info = b.e.inspectSession(r.state);
    expect(info.pendingOtpDeletes).toEqual([1]);
    expect(info.pendingReplayRecords).toEqual([
      { spkId: 1, hsDigest: b.e.handshakeDigest(m.handshake!) },
    ]);
  });
});

describe("acceptSession checks in order (SPEC §6.4)", () => {
  const setup = () => {
    const [a, b] = twoWithClock();
    initiate(a, b, true);
    return { a, b, m: send(a, "x") };
  };

  it("parameter validation", () => {
    const { a, b, m } = setup();
    expectCode(
      () => accept(b, a, m, { conversationId: "bad id" }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => accept(b, a, m, { self: { ...b.device, v: 9 } }),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () => accept(b, a, m, { self: { ...b.device, boxSk: 1 } }),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () => accept(b, a, m, { expectedPeerBoxPk: "AAAA" }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(() => accept(b, a, m, { lookupSpk: 1 }), "E2EE_INVALID_INPUT");
    expectCode(() => b.e.acceptSession(null as never), "E2EE_INVALID_INPUT");
  });

  it("steps 1-8", () => {
    const { a, b, m } = setup();
    const { handshake: _h, ...noHs } = m;
    expectCode(() => accept(b, a, noHs), "E2EE_HANDSHAKE_REQUIRED");
    expectCode(
      () => accept(b, a, { ...m, v: 3 } as never),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () => accept(b, a, { ...m, suite: "other" } as never),
      "E2EE_UNSUPPORTED_SUITE",
    );
    expectCode(
      () =>
        accept(b, a, m, { self: a.device, expectedPeerBoxPk: a.device.boxPk }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => accept(b, a, { ...m, header: { ...m.header, sid: "AAAAAAAAAAA" } }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => accept(b, a, m, { lookupSpk: () => undefined }),
      "E2EE_SPK_UNKNOWN",
    );
    const spk = b.spks.get(1)!;
    const other = b.e.generateSignedPrekey(b.device, 2);
    expectCode(
      () => accept(b, a, m, { lookupSpk: () => ({ ...spk, spkId: 2 }) }),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () => accept(b, a, m, { lookupSpk: () => ({ ...spk, pk: other.pk }) }),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () => accept(b, a, m, { lookupSpk: () => ({ ...spk, extra: 1 }) }),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () =>
        accept(b, a, m, {
          lookupSpk: () => ({ ...spk, suites: ["future-v2"] }),
        }),
      "E2EE_UNSUPPORTED_SUITE",
    );
    expectCode(
      () => accept(b, a, m, { seenHandshake: () => 1 }),
      "E2EE_INVALID_STATE",
    );
    const dup = expectCode(
      () => accept(b, a, m, { seenHandshake: () => true }),
      "E2EE_DUPLICATE_MESSAGE",
    );
    expect(dup.details).toEqual({ reason: "evicted-session" });
    expectCode(
      () => accept(b, a, m, { lookupOtp: () => undefined }),
      "E2EE_OTP_UNKNOWN",
    );
    const otp = b.otps.get(1)!;
    expectCode(
      () => accept(b, a, m, { lookupOtp: () => ({ ...otp, otpId: 9 }) }),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () => accept(b, a, m, { lookupOtp: () => ({ ...otp, pk: other.pk }) }),
      "E2EE_INVALID_STATE",
    );
    // seenHandshake is called with exactly (spkId, hsDigest).
    const calls: unknown[] = [];
    accept(b, a, m, {
      seenHandshake: (...args: unknown[]) => (calls.push(args), false),
    });
    expect(calls).toEqual([[1, b.e.handshakeDigest(m.handshake!)]]);
  });

  it("caller callback exceptions propagate unchanged (SPEC §4.8)", () => {
    const { a, b, m } = setup();
    const boom = new Error("store down");
    for (const k of ["lookupSpk", "lookupOtp", "seenHandshake"])
      expect(() =>
        accept(b, a, m, {
          [k]: () => {
            throw boom;
          },
        }),
      ).toThrow(boom);
  });

  it("existing checks (step 5)", () => {
    const { a, b, m } = setup();
    receive(b, a, m);
    const st = b.state!;
    expectCode(
      () => accept(b, a, m, { conversationId: "conv-2" }),
      "E2EE_INVALID_INPUT",
    );
    const mallory = party("mallory");
    initiate(mallory, b);
    const mm = send(mallory, "x");
    expectCode(() => accept(b, mallory, mm), "E2EE_IDENTITY_MISMATCH");
    // A different sender device id with the right key.
    initiate(a, b);
    const m2 = send(a, "y");
    const ad2 = { ...m2.ad, senderDeviceId: "alice-dev-2" };
    expectCode(
      () => accept(b, a, { ...m2, ad: ad2 }),
      "E2EE_IDENTITY_MISMATCH",
    );
    expectCode(() => accept(b, a, m), "E2EE_DUPLICATE_MESSAGE");
    expectCode(
      () => accept(b, a, m, { existing: { ...st, v: 1 } }),
      "E2EE_UNSUPPORTED_VERSION",
    );
  });

  it("without existing, the candidate's only session is active", () => {
    const { a, b, m } = setup();
    const cand = accept(b, a, m);
    const j = JSON.parse(JSON.stringify(cand)) as J;
    expect(j.activeSid).toBe(m.header.sid);
    expect(j).toMatchObject({
      conversationId: CONV,
      selfDeviceId: "bob-dev",
      peerDeviceId: "alice-dev",
      peerBoxPk: a.device.boxPk,
    });
  });
});

describe("initiateSession checks (SPEC §6.3)", () => {
  it("in order", () => {
    const [a, b] = twoWithClock();
    const bundle = bundleOf(b);
    const init = (over: Record<string, unknown>) =>
      a.e.initiateSession({
        conversationId: CONV,
        self: a.device,
        peerBundle: bundle,
        ...over,
      } as never);
    expectCode(() => init({ conversationId: "" }), "E2EE_INVALID_INPUT");
    expectCode(
      () => init({ self: { ...a.device, signPk: "x" } }),
      "E2EE_INVALID_STATE",
    );
    expectCode(() => init({ suite: "nope" }), "E2EE_UNSUPPORTED_SUITE");
    expectCode(
      () => init({ peerBundle: { ...bundle, spkId: 99 } }),
      "E2EE_BUNDLE_SIGNATURE_INVALID",
    );
    const self = bundleOf(a);
    expectCode(
      () =>
        a.e.initiateSession({
          conversationId: CONV,
          self: a.device,
          peerBundle: self,
        }),
      "E2EE_INVALID_INPUT",
    );
    const fut = b.e.generateSignedPrekey(b.device, 5, ["future-v2"] as never);
    const futBundle = b.e.buildDeviceBundle({ device: b.device, spk: fut });
    expectCode(() => init({ peerBundle: futBundle }), "E2EE_UNSUPPORTED_SUITE");
    expectCode(
      () => init({ peerBundle: futBundle, suite: SUITES[0] }),
      "E2EE_UNSUPPORTED_SUITE",
    );
    initiate(a, b);
    expectCode(
      () => init({ existing: a.state, conversationId: "conv-2" }),
      "E2EE_INVALID_INPUT",
    );
    const c = party("carol");
    expectCode(
      () => init({ existing: a.state, peerBundle: bundleOf(c) }),
      "E2EE_IDENTITY_MISMATCH",
    );
    const otherSelf = { ...a.device, deviceId: "alice-dev-2" };
    expectCode(
      () => init({ existing: a.state, self: otherSelf }),
      "E2EE_IDENTITY_MISMATCH",
    );
    expectCode(
      () => init({ existing: { ...a.state!, v: 1 } }),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(() => a.e.initiateSession(null as never), "E2EE_INVALID_INPUT");
  });

  it("uses the RNG in the documented order and the first common suite", () => {
    const [a, b] = twoWithClock();
    const fut = b.e.generateSignedPrekey(b.device, 5, [
      "future-v2",
      SUITES[0]!,
    ] as never);
    const st = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: b.e.buildDeviceBundle({ device: b.device, spk: fut }),
    });
    expect(
      (JSON.parse(a.e.serializeState(st)) as { suite: string }).suite,
    ).toBe(SUITES[0]);
  });
});

describe("D7: parseState and serializeState (SPEC §9.2)", () => {
  const live = (): Party => {
    const [a, b] = twoWithClock();
    initiate(a, b);
    receive(b, a, send(a, "x"));
    receive(a, b, send(b, "y"));
    for (let i = 0; i < 3; i++) send(a, "skip");
    receive(b, a, send(a, "z"));
    return b;
  };

  it("round-trips canonically", () => {
    const b = live();
    const s = b.e.serializeState(b.state!);
    expect(b.e.serializeState(b.e.parseState(s))).toBe(s);
    expect(s).toBe(b.e.canonicalJson(JSON.parse(s)));
  });

  it("rejects unknown v (incl. a BRNR v1 state) with E2EE_UNSUPPORTED_VERSION", () => {
    const b = live();
    const j = json(b);
    expectCode(
      () => b.e.parseState(JSON.stringify({ sessionId: "x", rootKeyB64: "y" })),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () => b.e.parseState(JSON.stringify({ ...j, v: 1 })),
      "E2EE_UNSUPPORTED_VERSION",
    );
    const k = json(b);
    (k.sessions[0]!["founding"] as { v: number }).v = 3;
    expectCode(
      () => b.e.parseState(JSON.stringify(k)),
      "E2EE_UNSUPPORTED_VERSION",
    );
  });

  it("rejects every invariant violation with E2EE_INVALID_STATE", () => {
    const b = live();
    const base = json(b);
    const other = b64uEncode(new Uint8Array(32).fill(3));
    const mutate = (f: (j: J) => void) => {
      const j = structuredClone(base);
      f(j);
      return JSON.stringify(j);
    };
    const s0 = (j: J) => j.sessions[0]!;
    const cases: Array<[string, (j: J) => void]> = [
      ["missing field", (j) => delete j["peerDeviceId"]],
      ["unknown field", (j) => (j["x"] = 1)],
      ["activeSid unknown", (j) => (j.activeSid = "AAAAAAAAAAA")],
      ["duplicate sid", (j) => j.sessions.push(structuredClone(s0(j)))],
      [
        "sid ≠ sid(founding)",
        (j) => ((s0(j)["founding"] as { spkId: number }).spkId = 9),
      ],
      ["skipped sid unknown", (j) => (j.skipped[0]!.sid = "AAAAAAAAAAA")],
      ["skipped n order", (j) => j.skipped[0]!.keys.reverse()],
      ["empty skipped group", (j) => (j.skipped[0]!.keys = [])],
      [
        "duplicate skipped group",
        (j) => j.skipped.push(structuredClone(j.skipped[0]!)),
      ],
      [
        "too many prevRemoteDh",
        (j) => (s0(j)["prevRemoteDh"] = Array(65).fill(other)),
      ],
      [
        "too many accepted handshakes",
        (j) => (j["acceptedHandshakes"] = Array(33).fill(other)),
      ],
      ["counter over 2^31−1", (j) => (s0(j)["ns"] = 2 ** 31)],
      ["founding key mismatch", (j) => (j["peerBoxPk"] = other)],
      ["self equals peer", (j) => (j["selfBoxPk"] = j["peerBoxPk"])],
      ["suite", (j) => (j["suite"] = "other")],
      ["dhs mismatch", (j) => ((s0(j)["dhs"] as { pk: string }).pk = other)],
      ["responder without ckr", (j) => delete s0(j)["ckr"]],
      [
        "pending on responder",
        (j) => (s0(j)["pending"] = { createdAt: new Date(T0).toISOString() }),
      ],
      ["bad stamp", (j) => (s0(j)["createdAt"] = "2026-02-30T00:00:00.000Z")],
      ["wrong key length", (j) => (s0(j)["rk"] = "AAAA")],
      [
        "non-canonical base64url",
        (j) => (s0(j)["rk"] = (s0(j)["rk"] as string).slice(0, 42) + "B"),
      ],
      ["too many sessions", (j) => j.sessions.push({}, {}, {})],
    ];
    for (const [name, f] of cases) {
      const err = expectCode(
        () => b.e.parseState(mutate(f)),
        "E2EE_INVALID_STATE",
      );
      expect(err, name).toBeDefined();
    }
    expectCode(() => b.e.parseState("{"), "E2EE_INVALID_STATE");
    expectCode(() => b.e.parseState("[]"), "E2EE_INVALID_STATE");
    expectCode(() => b.e.parseState(1 as never), "E2EE_INVALID_STATE");
    // A candidate (responder with no chains) is valid only inside decrypt.
    const cand = mutate((j) => {
      delete s0(j)["dhr"];
      delete s0(j)["cks"];
      delete s0(j)["ckr"];
    });
    expectCode(() => b.e.parseState(cand), "E2EE_INVALID_STATE");
    // 2,001 skipped keys.
    const many = mutate((j) => {
      const g = j.skipped[0]!;
      g.keys = Array.from({ length: 2001 }, (_, n) => [
        n,
        g.keys[0]![1],
        g.keys[0]![2],
      ]);
    });
    expectCode(() => b.e.parseState(many), "E2EE_INVALID_STATE");
  });

  it("initiator invariants: cks required, ckr implies dhr", () => {
    const [a, b] = twoWithClock();
    initiate(a, b);
    const j = json(a);
    const s = j.sessions[0]!;
    delete s["cks"];
    expectCode(() => a.e.parseState(JSON.stringify(j)), "E2EE_INVALID_STATE");
    const k = json(a);
    delete k.sessions[0]!["dhr"];
    k.sessions[0]!["ckr"] = k.sessions[0]!["rk"];
    expectCode(() => a.e.parseState(JSON.stringify(k)), "E2EE_INVALID_STATE");
  });
});
