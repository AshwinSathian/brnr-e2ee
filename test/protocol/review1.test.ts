// Regression tests for adversarial review round 1 and SPEC §20 item 13.
import { describe, expect, it } from "vitest";
import { LIMITS, type MessageV2, type SessionState } from "../../src/index.js";
import { expectCode, T0 } from "../helpers.js";
import {
  adFrom,
  CONV,
  commit,
  initiate,
  party,
  receive,
  send,
  type Party,
} from "../parties.js";
import { testClock } from "../helpers.js";

const two = (): [Party, Party] => {
  const clock = testClock();
  const a = party("alice", clock);
  const b = party("bob", clock);
  initiate(a, b);
  return [a, b];
};
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
    seenHandshake: () => false,
    ...(to.state ? { existing: to.state } : {}),
    ...over,
  } as never);

describe("review round 1 regressions", () => {
  it("-0 is not an integer (state, wire, canonicalJson)", () => {
    const [a, b] = two();
    const m = send(a, "x");
    receive(b, a, m);
    const raw = b.e.serializeState(b.state!);
    expectCode(
      () => b.e.parseState(raw.replace('"pn":0', '"pn":-0')),
      "E2EE_INVALID_STATE",
    );
    const e = expectCode(
      () => b.e.parseMessage(JSON.stringify(m).replace('"pn":0', '"pn":-0')),
      "E2EE_INVALID_INPUT",
    );
    expect(e.details).toEqual({ path: "header.pn" });
    expectCode(() => b.e.canonicalJson({ a: -0 }), "E2EE_INVALID_INPUT");
  });

  it("canonicalJson rejects sparse arrays and deep nesting", () => {
    const [a] = two();
    // eslint-disable-next-line no-sparse-arrays
    expectCode(() => a.e.canonicalJson([, "x"]), "E2EE_INVALID_INPUT");
    let deep: unknown = "x";
    for (let i = 0; i < 33; i++) deep = [deep];
    expectCode(() => a.e.canonicalJson(deep), "E2EE_INVALID_INPUT");
    let ok: unknown = "x";
    for (let i = 0; i < 32; i++) ok = [ok];
    expect(a.e.canonicalJson(ok)).toContain("x");
    let huge: unknown = "x";
    for (let i = 0; i < 200_000; i++) huge = [huge];
    expectCode(() => a.e.canonicalJson(huge), "E2EE_INVALID_INPUT");
  });

  it("throwing getters on caller input give typed errors", () => {
    const [a, b] = two();
    const m = send(a, "x");
    const trap = (o: object, key: string) =>
      Object.defineProperty({ ...o }, key, {
        get() {
          throw new Error("trap");
        },
        enumerable: true,
      });
    expectCode(() => b.e.parseMessage(trap(m, "v")), "E2EE_INVALID_INPUT");
    expectCode(
      () => accept(b, a, m, { self: trap(b.device, "boxSk") }),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () =>
        b.e.decrypt(
          trap(
            { state: a.state, message: m, expectedAd: adFrom(a) },
            "message",
          ) as never,
        ),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        b.e.parseMessage(
          new Proxy(m, {
            ownKeys: () => {
              throw new Error("x");
            },
          }),
        ),
      "E2EE_INVALID_INPUT",
    );
  });

  it("lookup callbacks returning null mean unknown", () => {
    const [a, b] = two();
    const m = send(a, "x");
    expectCode(
      () => accept(b, a, m, { lookupSpk: () => null }),
      "E2EE_SPK_UNKNOWN",
    );
    expectCode(
      () => accept(b, a, m, { lookupOtp: () => null }),
      "E2EE_OTP_UNKNOWN",
    );
  });

  it("the returned message does not share objects with the returned state", () => {
    const [a] = two();
    const { state, message } = a.e.encrypt({
      state: a.state!,
      plaintext: new Uint8Array(1),
      ad: adFrom(a),
    });
    (message.handshake as { spkId: number }).spkId = 99;
    expect(() => a.e.serializeState(state)).not.toThrow();
  });

  it("eviction sees re-stamped stamps", () => {
    const clock = testClock();
    const a = party("alice", clock);
    const b = party("bob", clock);
    for (let i = 0; i < 3; i++) {
      initiate(a, b);
      clock.advance(1000);
    }
    const j = JSON.parse(a.e.serializeState(a.state!)) as {
      sessions: Array<{ sid: string; lastUsedAt: string }>;
      activeSid: string;
    };
    // The oldest non-active session gets a far-future stamp; after re-stamping it is "now", so the other one is evicted.
    const nonActive = j.sessions.filter((s) => s.sid !== j.activeSid);
    nonActive[0]!.lastUsedAt = new Date(T0 + 10 * 24 * 3600_000).toISOString();
    a.state = a.e.parseState(JSON.stringify(j));
    initiate(a, b);
    const sids = (
      JSON.parse(a.e.serializeState(a.state)) as {
        sessions: Array<{ sid: string }>;
      }
    ).sessions.map((s) => s.sid);
    expect(sids).toContain(nonActive[0]!.sid);
    expect(sids).not.toContain(nonActive[1]!.sid);
  });

  it("a candidate state must decrypt on its new session (SPEC §9.2a)", () => {
    const [a, b] = two();
    receive(b, a, send(a, "x"));
    receive(a, b, send(b, "y"));
    const onOld = send(a, "old session");
    a.state = null;
    initiate(a, b);
    const fresh = send(a, "new session");
    const cand = accept(b, a, fresh);
    expectCode(
      () => b.e.decrypt({ state: cand, message: onOld, expectedAd: adFrom(a) }),
      "E2EE_INVALID_STATE",
    );
    expect(
      new TextDecoder().decode(
        b.e.decrypt({ state: cand, message: fresh, expectedAd: adFrom(a) })
          .plaintext,
      ),
    ).toBe("new session");
    // Two candidates in one state.
    const j = JSON.parse(JSON.stringify(cand)) as {
      sessions: Array<Record<string, unknown>>;
    };
    const twin = j.sessions.at(-1)!;
    const c2 = structuredClone(twin);
    j.sessions.splice(0, 1, c2);
    expectCode(
      () =>
        b.e.decrypt({
          state: j as unknown as SessionState,
          message: fresh,
          expectedAd: adFrom(a),
        }),
      "E2EE_INVALID_STATE",
    );
  });

  it("a reused ratchet key with a skipped group → DUPLICATE_MESSAGE, never a broken state", () => {
    const [a, b] = two();
    receive(b, a, send(a, "x"));
    receive(a, b, send(b, "y"));
    const s1 = send(a, "s1");
    const s2 = send(a, "s2");
    receive(b, a, s2); // s1's key stored under (sid, dhA)
    // Force b's state to forget dhA as current and previous, keeping the skipped group.
    const j = JSON.parse(b.e.serializeState(b.state!)) as {
      sessions: Array<Record<string, unknown>>;
    };
    j.sessions[0]!["dhr"] =
      j.sessions[0]!["dhs"] &&
      (JSON.parse(b.e.serializeState(b.state!)) as { selfBoxPk: string })
        .selfBoxPk;
    j.sessions[0]!["prevRemoteDh"] = [];
    const st = b.e.parseState(JSON.stringify(j));
    const reused = { ...s2, header: { ...s2.header, n: 5 } };
    expectCode(
      () => b.e.decrypt({ state: st, message: reused, expectedAd: adFrom(a) }),
      "E2EE_DUPLICATE_MESSAGE",
    );
    // The stored key itself is still usable.
    commit(
      b,
      b.e.decrypt({ state: st, message: s1, expectedAd: adFrom(a) }).state,
    );
  });

  it("received pn may be 2^31−1, n at most 2^31−2", () => {
    const [a] = two();
    const m = send(a, "x");
    expect(
      a.e.parseMessage({ ...m, header: { ...m.header, pn: LIMITS.MAX_INT } })
        .header.pn,
    ).toBe(LIMITS.MAX_INT);
    expectCode(
      () =>
        a.e.parseMessage({ ...m, header: { ...m.header, n: LIMITS.MAX_INT } }),
      "E2EE_INVALID_INPUT",
    );
  });
});

describe("review round 2 regressions", () => {
  it("candidate state with an unknown sid → INVALID_STATE before routing", () => {
    const [a, b] = two();
    const m = send(a, "x");
    const cand = accept(b, a, m);
    const unknown = { ...m, header: { ...m.header, sid: "AAAAAAAAAAA" } };
    delete (unknown as { handshake?: unknown }).handshake;
    expectCode(
      () =>
        b.e.decrypt({ state: cand, message: unknown, expectedAd: adFrom(a) }),
      "E2EE_INVALID_STATE",
    );
  });

  it("canonicalJson and onDecrypt never leak raw errors from getters or proxies", () => {
    const [a] = two();
    const throwing = {
      get x() {
        throw new Error("g");
      },
    };
    expectCode(() => a.e.canonicalJson(throwing), "E2EE_INVALID_INPUT");
    expectCode(
      () =>
        a.e.canonicalJson(
          new Proxy(
            {},
            {
              ownKeys: () => {
                throw new Error("o");
              },
            },
          ),
        ),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        a.e.canonicalJson(
          new Proxy(
            {},
            {
              getPrototypeOf: () => {
                throw new Error("p");
              },
            },
          ),
        ),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        a.e.canonicalJson(
          new Proxy([1], {
            has: () => {
              throw new Error("h");
            },
          }),
        ),
      "E2EE_INVALID_INPUT",
    );
    const t = a.e.recordRecoverySignal(null, "evicted-session");
    expectCode(() => a.e.onDecrypt(t, throwing as never), "E2EE_INVALID_INPUT");
  });

  it("expectedAd is read once", () => {
    const [a, b] = two();
    receive(b, a, send(a, "1"));
    const m = send(a, "2");
    let reads = 0;
    const counting = new Proxy(adFrom(a), {
      get: (o, k) => {
        if (k === "conversationId") reads++;
        return o[k as keyof typeof o];
      },
    });
    b.e.decrypt({ state: b.state!, message: m, expectedAd: counting });
    expect(reads).toBe(1);
  });

  it("sightings later than now are ignored by recoveryDecision", () => {
    const clock = testClock();
    const a = party("alice", clock);
    let t = a.e.recordRecoverySignal(null, "handshake-required");
    clock.advance(60_000);
    t = a.e.recordRecoverySignal(t, "handshake-required");
    clock.advance(-11 * 60_000); // clock stepped back
    t = a.e.recordRecoverySignal(t, "handshake-required");
    expect(a.e.recoveryDecision(t).due).toBe(false);
  });
});
