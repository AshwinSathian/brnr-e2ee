// Suite negotiation, mixed v1/v2 peers, the v1 → v2 upgrade inside a state, and the suite v2 shapes
// and invariants (SPEC §4.7, §5.4, §6.1-§6.4, §7.4, §7.6, §9.1-§9.2).
import { describe, expect, it } from "vitest";
import type {
  AssociatedData,
  MessageV2,
  SessionState,
} from "../../src/index.js";
import { createE2ee, SUITES } from "../../src/index.js";
import { sidOf } from "../../src/x3dh.js";
import { expectCode } from "../helpers.js";
import {
  adFrom,
  adOf,
  bundleOf,
  CONV,
  initiate,
  party,
  receive,
  send,
  V1,
  V2,
  type Party,
} from "../parties.js";

const json = (s: SessionState | null) =>
  JSON.parse(JSON.stringify(s)) as Record<string, unknown> & {
    suite: string;
    activeSid: string;
    sessions: Array<
      Record<string, unknown> & { founding: Record<string, unknown> }
    >;
  };
const suiteOf = (p: Party) => p.e.inspectSession(p.state!).suite;

/** Alice and Bob with one round trip on a fresh session. */
function pair(aSuites = [...SUITES], bSuites = [...SUITES]) {
  const a = party("alice", undefined, aSuites);
  const b = party("bob", undefined, bSuites);
  initiate(a, b);
  expect(receive(b, a, send(a, "hello"))).toBe("hello");
  expect(receive(a, b, send(b, "reply"))).toBe("reply");
  return { a, b };
}

describe("suite negotiation", () => {
  it("SUITES is [v2, v1] and new SPKs offer both", () => {
    expect(SUITES).toEqual([V2, V1]);
    const e = createE2ee();
    const d = e.generateDeviceIdentity("d");
    expect(e.generateSignedPrekey(d, 1).suites).toEqual([V2, V1]);
  });

  it("upgraded peers negotiate v2; inspectSession reports the suite", () => {
    const { a, b } = pair();
    expect(suiteOf(a)).toBe(V2);
    expect(suiteOf(b)).toBe(V2);
    const st = json(a.state);
    expect(st["selfSignPk"]).toBe(a.device.signPk);
    expect(st["peerSignPk"]).toBe(b.device.signPk);
  });

  it("a peer whose SPK offers v1 only gets v1, and its states carry no sign keys", () => {
    const { a, b } = pair([...SUITES], [V1]);
    expect(suiteOf(a)).toBe(V1);
    expect(suiteOf(b)).toBe(V1);
    for (const p of [a, b]) {
      const st = json(p.state);
      expect(st["selfSignPk"]).toBeUndefined();
      expect(st["peerSignPk"]).toBeUndefined();
    }
  });

  it("an explicit suite: v1 still works against a [v2, v1] SPK (a 1.0 initiator)", () => {
    const a = party("alice");
    const b = party("bob");
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b),
      suite: V1,
    });
    const m = send(a, "old peer");
    expect(m.suite).toBe(V1);
    expect(m.handshake?.initiatorSignPk).toBeUndefined();
    expect(receive(b, a, m)).toBe("old peer");
    expect(suiteOf(b)).toBe(V1);
  });

  it("v2 messages carry the identity fields and the recipient", () => {
    const a = party("alice");
    const b = party("bob");
    initiate(a, b);
    const m = send(a, "x");
    expect(m.handshake).toMatchObject({
      initiatorSignPk: a.device.signPk,
      responderDeviceId: b.device.deviceId,
      responderSignPk: b.device.signPk,
    });
    expect(m.ad).toEqual(adOf(V2, a.device.deviceId, b.device.deviceId));
  });
});

describe("the v1 → v2 upgrade inside one state", () => {
  function upgraded() {
    const { a, b } = pair([V1], [V1]);
    // Bob upgrades: a new SPK offering [v2, v1].
    const spk = b.e.generateSignedPrekey(b.device, 2);
    b.spks.set(2, spk);
    const inflight = send(a, "v1 in flight");
    initiate(a, b);
    expect(suiteOf(a)).toBe(V2);
    return { a, b, inflight };
  }

  it("the initiator's state moves to v2 and gains the sign keys", () => {
    const { a, b } = upgraded();
    const st = json(a.state);
    expect(st.sessions.map((x) => "initiatorSignPk" in x.founding)).toEqual([
      false,
      true,
    ]);
    expect(st["peerSignPk"]).toBe(b.device.signPk);
  });

  it("the responder moves to v2 on the founding decrypt; a late v1 message is then refused", () => {
    const { a, b, inflight } = upgraded();
    expect(receive(b, a, send(a, "first v2"))).toBe("first v2");
    expect(suiteOf(b)).toBe(V2);
    const v2Sid = b.e.inspectSession(b.state!).activeSid;
    const before = b.e.serializeState(b.state!);
    expectCode(() => receive(b, a, inflight), "E2EE_UNSUPPORTED_SUITE");
    expect(b.e.serializeState(b.state!)).toBe(before);
    expect(b.e.inspectSession(b.state!).activeSid).toBe(v2Sid);
    const reply = send(b, "reply");
    expect(reply.suite).toBe(V2);
    expect(receive(a, b, reply)).toBe("reply");
    expect(receive(b, a, send(a, "again"))).toBe("again");
    // Confirmed decrypts on the active v2 session retire the v1 session on both sides.
    for (const p of [a, b]) {
      const info = p.e.inspectSession(p.state!);
      expect(info.sessions.filter((x) => x.retiredAt === null)).toHaveLength(1);
    }
  });

  it("before the founding arrives, the responder's v1 replies are refused by the upgraded initiator", () => {
    const { a, b } = upgraded();
    const v2Sid = a.e.inspectSession(a.state!).activeSid;
    expectCode(
      () => receive(a, b, send(b, "still v1")),
      "E2EE_UNSUPPORTED_SUITE",
    );
    expect(a.e.inspectSession(a.state!).activeSid).toBe(v2Sid);
    expect(suiteOf(a)).toBe(V2);
    const m = send(a, "v2 with handshake");
    expect(m.handshake?.initiatorSignPk).toBe(a.device.signPk);
    expect(receive(b, a, m)).toBe("v2 with handshake");
  });

  it("a v1 state with sign keys stays valid, and a fresh v1 re-initiation keeps v1", () => {
    const { a, b } = pair([V1], [V1]);
    initiate(a, b);
    expect(suiteOf(a)).toBe(V1);
    const st = json(a.state);
    st["selfSignPk"] = a.device.signPk;
    st["peerSignPk"] = b.device.signPk;
    expect(() => a.e.parseState(JSON.stringify(st))).not.toThrow();
  });
});

describe("suite v2 associated data", () => {
  it("encrypt requires recipientDeviceId = the peer, and the v2 shape", () => {
    const { a, b } = pair();
    const good = adFrom(a, b);
    const { recipientDeviceId: _r, ...v1Shape } = good as AssociatedData & {
      recipientDeviceId: string;
    };
    for (const ad of [
      { ...good, recipientDeviceId: "someone-else" },
      { ...v1Shape, suite: V1 },
      v1Shape,
    ])
      expectCode(
        () =>
          a.e.encrypt({
            state: a.state!,
            plaintext: new Uint8Array(1),
            ad: ad as AssociatedData,
          }),
        "E2EE_AD_MISMATCH",
      );
  });

  it("decrypt requires recipientDeviceId = this device", () => {
    const { a, b } = pair();
    const m = send(a, "x");
    expectCode(
      () =>
        b.e.decrypt({
          state: b.state!,
          message: {
            ...m,
            ad: { ...m.ad, recipientDeviceId: "other" } as MessageV2["ad"],
          },
          expectedAd: {
            ...adOf(V2, a.device.deviceId, "other"),
          },
        }),
      "E2EE_AD_MISMATCH",
    );
    expect(receive(b, a, m)).toBe("x");
  });

  it("a v2 message relabelled as v1 on the same sid is refused as a suite mismatch", () => {
    const { a, b } = pair();
    const m = send(a, "x");
    const { recipientDeviceId: _r, ...rest } = m.ad as MessageV2["ad"] & {
      recipientDeviceId: string;
    };
    const relabelled = {
      ...m,
      suite: V1,
      ad: { ...rest, suite: V1 },
    } as MessageV2;
    expectCode(
      () =>
        b.e.decrypt({
          state: b.state!,
          message: relabelled,
          expectedAd: relabelled.ad,
        }),
      "E2EE_UNSUPPORTED_SUITE",
    );
  });

  it("a v1 message relabelled as v2 on a v1 session is refused as a suite mismatch", () => {
    const { a, b } = pair([V1], [V1]);
    const m = send(a, "x");
    const ad = adOf(V2, a.device.deviceId, b.device.deviceId);
    const relabelled = { ...m, suite: V2, ad } as MessageV2;
    expectCode(
      () =>
        b.e.decrypt({ state: b.state!, message: relabelled, expectedAd: ad }),
      "E2EE_UNSUPPORTED_SUITE",
    );
  });
});

describe("suite shapes (SPEC §4.7)", () => {
  const e = createE2ee();

  it("a message is checked against its suite's shape", () => {
    const { a, b } = pair();
    const m = send(a, "x");
    initiate(a, b);
    const f = send(a, "founding");
    const { recipientDeviceId: _r, ...v1Ad } = m.ad as MessageV2["ad"] & {
      recipientDeviceId: string;
    };
    expectCode(() => e.parseMessage({ ...m, ad: v1Ad }), "E2EE_INVALID_INPUT");
    expectCode(
      () => e.parseMessage({ ...m, ad: { ...m.ad, suite: V1 } }),
      "E2EE_INVALID_INPUT",
    );
    const { initiatorSignPk: _s, ...v1Hs } = f.handshake!;
    expectCode(
      () => e.parseMessage({ ...f, handshake: v1Hs }),
      "E2EE_INVALID_INPUT",
    );
    const v1 = pair([V1], [V1]);
    const n = send(v1.a, "y");
    expectCode(
      () =>
        e.parseMessage({
          ...n,
          ad: { ...n.ad, recipientDeviceId: "bob-dev" },
        }),
      "E2EE_INVALID_INPUT",
    );
    expect(e.parseMessage(m)).toEqual(m);
    expect(e.parseMessage(f)).toEqual(f);
  });

  it("handshakeDigest takes either shape and rejects a partial v2 handshake", () => {
    const a = party("alice");
    const b = party("bob");
    initiate(a, b);
    const h = send(a, "x").handshake!;
    expect(e.handshakeDigest(h)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const { responderSignPk: _x, ...partial } = h;
    expectCode(() => e.handshakeDigest(partial), "E2EE_INVALID_INPUT");
    const { initiatorSignPk: _y, responderDeviceId: _z, ...v1 } = partial;
    expect(e.handshakeDigest(v1)).not.toBe(e.handshakeDigest(h));
  });
});

describe("acceptSession pins (SPEC §6.4)", () => {
  const founding = () => {
    const a = party("alice");
    const b = party("bob");
    initiate(a, b);
    return { a, b, m: send(a, "x") };
  };
  const go = (b: Party, m: MessageV2, over: Record<string, unknown> = {}) =>
    b.e.acceptSession({
      conversationId: CONV,
      self: b.device,
      expectedPeerBoxPk: "",
      message: m,
      lookupSpk: (id: number) => b.spks.get(id),
      lookupOtp: (id: number) => b.otps.get(id),
      seenHandshake: () => false,
      ...over,
    } as never);

  it("expectedPeerSignPk must be base64url of 32 bytes when present, in either suite", () => {
    const { a, b, m } = founding();
    for (const bad of ["AAAA", 7, null])
      expectCode(
        () =>
          go(b, m, {
            expectedPeerBoxPk: a.device.boxPk,
            expectedPeerSignPk: bad,
          }),
        "E2EE_INVALID_INPUT",
      );
  });

  it("a handshake for another responder device or signing key is refused", () => {
    const { a, b, m } = founding();
    const pins = {
      expectedPeerBoxPk: a.device.boxPk,
      expectedPeerSignPk: a.device.signPk,
    };
    const other = party("carol");
    // Bob's box key and SPK, but self names another deviceId or signing key.
    for (const self of [
      { ...b.device, deviceId: "carol-dev" },
      { ...b.device, signPk: other.device.signPk, signSk: other.device.signSk },
    ])
      expectCode(() => go(b, m, { ...pins, self }), "E2EE_IDENTITY_MISMATCH");
    expect(() => go(b, m, pins)).not.toThrow();
  });

  it("existing pins the self signing key too", () => {
    const a = party("alice");
    const b = party("bob");
    initiate(a, b);
    receive(b, a, send(a, "one"));
    const other = party("carol");
    // Bob's deviceId and box keys under another signing key, with an SPK it signed.
    const self = {
      ...b.device,
      signPk: other.device.signPk,
      signSk: other.device.signSk,
    };
    const spk = b.e.generateSignedPrekey(self, 9);
    const fresh = party("alice");
    fresh.state = fresh.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: b.e.buildDeviceBundle({ device: self, spk }),
    });
    const m = send(fresh, "aimed at the other signing key");
    // Step 3 passes (the handshake names `self`); step 5 finds Bob's stored signing key.
    expectCode(
      () =>
        go(b, m, {
          expectedPeerBoxPk: a.device.boxPk,
          expectedPeerSignPk: a.device.signPk,
          existing: b.state,
          self,
          lookupSpk: () => spk,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
    expect(() =>
      go(b, m, {
        expectedPeerBoxPk: a.device.boxPk,
        expectedPeerSignPk: a.device.signPk,
        self,
        lookupSpk: () => spk,
      }),
    ).not.toThrow();
    expectCode(
      () =>
        b.e.initiateSession({
          conversationId: CONV,
          self,
          peerBundle: bundleOf(a),
          existing: b.state!,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
  });
});

describe("suite v2 state invariants (SPEC §9.2)", () => {
  /** Edits the state, then re-derives every sid from its founding so only the edit is invalid. */
  const bad = (p: Party, edit: (st: ReturnType<typeof json>) => void) => {
    const st = json(p.state);
    edit(st);
    for (const x of st.sessions) {
      const sid = sidOf(x.founding as never);
      if (st.activeSid === x["sid"]) st.activeSid = sid;
      x["sid"] = sid;
    }
    expect(st["skipped"]).toEqual([]);
    expectCode(() => p.e.parseState(JSON.stringify(st)), "E2EE_INVALID_STATE");
  };

  it("sign keys: both or none, and present with a v2 session", () => {
    const { a } = pair();
    bad(a, (st) => delete st["selfSignPk"]);
    bad(a, (st) => delete st["peerSignPk"]);
    bad(a, (st) => {
      delete st["selfSignPk"];
      delete st["peerSignPk"];
    });
  });

  it("a v1 state may hold both sign keys but not one", () => {
    const { a, b } = pair([V1], [V1]);
    bad(a, (st) => (st["selfSignPk"] = a.device.signPk));
    bad(a, (st) => (st["peerSignPk"] = b.device.signPk));
  });

  it("the founding identity agrees with the state, for both roles", () => {
    const { a, b } = pair();
    const x = party("carol").device.signPk;
    for (const p of [a, b]) {
      bad(p, (st) => (st.sessions[0]!.founding["initiatorSignPk"] = x));
      bad(p, (st) => (st.sessions[0]!.founding["responderSignPk"] = x));
      bad(p, (st) => (st.sessions[0]!.founding["responderDeviceId"] = "zz"));
    }
  });

  it("the state's suite is its active session's", () => {
    const { a } = pair();
    bad(a, (st) => (st.suite = V1));
    bad(a, (st) => (st.suite = "x25519-xchacha20poly1305-sha256-v9"));
    const v1 = pair([V1], [V1]);
    bad(v1.a, (st) => (st.suite = V2));
  });
});
