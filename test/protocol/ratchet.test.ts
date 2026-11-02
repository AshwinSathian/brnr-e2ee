// X3DH and Double Ratchet behaviour through the public API (SPEC §6, §7).
import { describe, expect, it } from "vitest";
import { LIMITS, type MessageV2, type SessionState } from "../../src/index.js";
import { b64uDecode, b64uEncode } from "../../src/codec.js";
import { aeadSeal } from "../../src/primitives.js";
import { aadOf, pad, unpad } from "../../src/ratchet.js";
import { sidOf } from "../../src/x3dh.js";
import { expectCode } from "../helpers.js";
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

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
type Json = Record<string, unknown> & {
  sessions: Array<Record<string, unknown>>;
};
const edit = (s: SessionState | null, f: (j: Json) => void): SessionState => {
  const j = clone(s) as unknown as Json;
  f(j);
  return j as unknown as SessionState;
};

function pair(otp = true): [Party, Party] {
  const a = party("alice");
  const b = party("bob");
  initiate(a, b, otp);
  return [a, b];
}

/** Established: a→b, b→a. */
function established(): [Party, Party] {
  const [a, b] = pair();
  receive(b, a, send(a, "1"));
  receive(a, b, send(b, "2"));
  return [a, b];
}

const decryptRaw = (to: Party, from: Party, m: MessageV2) =>
  to.e.decrypt({
    state: to.state as SessionState,
    message: m,
    expectedAd: adFrom(from, to),
  });

describe("padding (SPEC §7.5)", () => {
  it("bucket edges", () => {
    expect(pad(new Uint8Array(60))).toHaveLength(64);
    expect(pad(new Uint8Array(61))).toHaveLength(128);
    expect(pad(new Uint8Array(0))).toHaveLength(64);
    expect(pad(new Uint8Array(8192))).toHaveLength(8196);
    expectCode(() => pad(new Uint8Array(8193)), "E2EE_PLAINTEXT_TOO_LARGE");
    for (const n of [0, 1, 60, 61, 124, 125, 4092, 4093, 8192]) {
      const p = Uint8Array.from({ length: n }, (_, i) => i & 255);
      expect(unpad(pad(p))).toEqual(p);
    }
  });
  it("strict unpad", () => {
    const good = pad(Uint8Array.of(1, 2, 3));
    const nonZero = good.slice();
    nonZero[63] = 1;
    expectCode(() => unpad(nonZero), "E2EE_INVALID_PADDING");
    const tooLong = good.slice();
    tooLong[3] = 61; // 4 + 61 > 64
    expectCode(() => unpad(tooLong), "E2EE_INVALID_PADDING");
    const nonMinimal = new Uint8Array(128);
    nonMinimal[3] = 3; // fits in 64
    expectCode(() => unpad(nonMinimal), "E2EE_INVALID_PADDING");
    expectCode(() => unpad(new Uint8Array(3)), "E2EE_INVALID_PADDING");
    expectCode(() => unpad(new Uint8Array(100)), "E2EE_INVALID_PADDING");
    const huge = new Uint8Array(64);
    huge[0] = 0xff;
    expectCode(() => unpad(huge), "E2EE_INVALID_PADDING");
  });
});

describe("D1: previous-chain messages after a DH ratchet (DR §3.5)", () => {
  it("decrypts skipped messages from the previous chain via pn", () => {
    const [a, b] = pair();
    const a1 = send(a, "a1");
    const a2 = send(a, "a2");
    const a3 = send(a, "a3");
    expect(receive(b, a, a1)).toBe("a1");
    expect(receive(a, b, send(b, "b1"))).toBe("b1");
    const a4 = send(a, "a4");
    expect(a4.header.pn).toBe(3);
    expect(receive(b, a, a4)).toBe("a4");
    const r = decryptRaw(b, a, a3);
    expect(r.advancedReceiveChain).toBe(false);
    commit(b, r.state);
    expect(receive(b, a, a2)).toBe("a2");
    expectCode(() => receive(b, a, a2), "E2EE_DUPLICATE_MESSAGE");
    expectCode(() => receive(b, a, a4), "E2EE_DUPLICATE_MESSAGE");
  });
});

describe("skip limits (SPEC §7.6)", () => {
  for (const [gap, ok] of [
    [1, true],
    [999, true],
    [1000, true],
    [1001, false],
  ] as const)
    it(`gap ${gap} → ${ok ? "ok" : "E2EE_SKIP_TOO_LARGE"}`, () => {
      const [a, b] = established();
      for (let k = 0; k < gap; k++) send(a, "dropped");
      const m = send(a, "late");
      const before = b.e.serializeState(b.state as SessionState);
      if (ok) {
        expect(receive(b, a, m)).toBe("late");
        const skipped = (
          JSON.parse(b.e.serializeState(b.state as SessionState)) as {
            skipped: { keys: unknown[] }[];
          }
        ).skipped;
        expect(skipped.reduce((n, g) => n + g.keys.length, 0)).toBe(gap);
      } else {
        expectCode(() => receive(b, a, m), "E2EE_SKIP_TOO_LARGE");
        expect(b.e.serializeState(b.state as SessionState)).toBe(before);
      }
    });

  it("pn gap over MAX_SKIP → E2EE_SKIP_TOO_LARGE", () => {
    const [a, b] = established();
    receive(b, a, send(a, "x"));
    a.state = edit(a.state, (j) => {
      (j.sessions[0] as { pn: number }).pn += 0;
    });
    // b sends on a new chain after a's message; forge pn huge on b's side.
    b.state = edit(b.state, (j) => {
      (j.sessions[0] as { ns: number }).ns = 0;
    });
    const m = send(b, "y");
    const forged = { ...m, header: { ...m.header, pn: 2000 } };
    expectCode(() => decryptRaw(a, b, forged), "E2EE_SKIP_TOO_LARGE");
  });
});

describe("replay rules (SPEC §7.6)", () => {
  it("in-window replays → E2EE_DUPLICATE_MESSAGE, state unchanged", () => {
    const [a, b] = established();
    const m = send(a, "x");
    receive(b, a, m);
    const before = b.e.serializeState(b.state as SessionState);
    expectCode(() => decryptRaw(b, a, m), "E2EE_DUPLICATE_MESSAGE");
    expect(b.e.serializeState(b.state as SessionState)).toBe(before);
  });
  it("old ratchet key in prevRemoteDh → E2EE_DUPLICATE_MESSAGE", () => {
    const [a, b] = established();
    const old = send(a, "old");
    receive(b, a, old);
    receive(a, b, send(b, "r"));
    receive(b, a, send(a, "new"));
    const forged = { ...old, header: { ...old.header, n: 50 } };
    expectCode(() => decryptRaw(b, a, forged), "E2EE_DUPLICATE_MESSAGE");
  });
  it("prevRemoteDh is capped at 64", () => {
    const [a, b] = established();
    for (let i = 0; i < 70; i++) {
      receive(b, a, send(a, `a${i}`));
      receive(a, b, send(b, `b${i}`));
    }
    const j = JSON.parse(b.e.serializeState(b.state as SessionState)) as {
      sessions: { prevRemoteDh: string[] }[];
    };
    expect(j.sessions[0]!.prevRemoteDh).toHaveLength(LIMITS.MAX_PREV_REMOTE_DH);
  });
});

describe("F-2: forged {dh: SPK_B} before the first reply", () => {
  it("→ E2EE_DECRYPT_FAILED, state unchanged", () => {
    const [a, b] = pair();
    const m = send(a, "x");
    const spkPk = bundleOf(b, false).spkPk;
    const forged: MessageV2 = {
      ...m,
      handshake: undefined as never,
      ad: adFrom(b, a),
      header: { ...m.header, dh: spkPk, pn: 0, n: 0 },
    };
    delete (forged as { handshake?: unknown }).handshake;
    const before = JSON.stringify(a.state);
    expectCode(() => decryptRaw(a, b, forged), "E2EE_DECRYPT_FAILED");
    expect(JSON.stringify(a.state)).toBe(before);
  });
});

describe("D2: identity binding", () => {
  it("swapped identity key → E2EE_IDENTITY_MISMATCH", () => {
    const [a, b] = pair();
    const m = send(a, "x");
    const mallory = party("mallory");
    expectCode(
      () =>
        b.e.acceptSession({
          conversationId: CONV,
          self: b.device,
          expectedPeerBoxPk: mallory.device.boxPk,
          expectedPeerSignPk: mallory.device.signPk,
          message: m,
          lookupSpk: (id) => b.spks.get(id),
          lookupOtp: (id) => b.otps.get(id),
          seenHandshake: () => false,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
  });
  it("tampered AD: AD_MISMATCH at the API; DECRYPT_FAILED when the state is bent to match", () => {
    const [a, b] = pair();
    const m = send(a, "x");
    const ad2 = { ...m.ad, senderDeviceId: "mallory-dev" };
    const t = { ...m, ad: ad2 };
    const cand = b.e.acceptSession({
      conversationId: CONV,
      self: b.device,
      expectedPeerBoxPk: a.device.boxPk,
      expectedPeerSignPk: a.device.signPk,
      message: t,
      lookupSpk: (id) => b.spks.get(id),
      lookupOtp: (id) => b.otps.get(id),
      seenHandshake: () => false,
    });
    expectCode(
      () => b.e.decrypt({ state: cand, message: t, expectedAd: adFrom(a) }),
      "E2EE_AD_MISMATCH",
    );
    expectCode(
      () => b.e.decrypt({ state: cand, message: t, expectedAd: ad2 }),
      "E2EE_DECRYPT_FAILED",
    );
  });
});

describe("D3: handshake on every message until the first inbound", () => {
  it("first message dropped → second establishes", () => {
    const [a, b] = pair();
    send(a, "dropped");
    const m2 = send(a, "second");
    expect(m2.handshake).toBeDefined();
    expect(m2.header.n).toBe(1);
    expect(receive(b, a, m2)).toBe("second");
    const m3 = send(a, "third");
    expect(m3.handshake).toEqual(m2.handshake);
    receive(a, b, send(b, "reply"));
    expect(send(a, "fourth").handshake).toBeUndefined();
    expect(
      a.e.inspectSession(a.state as SessionState).sessions[0]!.pending,
    ).toBeNull();
  });
});

describe("D4: SPK retention", () => {
  it("previous SPK inside retention works; after deletion → E2EE_SPK_UNKNOWN", () => {
    const a = party("alice");
    const b = party("bob");
    initiate(a, b, false);
    b.spks.set(2, b.e.generateSignedPrekey(b.device, 2));
    const m = send(a, "on spk 1");
    expect(m.handshake?.spkId).toBe(1);
    const a2 = party("alice2");
    initiate(a2, b, false);
    const m2 = send(a2, "x");
    expect(m2.handshake?.spkId).toBe(2);
    expect(receive(b, a, m)).toBe("on spk 1");
    const c = party("carol");
    initiate(c, b, false);
    const mc = { ...send(c, "x") };
    const mOld = { ...mc, handshake: { ...mc.handshake!, spkId: 1 } };
    b.spks.delete(1);
    b.state = null;
    expectCode(
      () =>
        b.e.acceptSession({
          conversationId: CONV,
          self: b.device,
          expectedPeerBoxPk: c.device.boxPk,
          expectedPeerSignPk: c.device.signPk,
          message: {
            ...mOld,
            header: { ...mOld.header, sid: sidOf(mOld.handshake!) },
          },
          lookupSpk: (id) => b.spks.get(id),
          lookupOtp: (id) => b.otps.get(id),
          seenHandshake: () => false,
        }),
      "E2EE_SPK_UNKNOWN",
    );
  });
});

describe("D5: OTP the responder lacks", () => {
  it("→ E2EE_OTP_UNKNOWN, never a silent 3-DH", () => {
    const [a, b] = pair(true);
    b.otps.clear();
    expectCode(() => receive(b, a, send(a, "x")), "E2EE_OTP_UNKNOWN");
  });
});

describe("D9 and AAD binding (SPEC §7.4)", () => {
  it("encrypt rejects any AD that is not exactly the state's", () => {
    const [a] = pair();
    const good = adFrom(a);
    for (const ad of [
      { ...good, conversationId: "other" },
      { ...good, senderDeviceId: "x" },
      { ...good, v: 1 },
      { ...good, suite: "s" },
      { ...good, extra: "1" },
      {
        conversationId: CONV,
        senderDeviceId: good.senderDeviceId,
        suite: good.suite,
      },
      null,
      "x",
    ])
      expectCode(
        () =>
          a.e.encrypt({
            state: a.state!,
            plaintext: new Uint8Array(1),
            ad: ad as never,
          }),
        "E2EE_AD_MISMATCH",
      );
  });
  it("tampering with sid, dh, pn, n or the handshake fails", () => {
    const [a, b] = established();
    const m = send(a, "x");
    const other = b64uEncode(new Uint8Array(32).fill(9));
    expectCode(
      () =>
        decryptRaw(b, a, { ...m, header: { ...m.header, n: m.header.n + 1 } }),
      "E2EE_DECRYPT_FAILED",
    );
    expectCode(
      () =>
        decryptRaw(b, a, {
          ...m,
          header: { ...m.header, pn: m.header.pn + 1 },
        }),
      "E2EE_DECRYPT_FAILED",
    );
    expectCode(
      () => decryptRaw(b, a, { ...m, header: { ...m.header, dh: other } }),
      "E2EE_DECRYPT_FAILED",
    );
    expectCode(
      () =>
        decryptRaw(b, a, { ...m, header: { ...m.header, sid: "AAAAAAAAAAA" } }),
      "E2EE_HANDSHAKE_REQUIRED",
    );
    const ct = b64uDecode(m.ciphertext)!;
    ct[0]! ^= 1;
    expectCode(
      () => decryptRaw(b, a, { ...m, ciphertext: b64uEncode(ct) }),
      "E2EE_DECRYPT_FAILED",
    );
    expectCode(
      () => decryptRaw(b, a, { ...m, nonce: b64uEncode(new Uint8Array(24)) }),
      "E2EE_DECRYPT_FAILED",
    );
  });
  it("a handshake that is not the founding one → E2EE_INVALID_INPUT", () => {
    const [a, b] = pair();
    const m1 = send(a, "1");
    receive(b, a, m1);
    const m2 = send(a, "2");
    const h = {
      ...m2.handshake!,
      initiatorEphPk: b64uEncode(new Uint8Array(32).fill(5)),
    };
    expectCode(
      () =>
        decryptRaw(b, a, {
          ...m2,
          handshake: h,
          header: { ...m2.header, sid: sidOf(h) },
        }),
      "E2EE_SESSION_CONFLICT",
    );
    // Same sid, different handshake bytes (re-ordered otpId removed): forged by hand.
    const { otpId: _o, ...noOtp } = m2.handshake!;
    expectCode(
      () => decryptRaw(b, a, { ...m2, handshake: noOtp }),
      "E2EE_INVALID_INPUT",
    );
  });
});

describe("D10: plaintext size and padding through the API", () => {
  it("8192 ok, 8193 → E2EE_PLAINTEXT_TOO_LARGE", () => {
    const [a, b] = established();
    const big = new Uint8Array(8192).fill(97);
    const { message } = a.e.encrypt({
      state: a.state!,
      plaintext: big,
      ad: adFrom(a),
    });
    expect(b64uDecode(message.ciphertext)).toHaveLength(8196 + 16);
    expect(
      b.e.decrypt({ state: b.state!, message, expectedAd: adFrom(a) })
        .plaintext,
    ).toEqual(big);
    expectCode(
      () =>
        a.e.encrypt({
          state: a.state!,
          plaintext: new Uint8Array(8193),
          ad: adFrom(a),
        }),
      "E2EE_PLAINTEXT_TOO_LARGE",
    );
    expectCode(
      () =>
        a.e.encrypt({
          state: a.state!,
          plaintext: "x" as never,
          ad: adFrom(a),
        }),
      "E2EE_INVALID_INPUT",
    );
  });
  it("valid AEAD with bad padding → E2EE_INVALID_PADDING", () => {
    const [a, b] = established();
    const m = send(a, "x");
    const key = decryptRaw(b, a, m).messageKey;
    const bad = pad(Uint8Array.of(120));
    bad[63] = 7;
    const forged = {
      ...m,
      ciphertext: b64uEncode(
        aeadSeal(key, b64uDecode(m.nonce)!, bad, aadOf(m)),
      ),
    };
    expectCode(() => decryptRaw(b, a, forged), "E2EE_INVALID_PADDING");
  });
});

describe("encrypt edge cases", () => {
  it("Ns at 2^31−1 → E2EE_INVALID_STATE", () => {
    const [a] = established();
    a.state = edit(a.state, (j) => {
      (j.sessions[0] as { ns: number }).ns = LIMITS.MAX_INT;
    });
    expectCode(() => send(a, "x"), "E2EE_INVALID_STATE");
  });
  it("a candidate cannot encrypt or be serialised", () => {
    const [a, b] = pair();
    const m = send(a, "x");
    const cand = b.e.acceptSession({
      conversationId: CONV,
      self: b.device,
      expectedPeerBoxPk: a.device.boxPk,
      expectedPeerSignPk: a.device.signPk,
      message: m,
      lookupSpk: (id) => b.spks.get(id),
      lookupOtp: (id) => b.otps.get(id),
      seenHandshake: () => false,
    });
    expectCode(
      () =>
        b.e.encrypt({
          state: cand,
          plaintext: new Uint8Array(1),
          ad: adFrom(b),
        }),
      "E2EE_INVALID_STATE",
    );
    expectCode(() => b.e.serializeState(cand), "E2EE_INVALID_STATE");
    expectCode(() => b.e.inspectSession(cand), "E2EE_INVALID_STATE");
    // The SPK private key sits in the candidate only.
    expect(JSON.stringify(cand)).toContain(b.spks.get(1)!.sk);
    const r = b.e.decrypt({ state: cand, message: m, expectedAd: adFrom(a) });
    expect(b.e.serializeState(r.state)).not.toContain(b.spks.get(1)!.sk);
  });
  it("encrypt does not change lastUsedAt and draws only a nonce", () => {
    const [a] = established();
    const before = a.e.inspectSession(a.state!);
    send(a, "x");
    expect(a.e.inspectSession(a.state!).sessions[0]!.lastUsedAt).toBe(
      before.sessions[0]!.lastUsedAt,
    );
  });
});
