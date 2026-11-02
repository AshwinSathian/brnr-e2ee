// SPEC §16: every row is driven through the public API. Each implementing step adds its drivers;
// the last test asserts that every code in the closed union has at least one.
import { describe, expect, it } from "vitest";
import {
  createE2ee,
  E2EE_ERROR_CODES,
  E2eeError,
  isE2eeError,
  type E2eeErrorCode,
} from "../src/index.js";
import { b64uDecode, b64uEncode } from "../src/codec.js";
import { aeadSeal } from "../src/primitives.js";
import { aadOf, pad } from "../src/ratchet.js";
import { fail } from "../src/errors.js";
import { expectCode, makeE2ee, testClock } from "./helpers.js";
import {
  adFrom,
  bundleOf,
  CONV,
  initiate,
  party,
  receive,
  send,
  V1,
  type Party,
} from "./parties.js";
import type { MessageV2, SessionState } from "../src/index.js";

// Two parties with an established session, plus an unanswered founding message.
const clock = testClock();
const A = party("ea", clock);
const B = party("eb", clock);
initiate(A, B);
const founding = send(A, "f");
const accept = (m: MessageV2, over: Record<string, unknown> = {}) =>
  B.e.acceptSession({
    conversationId: CONV,
    self: B.device,
    expectedPeerBoxPk: A.device.boxPk,
    expectedPeerSignPk: A.device.signPk,
    message: m,
    lookupSpk: (id: number) => B.spks.get(id),
    lookupOtp: (id: number) => B.otps.get(id),
    seenHandshake: () => false,
    ...over,
  } as never);
const cand = accept(founding);
receive(B, A, founding);
receive(A, B, send(B, "r"));
const live = send(A, "live");
const dec = (st: SessionState | null, m: MessageV2, ad = adFrom(A)) =>
  B.e.decrypt({ state: st as SessionState, message: m, expectedAd: ad });
const afterRatchet = ((): [Party, MessageV2] => {
  const C = party("ec", clock);
  initiate(C, B, false);
  return [C, send(C, "c")];
})();

const { e } = makeE2ee("errors");
const dev = e.generateDeviceIdentity("dev-e");
const spk = e.generateSignedPrekey(dev, 1);
const bundle = e.buildDeviceBundle({ device: dev, spk });
const other = e.generateDeviceIdentity("dev-o");
const SMALL = b64uEncode(Uint8Array.of(1, ...new Uint8Array(31)));

type Driver = [string, () => unknown];
const drivers: Partial<Record<E2eeErrorCode, Driver[]>> = {
  E2EE_UNSUPPORTED_VERSION: [
    ["bundle v", () => e.verifyDeviceBundle({ ...bundle, v: 3 } as never)],
  ],
  E2EE_INVALID_INPUT: [
    [
      "wrong key length",
      () => e.verifyDeviceBundle({ ...bundle, deviceBoxPk: "AA" }),
    ],
    [
      "bad generateOneTimePrekeys bounds",
      () => e.generateOneTimePrekeys(1, 1001),
    ],
    [
      "v2 message without expectedPeerSignPk",
      () => accept(founding, { expectedPeerSignPk: undefined }),
    ],
    [
      "suite shape (v1 AD in a v2 message)",
      () => {
        const { recipientDeviceId: _r, ...ad } = live.ad as typeof live.ad & {
          recipientDeviceId: string;
        };
        return B.e.parseMessage({ ...live, ad });
      },
    ],
  ],
  E2EE_INVALID_STATE: [
    ["serializeState on a candidate", () => B.e.serializeState(cand)],
    [
      "callback key mismatch",
      () =>
        accept(founding, {
          lookupSpk: () => ({ ...B.spks.get(1)!, spkId: 7 }),
        }),
    ],
    [
      "key pair fails §4",
      () => e.generateSignedPrekey({ ...dev, boxSk: "x" }, 1),
    ],
  ],
  E2EE_INVALID_KEY: [
    [
      "small-order Ed25519",
      () => e.verifyDeviceBundle({ ...bundle, deviceSignPk: SMALL }),
    ],
  ],
  E2EE_BUNDLE_SIGNATURE_INVALID: [
    [
      "deviceBoxPkSig",
      () => e.verifyDeviceBundle({ ...bundle, deviceBoxPk: other.boxPk }),
    ],
    ["spkSig", () => e.verifyDeviceBundle({ ...bundle, spkId: 2 })],
  ],
  E2EE_UNSUPPORTED_SUITE: [
    [
      "message suite not in SUITES",
      () => B.e.parseMessage({ ...live, suite: "zz" }),
    ],
    [
      "no common suite with a bundle",
      () =>
        A.e.initiateSession({
          conversationId: CONV,
          self: A.device,
          peerBundle: B.e.buildDeviceBundle({
            device: B.device,
            spk: B.e.generateSignedPrekey(B.device, 9, ["zz-v9"] as never),
          }),
        }),
    ],
    [
      "message suite differs from the routed session's",
      () => {
        const { recipientDeviceId: _r, ...ad } = live.ad as typeof live.ad & {
          recipientDeviceId: string;
        };
        const v1Ad = { ...ad, suite: V1 } as MessageV2["ad"];
        return dec(B.state, { ...live, suite: V1, ad: v1Ad }, v1Ad);
      },
    ],
    [
      "initiateSession choosing a suite older than existing.suite",
      () =>
        A.e.initiateSession({
          conversationId: CONV,
          self: A.device,
          peerBundle: B.e.buildDeviceBundle({
            device: B.device,
            spk: B.e.generateSignedPrekey(B.device, 8, [V1]),
          }),
          existing: A.state!,
        }),
    ],
    [
      "message suite not in the SPK's suites",
      () =>
        accept(founding, {
          lookupSpk: () => ({ ...B.spks.get(1)!, suites: ["zz-v9"] }),
        }),
    ],
  ],
  E2EE_DEVICE_LIST_INVALID: [
    [
      "tampered list signature",
      () => {
        const acc = e.generateAccountIdentity();
        const l = e.buildSignedDeviceList({
          account: acc,
          accountId: "a",
          epoch: 1,
          devices: [
            {
              deviceId: "d",
              deviceSignPk: dev.signPk,
              deviceBoxPk: dev.boxPk,
              addedAt: "2026-01-01T00:00:00.000Z",
            },
          ],
        });
        e.verifySignedDeviceList({ ...l, epoch: 2 });
      },
    ],
  ],
  E2EE_IDENTITY_MISMATCH: [
    [
      "pin mismatch on acceptSession",
      () => accept(founding, { expectedPeerBoxPk: other.boxPk }),
    ],
    [
      "signing-key pin mismatch on acceptSession (v2)",
      () => accept(founding, { expectedPeerSignPk: other.signPk }),
    ],
    [
      "v2 handshake made for another device",
      () => accept(founding, { self: { ...B.device, deviceId: "eb-other" } }),
    ],
    [
      "peer key mismatch with existing",
      () =>
        A.e.initiateSession({
          conversationId: CONV,
          self: A.device,
          peerBundle: bundleOf(party("x", clock)),
          existing: A.state!,
        }),
    ],
  ],
  E2EE_SPK_UNKNOWN: [
    [
      "lookupSpk returns nothing",
      () => accept(founding, { lookupSpk: () => undefined }),
    ],
  ],
  E2EE_OTP_UNKNOWN: [
    [
      "lookupOtp returns nothing",
      () => accept(founding, { lookupOtp: () => undefined }),
    ],
  ],
  E2EE_HANDSHAKE_REQUIRED: [
    ["acceptSession without a handshake", () => accept(live)],
    [
      "unknown sid without a handshake",
      () =>
        dec(B.state, {
          ...live,
          header: { ...live.header, sid: "AAAAAAAAAAA" },
        }),
    ],
  ],
  E2EE_SESSION_CONFLICT: [
    [
      "unknown sid with a new handshake",
      () => dec(B.state, { ...afterRatchet[1], ad: adFrom(A) }),
    ],
  ],
  E2EE_SKIP_TOO_LARGE: [
    [
      "skip over MAX_SKIP",
      () =>
        dec(B.state, {
          ...live,
          header: { ...live.header, n: live.header.n + 1001 },
        }),
    ],
  ],
  E2EE_DUPLICATE_MESSAGE: [
    ["replay inside the window", () => dec(B.state, founding)],
    [
      "held sid in acceptSession({ existing })",
      () => accept(founding, { existing: B.state }),
    ],
    [
      "device replay set",
      () => accept(founding, { seenHandshake: () => true }),
    ],
  ],
  E2EE_DECRYPT_FAILED: [
    ["AEAD failure", () => dec(B.state, { ...live, nonce: "A".repeat(32) })],
    [
      "step 5.0",
      () => {
        const s = party("ef", clock);
        initiate(s, B);
        const { handshake: _h, ...m } = send(s, "x");
        const forged = {
          ...m,
          ad: adFrom(B, s),
          header: { ...m.header, dh: bundleOf(B, false).spkPk },
        };
        return s.e.decrypt({
          state: s.state!,
          message: forged,
          expectedAd: adFrom(B, s),
        });
      },
    ],
  ],
  E2EE_INVALID_PADDING: [
    [
      "AEAD ok, unpad fails",
      () => {
        const key = dec(B.state, live).messageKey;
        const bad = pad(Uint8Array.of(1));
        bad[63] = 1;
        const ct = b64uEncode(
          aeadSeal(key, b64uDecode(live.nonce)!, bad, aadOf(live)),
        );
        return dec(B.state, { ...live, ciphertext: ct });
      },
    ],
  ],
  E2EE_PLAINTEXT_TOO_LARGE: [
    [
      "plaintext over 8,192",
      () =>
        A.e.encrypt({
          state: A.state!,
          plaintext: new Uint8Array(8193),
          ad: adFrom(A),
        }),
    ],
  ],
  E2EE_AD_MISMATCH: [
    [
      "expectedAd differs",
      () => dec(B.state, live, { ...adFrom(A), senderDeviceId: "zz" }),
    ],
    [
      "encrypt ad differs",
      () =>
        A.e.encrypt({
          state: A.state!,
          plaintext: new Uint8Array(1),
          ad: adFrom(B),
        }),
    ],
  ],
  E2EE_RNG_UNAVAILABLE: [
    [
      "failed health check",
      () => createE2ee({ rng: (n) => new Uint8Array(n) }),
    ],
  ],
};

describe("E2eeError", () => {
  it("carries a code from the closed union and frozen details", () => {
    const err = new E2eeError("E2EE_DECRYPT_FAILED", undefined, {
      reason: "x",
    });
    expect(err.message).toBe("E2EE_DECRYPT_FAILED");
    expect(err.name).toBe("E2eeError");
    expect(Object.isFrozen(err.details)).toBe(true);
    expect(isE2eeError(err)).toBe(true);
    expect(isE2eeError(new Error("x"))).toBe(false);
    expect(new E2eeError("E2EE_INVALID_INPUT").details).toBeUndefined();
    expectCode(() => fail("E2EE_INVALID_KEY"), "E2EE_INVALID_KEY");
    expect(new Set(E2EE_ERROR_CODES).size).toBe(19);
  });
});

describe("every §16 row is reachable", () => {
  it("every code has a driver", () => {
    for (const code of E2EE_ERROR_CODES)
      expect(drivers[code]?.length ?? 0, code).toBeGreaterThan(0);
  });
  for (const code of E2EE_ERROR_CODES) {
    const list = drivers[code] ?? [];
    for (const [name, fn] of list)
      it(`${code}: ${name}`, () => {
        expectCode(fn, code);
      });
  }
});
