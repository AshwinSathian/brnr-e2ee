// SPEC §12. Test values from libsignal rust/protocol/src/fingerprint.rs tests (commit
// b2a5c30f3245c1bcad04b27b1e752a38321c793d, fetched 2026-10-22). Values only; no code copied.
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../../src/codec.js";
import { digits30, fingerprintChain } from "../../src/testing.js";
import { expectCode, hex, makeE2ee, toHex } from "../helpers.js";

const ALICE = hex(
  "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868",
);
const BOB = hex(
  "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b",
);
const DISPLAYABLE =
  "300354477692869396892869876765458257569162576843440918079131";
const ALICE_FP =
  "1e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df";
const BOB_FP =
  "d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d";

describe("fingerprint core (D11)", () => {
  it("reproduces libsignal's published values", () => {
    const a = fingerprintChain(ALICE, "+14152222222").slice(0, 32);
    const b = fingerprintChain(BOB, "+14153333333").slice(0, 32);
    expect(toHex(a)).toBe(ALICE_FP);
    expect(toHex(b)).toBe(BOB_FP);
    const [x, y] = [digits30(a), digits30(b)];
    expect(x < y ? x + y : y + x).toBe(DISPLAYABLE);
  });
});

describe("computeSafetyNumber and verifySafetyNumberPayload", () => {
  const { e } = makeE2ee("fp");
  const alice = {
    accountSignPk: e.generateAccountIdentity().signPk,
    stableId: "alice",
  };
  const bob = {
    accountSignPk: e.generateAccountIdentity().signPk,
    stableId: "bob",
  };

  it("both sides agree on the digits; QR payloads verify crosswise only", () => {
    const sa = e.computeSafetyNumber({ local: alice, remote: bob });
    const sb = e.computeSafetyNumber({ local: bob, remote: alice });
    expect(sa.digits).toBe(sb.digits);
    expect(sa.digits).toMatch(/^\d{60}$/);
    expect(sa.groups).toHaveLength(12);
    expect(sa.groups.join("")).toBe(sa.digits);
    expect(sa.qrPayload).toHaveLength(66);
    expect(e.verifySafetyNumberPayload(sa, sb.qrPayload)).toBe(true);
    expect(e.verifySafetyNumberPayload(sb, sa.qrPayload)).toBe(true);
    expect(e.verifySafetyNumberPayload(sa, sa.qrPayload)).toBe(false);
    const wrongVersion = sb.qrPayload.slice();
    wrongVersion[1] = 2;
    expect(e.verifySafetyNumberPayload(sa, wrongVersion)).toBe(false);
    const flipped = sb.qrPayload.slice();
    flipped[40]! ^= 1;
    expect(e.verifySafetyNumberPayload(sa, flipped)).toBe(false);
    const half = sb.qrPayload.slice();
    half[3]! ^= 1;
    expect(e.verifySafetyNumberPayload(sa, half)).toBe(false);
    expect(e.verifySafetyNumberPayload(sa, sb.qrPayload.slice(0, 65))).toBe(
      false,
    );
    expect(e.verifySafetyNumberPayload(null as never, sb.qrPayload)).toBe(
      false,
    );
    expect(e.verifySafetyNumberPayload(sa, [1, 2] as never)).toBe(false);
    const mitm = e.computeSafetyNumber({
      local: alice,
      remote: { ...bob, stableId: "eve" },
    });
    expect(mitm.digits).not.toBe(sa.digits);
  });

  it("validates inputs", () => {
    expectCode(
      () =>
        e.computeSafetyNumber({
          local: { ...alice, accountSignPk: "x" },
          remote: bob,
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.computeSafetyNumber({
          local: alice,
          remote: { ...bob, stableId: "" },
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.computeSafetyNumber({
          local: alice,
          remote: { ...bob, stableId: "\ud800" },
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.computeSafetyNumber({
          local: {
            ...alice,
            accountSignPk: b64uEncode(Uint8Array.of(1, ...new Uint8Array(31))),
          },
          remote: bob,
        }),
      "E2EE_INVALID_KEY",
    );
    expectCode(
      () => e.computeSafetyNumber(null as never),
      "E2EE_INVALID_INPUT",
    );
  });
});
