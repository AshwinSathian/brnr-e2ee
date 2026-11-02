// SPEC §13 device-link ceremony.
import { describe, expect, it } from "vitest";
import { SUITES } from "../../src/index.js";
import { b64uDecode, b64uEncode } from "../../src/codec.js";
import { expectCode, makeE2ee } from "../helpers.js";

function ceremony() {
  const { e: oldE } = makeE2ee("old");
  const { e: newE, tape } = makeE2ee("new");
  const account = oldE.generateAccountIdentity();
  const newDev = newE.generateDeviceIdentity("new-dev");
  const requestId = newE.generateLinkRequestId();
  const ephNew = newE.generateLinkEphemeral();
  const T = newE.linkTranscript({
    requestId,
    accountId: "acct",
    newDeviceId: newDev.deviceId,
    newDeviceSignPk: newDev.signPk,
    newDeviceBoxPk: newDev.boxPk,
    suites: [...SUITES],
  });
  const commit = newE.linkCommitment(T, ephNew.pk);
  const ephOld = oldE.generateLinkEphemeral();
  return {
    oldE,
    newE,
    tape,
    account,
    newDev,
    requestId,
    ephNew,
    ephOld,
    T,
    commit,
  };
}

describe("link ceremony (SPEC §13)", () => {
  it("full flow: commit, codes match, seal and open", () => {
    const c = ceremony();
    expect(c.tape.slice(-2).map((t) => [t.purpose, t.bytes.length])).toEqual([
      ["link-request", 16],
      ["seed", 32],
    ]);
    expect(c.requestId).toHaveLength(22);
    // The old device recomputes T from what the new device sent.
    const T2 = c.oldE.linkTranscript({
      requestId: c.requestId,
      accountId: "acct",
      newDeviceId: "new-dev",
      newDeviceSignPk: c.newDev.signPk,
      newDeviceBoxPk: c.newDev.boxPk,
      suites: [...SUITES],
    });
    expect(T2).toBe(c.T);
    expect(c.oldE.verifyLinkCommitment(c.commit, T2, c.ephNew.pk)).toBe(true);
    const codeOld = c.oldE.linkConfirmationCode({
      transcript: T2,
      ephNewPk: c.ephNew.pk,
      ephOldPk: c.ephOld.pk,
    });
    const codeNew = c.newE.linkConfirmationCode({
      transcript: c.T,
      ephNewPk: c.ephNew.pk,
      ephOldPk: c.ephOld.pk,
    });
    expect(codeOld).toMatch(/^\d{6}$/);
    expect(codeOld).toBe(codeNew);
    const sealed = c.oldE.sealAccountKey({
      account: c.account,
      transcript: T2,
      ephSelf: c.ephOld,
      ephPeerPk: c.ephNew.pk,
    });
    expect(
      c.newE.openAccountKey({
        sealed,
        transcript: c.T,
        ephSelf: c.ephNew,
        ephPeerPk: c.ephOld.pk,
      }),
    ).toEqual(c.account);
  });

  it("binding: any transcript or key change breaks commitment, code or seal", () => {
    const c = ceremony();
    const other = c.oldE.generateLinkEphemeral();
    expect(c.oldE.verifyLinkCommitment(c.commit, c.T, other.pk)).toBe(false);
    const T3 = c.oldE.linkTranscript({
      requestId: c.requestId,
      accountId: "acct2",
      newDeviceId: "new-dev",
      newDeviceSignPk: c.newDev.signPk,
      newDeviceBoxPk: c.newDev.boxPk,
      suites: [...SUITES],
    });
    expect(c.oldE.verifyLinkCommitment(c.commit, T3, c.ephNew.pk)).toBe(false);
    expect(
      c.oldE.linkConfirmationCode({
        transcript: T3,
        ephNewPk: c.ephNew.pk,
        ephOldPk: c.ephOld.pk,
      }),
    ).not.toBe(
      c.oldE.linkConfirmationCode({
        transcript: c.T,
        ephNewPk: c.ephNew.pk,
        ephOldPk: c.ephOld.pk,
      }),
    );
    const sealed = c.oldE.sealAccountKey({
      account: c.account,
      transcript: c.T,
      ephSelf: c.ephOld,
      ephPeerPk: c.ephNew.pk,
    });
    expectCode(
      () =>
        c.newE.openAccountKey({
          sealed,
          transcript: T3,
          ephSelf: c.ephNew,
          ephPeerPk: c.ephOld.pk,
        }),
      "E2EE_DECRYPT_FAILED",
    );
    expectCode(
      () =>
        c.newE.openAccountKey({
          sealed,
          transcript: c.T,
          ephSelf: other,
          ephPeerPk: c.ephOld.pk,
        }),
      "E2EE_DECRYPT_FAILED",
    );
    const bad = b64uDecode(sealed)!;
    bad[30]! ^= 1;
    expectCode(
      () =>
        c.newE.openAccountKey({
          sealed: b64uEncode(bad),
          transcript: c.T,
          ephSelf: c.ephNew,
          ephPeerPk: c.ephOld.pk,
        }),
      "E2EE_DECRYPT_FAILED",
    );
  });

  it("verifiers never throw; inputs are validated", () => {
    const c = ceremony();
    expect(c.oldE.verifyLinkCommitment("x", c.T, c.ephNew.pk)).toBe(false);
    expect(c.oldE.verifyLinkCommitment(c.commit, 5 as never, c.ephNew.pk)).toBe(
      false,
    );
    expect(c.oldE.verifyLinkCommitment(c.commit, c.T, null as never)).toBe(
      false,
    );
    expectCode(
      () => c.oldE.linkCommitment("x", c.ephNew.pk),
      "E2EE_INVALID_INPUT",
    );
    const base = {
      requestId: c.requestId,
      accountId: "acct",
      newDeviceId: "n",
      newDeviceSignPk: c.newDev.signPk,
      newDeviceBoxPk: c.newDev.boxPk,
      suites: [...SUITES],
    };
    for (const over of [
      { requestId: "a b" },
      { accountId: "" },
      { newDeviceId: "x".repeat(129) },
      { newDeviceBoxPk: "x" },
      { newDeviceSignPk: "x" },
      { suites: [] },
    ])
      expectCode(
        () => c.oldE.linkTranscript({ ...base, ...over } as never),
        "E2EE_INVALID_INPUT",
      );
    expectCode(
      () =>
        c.oldE.linkTranscript({
          ...base,
          newDeviceSignPk: b64uEncode(Uint8Array.of(1, ...new Uint8Array(31))),
        }),
      "E2EE_INVALID_KEY",
    );
    expectCode(
      () =>
        c.oldE.linkConfirmationCode({
          transcript: c.T,
          ephNewPk: "x",
          ephOldPk: c.ephOld.pk,
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        c.oldE.sealAccountKey({
          account: { ...c.account, v: 2 } as never,
          transcript: c.T,
          ephSelf: c.ephOld,
          ephPeerPk: c.ephNew.pk,
        }),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () =>
        c.oldE.sealAccountKey({
          account: c.account,
          transcript: c.T,
          ephSelf: { pk: c.ephOld.pk },
          ephPeerPk: c.ephNew.pk,
        } as never),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () =>
        c.oldE.sealAccountKey({
          account: c.account,
          transcript: c.T,
          ephSelf: c.ephOld,
          ephPeerPk: b64uEncode(new Uint8Array(32)),
        }),
      "E2EE_INVALID_KEY",
    );
    expectCode(
      () =>
        c.newE.openAccountKey({
          sealed: "AAAA",
          transcript: c.T,
          ephSelf: c.ephNew,
          ephPeerPk: c.ephOld.pk,
        }),
      "E2EE_INVALID_INPUT",
    );
  });

  it("bad unsealed content → E2EE_INVALID_INPUT", async () => {
    const c = ceremony();
    const { aeadSeal, hkdfSha256, x25519Dh } =
      await import("../../src/primitives.js");
    const { concat, utf8 } = await import("../../src/codec.js");
    const seal = (pt: Uint8Array) => {
      const t = b64uDecode(c.T)!;
      const key = hkdfSha256(
        t,
        x25519Dh(b64uDecode(c.ephOld.sk)!, b64uDecode(c.ephNew.pk)!),
        utf8("e2ee/v2/link-seal"),
        32,
      );
      const nonce = new Uint8Array(24).fill(7);
      return b64uEncode(
        concat(
          nonce,
          aeadSeal(
            key,
            nonce,
            pt,
            concat(t, b64uDecode(c.ephOld.pk)!, b64uDecode(c.ephNew.pk)!),
          ),
        ),
      );
    };
    const open = (sealed: string) =>
      c.newE.openAccountKey({
        sealed,
        transcript: c.T,
        ephSelf: c.ephNew,
        ephPeerPk: c.ephOld.pk,
      });
    expectCode(() => open(seal(Uint8Array.of(0xff))), "E2EE_INVALID_INPUT");
    expectCode(() => open(seal(utf8("{"))), "E2EE_INVALID_INPUT");
    expectCode(
      () => open(seal(utf8(JSON.stringify({ ...c.account, x: 1 })))),
      "E2EE_INVALID_INPUT",
    );
    const other = c.oldE.generateAccountIdentity();
    expectCode(
      () =>
        open(
          seal(utf8(JSON.stringify({ ...c.account, signSk: other.signSk }))),
        ),
      "E2EE_INVALID_INPUT",
    );
    expect(open(seal(utf8(JSON.stringify(c.account))))).toEqual(c.account);
  });
});
