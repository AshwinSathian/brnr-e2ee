// A1: the brnr-e2ee/testing RNGs are refused without an explicit opt-in. A2: repeated back-to-back seeds fail (SPEC §15).
import { describe, expect, it } from "vitest";
import { createE2ee, type Rng } from "../../src/index.js";
import { drbgRng, tapeRng } from "../../src/testing.js";
import { expectCode } from "../helpers.js";
import { bundleOf, CONV, party } from "../parties.js";

describe("A1: test RNGs need dangerouslyAllowTestRng", () => {
  it("drbgRng and tapeRng are refused by default and accepted only with the opt-in set to true", () => {
    const seed = new Uint8Array(32);
    expectCode(
      () => createE2ee({ rng: drbgRng(seed).rng }),
      "E2EE_RNG_UNAVAILABLE",
    );
    expectCode(() => createE2ee({ rng: tapeRng([]) }), "E2EE_RNG_UNAVAILABLE");
    expectCode(
      () =>
        createE2ee({
          rng: drbgRng(seed).rng,
          dangerouslyAllowTestRng: "true" as never,
        }),
      "E2EE_RNG_UNAVAILABLE",
    );
    const e = createE2ee({
      rng: drbgRng(seed).rng,
      dangerouslyAllowTestRng: true,
    });
    expect(e.generateAccountIdentity().signSk).toHaveLength(43);
  });

  it("the brand is a registered symbol, so a test RNG from the other build is refused too", () => {
    const rng = Object.assign(
      (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
      { [Symbol.for("brnr-e2ee/test-rng")]: true },
    );
    expectCode(() => createE2ee({ rng }), "E2EE_RNG_UNAVAILABLE");
    // An RNG whose brand lookup throws is not a test RNG; its draws are checked as usual.
    const trapped = new Proxy(
      (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
      {
        get: () => {
          throw new Error("trap");
        },
      },
    );
    expect(() => createE2ee({ rng: trapped })).not.toThrow();
  });
});

describe("A2: a repeated draw is caught", () => {
  /** Real randomness until `stuck` is set, then the same bytes for every draw. */
  function stuckRng() {
    const r = { stuck: false };
    const rng: Rng = (n) =>
      r.stuck
        ? new Uint8Array(n).fill(0x41)
        : globalThis.crypto.getRandomValues(new Uint8Array(n));
    return { rng, r };
  }

  it("generateDeviceIdentity, generateOneTimePrekeys and initiateSession fail on equal back-to-back seeds", () => {
    const { rng, r } = stuckRng();
    const e = createE2ee({ rng });
    const b = party("bob");
    const device = e.generateDeviceIdentity("dev-1");
    r.stuck = true;
    expectCode(() => e.generateDeviceIdentity("dev-2"), "E2EE_RNG_UNAVAILABLE");
    expectCode(() => e.generateOneTimePrekeys(1, 2), "E2EE_RNG_UNAVAILABLE");
    expect(e.generateOneTimePrekeys(1, 1)).toHaveLength(1);
    expectCode(
      () =>
        e.initiateSession({
          conversationId: CONV,
          self: device,
          peerBundle: bundleOf(b),
        }),
      "E2EE_RNG_UNAVAILABLE",
    );
  });

  it("a repeat after the first OTP pair is caught as well", () => {
    let i = 0;
    const rng: Rng = (n) =>
      i++ < 4
        ? globalThis.crypto.getRandomValues(new Uint8Array(n))
        : new Uint8Array(n).fill(0x42);
    const e = createE2ee({ rng }); // draws 0-1 are the health check
    expectCode(() => e.generateOneTimePrekeys(1, 4), "E2EE_RNG_UNAVAILABLE");
  });
});
