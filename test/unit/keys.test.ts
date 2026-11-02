import { afterEach, describe, expect, it, vi } from "vitest";
import { createE2ee, SUITES, type DeviceBundleV2 } from "../../src/index.js";
import { b64uEncode } from "../../src/codec.js";
import { expectCode, makeE2ee, T0, testClock } from "../helpers.js";

export const SMALL_ORDER = b64uEncode(Uint8Array.of(1, ...new Uint8Array(31)));

describe("createE2ee (SPEC §15)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("draws two health samples", () => {
    const { tape } = makeE2ee();
    expect(tape.map((t) => [t.purpose, t.bytes.length])).toEqual([
      ["health", 32],
      ["health", 32],
    ]);
  });
  it("no RNG → E2EE_RNG_UNAVAILABLE", () => {
    vi.stubGlobal("crypto", undefined);
    expectCode(() => createE2ee(), "E2EE_RNG_UNAVAILABLE");
  });
  it("default RNG uses globalThis.crypto", () => {
    expect(createE2ee().generateAccountIdentity().signSk).toHaveLength(43);
  });
  it("failed health check → E2EE_RNG_UNAVAILABLE", () => {
    expectCode(
      () => createE2ee({ rng: (n) => new Uint8Array(n) }),
      "E2EE_RNG_UNAVAILABLE",
    );
    expectCode(
      () => createE2ee({ rng: (n) => new Uint8Array(n).fill(7) }),
      "E2EE_RNG_UNAVAILABLE",
    );
    let i = 0;
    expectCode(
      () =>
        createE2ee({
          rng: (n) =>
            i++ === 0 ? new Uint8Array(n) : new Uint8Array(n).fill(1),
        }),
      "E2EE_RNG_UNAVAILABLE",
    );
  });
  it("bad draws → E2EE_RNG_UNAVAILABLE", () => {
    const after = (bad: (n: number) => unknown) => {
      let i = 0;
      return createE2ee({
        rng: ((n: number) =>
          i++ < 2 ? new Uint8Array(n).fill(i) : bad(n)) as never,
      });
    };
    expectCode(
      () => after((n) => new Uint8Array(n - 1)).generateAccountIdentity(),
      "E2EE_RNG_UNAVAILABLE",
    );
    expectCode(
      () => after(() => [1, 2]).generateAccountIdentity(),
      "E2EE_RNG_UNAVAILABLE",
    );
    expectCode(
      () =>
        after(() => {
          throw new Error("x");
        }).generateAccountIdentity(),
      "E2EE_RNG_UNAVAILABLE",
    );
    expectCode(() => createE2ee({ rng: 5 as never }), "E2EE_RNG_UNAVAILABLE");
  });
  it("copies RNG output", () => {
    const buf = new Uint8Array(32);
    let i = 0;
    const e = createE2ee({
      rng: (n) =>
        i++ < 2 ? new Uint8Array(n).fill(i) : buf.fill(9).subarray(0, n),
    });
    const a = e.generateAccountIdentity();
    buf.fill(1);
    expect(a.signSk).toBe(b64uEncode(new Uint8Array(32).fill(9)));
  });
});

describe("clock (SPEC §4.8)", () => {
  it("invalid clock → E2EE_INVALID_INPUT; caller exceptions propagate", () => {
    const { e: good } = makeE2ee();
    const device = good.generateDeviceIdentity("dev-1");
    const mk = (now: () => Date) =>
      makeE2ee("c", { now, set() {}, advance() {}, ms: 0 } as never).e;
    expectCode(
      () => mk(() => new Date(NaN)).generateSignedPrekey(device, 1),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        mk(() => new Date(Date.UTC(1999, 0, 1))).generateSignedPrekey(
          device,
          1,
        ),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        mk(() => new Date(Date.UTC(10000, 0, 1))).generateSignedPrekey(
          device,
          1,
        ),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => mk(() => "2026" as never).generateSignedPrekey(device, 1),
      "E2EE_INVALID_INPUT",
    );
    const boom = new Error("caller");
    expect(() =>
      mk(() => {
        throw boom;
      }).generateSignedPrekey(device, 1),
    ).toThrow(boom);
    expectCode(() => createE2ee({ now: 1 as never }), "E2EE_INVALID_INPUT");
  });
});

describe("keys (SPEC §5.2)", () => {
  it("generates with the documented draw order", () => {
    const { e, tape } = makeE2ee();
    const acc = e.generateAccountIdentity();
    const dev = e.generateDeviceIdentity("dev-1");
    const spk = e.generateSignedPrekey(dev, 1);
    const otps = e.generateOneTimePrekeys(5, 3);
    expect(tape.slice(2).map((t) => t.purpose)).toEqual(Array(7).fill("seed"));
    expect(acc.signSk).toBe(b64uEncode(tape[2]!.bytes));
    expect(dev.signSk).toBe(b64uEncode(tape[3]!.bytes));
    expect(dev.boxSk).toBe(b64uEncode(tape[4]!.bytes));
    expect(spk.sk).toBe(b64uEncode(tape[5]!.bytes));
    expect(otps.map((o) => o.otpId)).toEqual([5, 6, 7]);
    expect(otps[2]!.sk).toBe(b64uEncode(tape[8]!.bytes));
    expect(spk).toMatchObject({
      v: 1,
      spkId: 1,
      createdAt: new Date(T0).toISOString(),
      suites: [...SUITES],
    });
  });

  it("validates parameters", () => {
    const { e } = makeE2ee();
    const dev = e.generateDeviceIdentity("dev-1");
    expectCode(() => e.generateDeviceIdentity("bad id"), "E2EE_INVALID_INPUT");
    expectCode(
      () => e.generateDeviceIdentity("x".repeat(129)),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => e.generateSignedPrekey({ ...dev, extra: 1 } as never, 1),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () => e.generateSignedPrekey({ ...dev, v: 2 } as never, 1),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () => e.generateSignedPrekey({ ...dev, signPk: SMALL_ORDER }, 1),
      "E2EE_INVALID_KEY",
    );
    for (const id of [0, -1, 1.5, 2 ** 31, "1"])
      expectCode(
        () => e.generateSignedPrekey(dev, id as never),
        "E2EE_INVALID_INPUT",
      );
    for (const s of [
      [],
      ["A"],
      ["a", "a"],
      Array.from({ length: 9 }, (_, i) => `s${i}`),
      ["x".repeat(65)],
    ])
      expectCode(
        () => e.generateSignedPrekey(dev, 1, s as never),
        "E2EE_INVALID_INPUT",
      );
    expect(
      e.generateSignedPrekey(dev, 2 ** 31 - 1, [
        "future-suite",
        ...SUITES,
      ] as never).suites,
    ).toEqual(["future-suite", ...SUITES]);
    for (const [f, c] of [
      [0, 1],
      [1, 0],
      [1, 1001],
      [2 ** 31 - 1, 2],
      [1.5, 1],
    ])
      expectCode(() => e.generateOneTimePrekeys(f!, c!), "E2EE_INVALID_INPUT");
    expect(e.generateOneTimePrekeys(2 ** 31 - 1, 1)).toHaveLength(1);
    expect(e.generateOneTimePrekeys(1, 1000)).toHaveLength(1000);
  });
});

describe("device bundles (SPEC §5.4)", () => {
  const setup = () => {
    const { e } = makeE2ee("bundle");
    const dev = e.generateDeviceIdentity("dev-b");
    const spk = e.generateSignedPrekey(dev, 7);
    const bundle: DeviceBundleV2 = {
      ...e.buildDeviceBundle({ device: dev, spk }),
      otp: { otpId: 3, pk: spk.pk },
    };
    return { e, dev, spk, bundle };
  };

  it("builds a bundle that verifies, from the SPK's suites and createdAt", () => {
    const { e, dev, spk, bundle } = setup();
    expect(bundle).toMatchObject({
      v: 2,
      deviceId: "dev-b",
      spkId: 7,
      suites: spk.suites,
      createdAt: spk.createdAt,
      deviceBoxPk: dev.boxPk,
    });
    e.verifyDeviceBundle(bundle);
    e.verifyDeviceBundle(JSON.stringify(bundle) as never);
    expect(e.parseBundle(JSON.stringify(bundle))).toEqual(bundle);
  });

  it("rejects tampering with signed fields → E2EE_BUNDLE_SIGNATURE_INVALID", () => {
    const { e, dev, bundle } = setup();
    const other = e.generateDeviceIdentity("dev-o");
    const T = (b: Partial<DeviceBundleV2>) =>
      expectCode(
        () => e.verifyDeviceBundle({ ...bundle, ...b }),
        "E2EE_BUNDLE_SIGNATURE_INVALID",
      );
    T({ deviceBoxPk: other.boxPk });
    T({ deviceId: "dev-x" });
    T({ spkPk: other.boxPk });
    T({ spkId: 8 });
    T({ createdAt: "2026-10-22T12:00:00.001Z" });
    T({ suites: ["x25519-xchacha20poly1305-sha256-v0"] });
    T({ suites: [...bundle.suites, "extra"] });
    T({ deviceSignPk: other.signPk });
    T({ spkSig: bundle.deviceBoxPkSig });
    // The OTP is not signed.
    e.verifyDeviceBundle({ ...bundle, otp: { otpId: 99, pk: dev.boxPk } });
    const { otp: _drop, ...noOtp } = bundle;
    e.verifyDeviceBundle(noOtp);
  });

  it("strict parse order and codes", () => {
    const { e, bundle } = setup();
    expectCode(() => e.verifyDeviceBundle(null as never), "E2EE_INVALID_INPUT");
    expectCode(
      () => e.verifyDeviceBundle("not json" as never),
      "E2EE_INVALID_INPUT",
    );
    expectCode(() => e.verifyDeviceBundle([] as never), "E2EE_INVALID_INPUT");
    expectCode(
      () => e.verifyDeviceBundle({ ...bundle, v: 1 } as never),
      "E2EE_UNSUPPORTED_VERSION",
    );
    const { v: _v, ...noV } = bundle;
    expectCode(
      () => e.verifyDeviceBundle(noV as never),
      "E2EE_UNSUPPORTED_VERSION",
    );
    const err = expectCode(
      () => e.verifyDeviceBundle({ ...bundle, extra: 1 } as never),
      "E2EE_INVALID_INPUT",
    );
    expect(err.details).toEqual({ path: "" });
    expect(
      expectCode(
        () => e.verifyDeviceBundle({ ...bundle, spkPk: bundle.spkPk.slice(1) }),
        "E2EE_INVALID_INPUT",
      ).details,
    ).toEqual({ path: "spkPk" });
    expectCode(
      () => e.verifyDeviceBundle({ ...bundle, otp: undefined } as never),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.verifyDeviceBundle({
          ...bundle,
          otp: { otpId: 0, pk: bundle.spkPk },
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.verifyDeviceBundle({
          ...bundle,
          createdAt: "2026-02-30T00:00:00.000Z",
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => e.verifyDeviceBundle({ ...bundle, deviceSignPk: SMALL_ORDER }),
      "E2EE_INVALID_KEY",
    );
    expectCode(
      () =>
        e.buildDeviceBundle({ device: bundle as never, spk: bundle as never }),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(() => e.buildDeviceBundle(null as never), "E2EE_INVALID_STATE");
  });

  it("unknown well-formed suite ids are accepted", () => {
    const { e } = makeE2ee("s", testClock());
    const dev = e.generateDeviceIdentity("d");
    const spk = e.generateSignedPrekey(dev, 1, [
      "zz-future-v9",
      ...SUITES,
    ] as never);
    e.verifyDeviceBundle(e.buildDeviceBundle({ device: dev, spk }));
  });
});
