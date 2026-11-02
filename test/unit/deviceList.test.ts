// SPEC §5.5 (D12).
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../../src/codec.js";
import { expectCode, makeE2ee, T0 } from "../helpers.js";

const iso = (t: number) => new Date(t).toISOString();

function setup() {
  const { e } = makeE2ee("dl");
  const account = e.generateAccountIdentity();
  const d1 = e.generateDeviceIdentity("d1");
  const d2 = e.generateDeviceIdentity("d2");
  const entry = (d: typeof d1, extra = {}) => ({
    deviceId: d.deviceId,
    deviceSignPk: d.signPk,
    deviceBoxPk: d.boxPk,
    addedAt: iso(T0),
    ...extra,
  });
  const list = e.buildSignedDeviceList({
    account,
    accountId: "acct-1",
    epoch: 3,
    devices: [entry(d1), entry(d2, { revokedAt: iso(T0 + 1) })],
  });
  return { e, account, d1, d2, entry, list };
}

describe("signed device lists (SPEC §5.5)", () => {
  it("builds, verifies, digests and matches bundles", () => {
    const { e, account, d1, d2, list } = setup();
    e.verifySignedDeviceList(list);
    e.verifySignedDeviceList(JSON.stringify(list) as never, {
      pinnedAccountSignPk: account.signPk,
      minEpoch: 3,
    });
    expect(e.deviceListDigest(list)).toHaveLength(43);
    expect(e.parseDeviceList(JSON.stringify(list))).toEqual(list);
    const b1 = e.buildDeviceBundle({
      device: d1,
      spk: e.generateSignedPrekey(d1, 1),
    });
    const b2 = e.buildDeviceBundle({
      device: d2,
      spk: e.generateSignedPrekey(d2, 1),
    });
    expect(e.bundleMatchesDeviceList(b1, list)).toBe(true);
    expect(e.bundleMatchesDeviceList(b2, list)).toBe(false); // revoked
    expect(
      e.bundleMatchesDeviceList({ ...b1, deviceBoxPk: b2.deviceBoxPk }, list),
    ).toBe(false);
    expectCode(
      () => e.bundleMatchesDeviceList({} as never, list),
      "E2EE_UNSUPPORTED_VERSION",
    );
  });

  it("D12: tampered signature, lower epoch and revoked device are rejected", () => {
    const { e, account, list } = setup();
    expectCode(
      () => e.verifySignedDeviceList({ ...list, epoch: 4 }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expectCode(
      () => e.verifySignedDeviceList({ ...list, accountId: "acct-2" }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expectCode(
      () =>
        e.verifySignedDeviceList({
          ...list,
          devices: list.devices.slice(0, 1),
        }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expectCode(
      () => e.verifySignedDeviceList(list, { minEpoch: 4 }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    const other = e.generateAccountIdentity();
    expectCode(
      () =>
        e.verifySignedDeviceList(list, { pinnedAccountSignPk: other.signPk }),
      "E2EE_IDENTITY_MISMATCH",
    );
    // A re-signed list by a different account key fails the pin, not the signature.
    const forged = e.buildSignedDeviceList({
      account: other,
      accountId: "acct-1",
      epoch: 5,
      devices: list.devices,
    });
    expectCode(
      () =>
        e.verifySignedDeviceList(forged, {
          pinnedAccountSignPk: account.signPk,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
    e.verifySignedDeviceList(forged);
  });

  it("checks in order and caps", () => {
    const { e, account, d1, entry, list } = setup();
    expectCode(
      () => e.verifySignedDeviceList(list, { minEpoch: 0 }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => e.verifySignedDeviceList(list, { pinnedAccountSignPk: "x" }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => e.verifySignedDeviceList({ ...list, v: 2 } as never),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () => e.verifySignedDeviceList({ ...list, extra: 1 } as never),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => e.verifySignedDeviceList({ ...list, devices: [] }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expectCode(
      () =>
        e.verifySignedDeviceList({
          ...list,
          devices: [list.devices[0]!, list.devices[0]!],
        }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    const SMALL = b64uEncode(Uint8Array.of(1, ...new Uint8Array(31)));
    expectCode(
      () => e.verifySignedDeviceList({ ...list, accountSignPk: SMALL }),
      "E2EE_INVALID_KEY",
    );
    expectCode(
      () =>
        e.verifySignedDeviceList({
          ...list,
          devices: [{ ...list.devices[0]!, deviceSignPk: SMALL }],
        }),
      "E2EE_INVALID_KEY",
    );
    // revokedAt < addedAt fails before the pin check.
    const badDates = {
      ...list,
      devices: [{ ...list.devices[0]!, revokedAt: iso(T0 - 1) }],
    };
    expectCode(
      () =>
        e.verifySignedDeviceList(badDates, {
          pinnedAccountSignPk: e.generateAccountIdentity().signPk,
        }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    const many = Array.from({ length: 65 }, (_, i) =>
      entry(d1, { deviceId: `d${i}` }),
    );
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account,
          accountId: "a",
          epoch: 1,
          devices: many,
        }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expect(
      e.buildSignedDeviceList({
        account,
        accountId: "a",
        epoch: 1,
        devices: many.slice(0, 64),
      }).devices,
    ).toHaveLength(64);
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account,
          accountId: "a",
          epoch: 1,
          devices: [entry(d1, { revokedAt: iso(T0 - 1) })],
        }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account,
          accountId: "a b",
          epoch: 1,
          devices: [entry(d1)],
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account,
          accountId: "a",
          epoch: 0,
          devices: [entry(d1)],
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account,
          accountId: "a",
          epoch: 1,
          devices: [{ ...entry(d1), x: 1 } as never],
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account: { ...account, v: 2 } as never,
          accountId: "a",
          epoch: 1,
          devices: [entry(d1)],
        }),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(() => e.parseDeviceList("{"), "E2EE_INVALID_INPUT");
  });
});
