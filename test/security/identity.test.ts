// Identity checks from the pre-release review (moved from test/attack-scratch): link seals and cross-struct signatures.
import { expect, it } from "vitest";
import { createE2ee } from "../../src/index.js";
import { expectCode } from "../helpers.js";

const e = createE2ee();
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");

it("sealAccountKey rejects low-order peer ephemerals (the server cannot force a known seal key)", () => {
  const account = e.generateAccountIdentity();
  const self = e.generateLinkEphemeral();
  const transcript = b64u(new Uint8Array(32).fill(7));
  const lowOrder = [
    new Uint8Array(32),
    Uint8Array.of(1, ...new Array<number>(31).fill(0)),
    Buffer.from(
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "hex",
    ),
  ];
  for (const p of lowOrder)
    expectCode(
      () =>
        e.sealAccountKey({
          account,
          transcript,
          ephSelf: self,
          ephPeerPk: b64u(p),
        }),
      "E2EE_INVALID_KEY",
    );
});

it("a device-list signature never verifies as a bundle signature and vice versa", () => {
  const account = e.generateAccountIdentity();
  const dev = e.generateDeviceIdentity("d1");
  const spk = e.generateSignedPrekey(dev, 1);
  const bundle = e.buildDeviceBundle({ device: dev, spk });
  const list = e.buildSignedDeviceList({
    account,
    accountId: "a1",
    epoch: 1,
    devices: [
      {
        deviceId: "d1",
        deviceSignPk: dev.signPk,
        deviceBoxPk: dev.boxPk,
        addedAt: "2026-10-22T12:00:00.000Z",
      },
    ],
  });
  expectCode(
    () => e.verifyDeviceBundle({ ...bundle, deviceBoxPkSig: list.sig }),
    "E2EE_BUNDLE_SIGNATURE_INVALID",
  );
  expectCode(
    () => e.verifySignedDeviceList({ ...list, sig: bundle.deviceBoxPkSig }),
    "E2EE_DEVICE_LIST_INVALID",
  );
  expect(() => e.verifySignedDeviceList(list)).not.toThrow();
  expectCode(
    () => e.verifySignedDeviceList(list, { minEpoch: 2 }),
    "E2EE_DEVICE_LIST_INVALID",
  );
});
