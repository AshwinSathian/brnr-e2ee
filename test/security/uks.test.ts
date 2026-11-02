// U-1: unknown-key-share (SPEC §6.5). A bundle may carry a box key its signer does not hold. Suite v2
// binds both devices' (deviceId, deviceSignPk, deviceBoxPk), so both forms of the attack fail; suite v1
// keeps the known limitation, documented by the last block.
import { describe, expect, it } from "vitest";
import type {
  DeviceBundleV2,
  MessageV2,
  SignedPrekeyPair,
  SuiteId,
} from "../../src/index.js";
import { b64uDecode, b64uEncode } from "../../src/codec.js";
import { boxPkSigPayload, spkSigPayload } from "../../src/keys.js";
import { ed25519Sign } from "../../src/primitives.js";
import { sidOf } from "../../src/x3dh.js";
import { expectCode } from "../helpers.js";
import {
  adOf,
  bundleOf,
  CONV,
  party,
  receive,
  send,
  V1,
  V2,
  type Party,
} from "../parties.js";

/** Eve signs, under her own device key and `deviceId`, a bundle with the victim's box key and SPK. */
function evilBundle(
  eve: Party,
  victim: Party,
  deviceId: string,
  suites?: string[],
): DeviceBundleV2 {
  const spk = victim.spks.get(1) as SignedPrekeyPair;
  const sk = b64uDecode(eve.device.signSk) as Uint8Array;
  const list = suites ?? [...spk.suites];
  return {
    v: 2,
    suites: list,
    deviceId,
    deviceSignPk: eve.device.signPk,
    deviceBoxPk: victim.device.boxPk,
    deviceBoxPkSig: b64uEncode(
      ed25519Sign(sk, boxPkSigPayload(deviceId, victim.device.boxPk)),
    ),
    spkId: spk.spkId,
    spkPk: spk.pk,
    spkSig: b64uEncode(
      ed25519Sign(
        sk,
        spkSigPayload(deviceId, spk.spkId, spk.pk, spk.createdAt, list),
      ),
    ),
    createdAt: spk.createdAt,
  };
}

/** Eve's signed device list naming `deviceId` with her signing key and `boxPk`: every check passes. */
function evilList(eve: Party, deviceId: string, boxPk: string) {
  const account = eve.e.generateAccountIdentity();
  const list = eve.e.buildSignedDeviceList({
    account,
    accountId: "eve",
    epoch: 1,
    devices: [
      {
        deviceId,
        deviceSignPk: eve.device.signPk,
        deviceBoxPk: boxPk,
        addedAt: "2026-10-22T12:00:00.000Z",
      },
    ],
  });
  eve.e.verifySignedDeviceList(list, { pinnedAccountSignPk: account.signPk });
  return list;
}

const three = (mk: (n: string) => Party = (n) => party(n)) =>
  [mk("alice"), mk("bob"), mk("eve")] as const;

/** Bob's §6.4 accept with explicit pins; returns the candidate or throws. */
const accept = (
  bob: Party,
  m: MessageV2,
  pins: { box: string; sign?: string },
) =>
  bob.e.acceptSession({
    conversationId: CONV,
    self: bob.device,
    expectedPeerBoxPk: pins.box,
    ...(pins.sign ? { expectedPeerSignPk: pins.sign } : {}),
    message: m,
    lookupSpk: (id) => bob.spks.get(id),
    lookupOtp: (id) => bob.otps.get(id),
    seenHandshake: () => false,
  });

/** Rewrites the handshake (and the sid that names it) as an active attacker would. */
const rewrite = (
  m: MessageV2,
  h: Partial<NonNullable<MessageV2["handshake"]>>,
  ad: Partial<MessageV2["ad"]> = {},
): MessageV2 => {
  const handshake = { ...m.handshake!, ...h };
  return {
    ...m,
    handshake,
    header: { ...m.header, sid: sidOf(handshake) },
    ad: { ...m.ad, ...ad } as MessageV2["ad"],
  };
};

describe("U-1 under suite v2: the misdirected recipient", () => {
  for (const deviceId of ["eve-dev", "bob-dev"])
    it(`Bob refuses Alice's message to Eve's bundle (deviceId ${deviceId}) with IDENTITY_MISMATCH`, () => {
      const [alice, bob, eve] = three();
      const bundle = evilBundle(eve, bob, deviceId);
      const list = evilList(eve, deviceId, bob.device.boxPk);
      expect(alice.e.bundleMatchesDeviceList(bundle, list)).toBe(true);
      alice.state = alice.e.initiateSession({
        conversationId: CONV,
        self: alice.device,
        peerBundle: bundle,
      });
      const m = send(alice, "for Eve only");
      expect(m.suite).toBe(V2);
      expect(m.handshake?.responderDeviceId).toBe(deviceId);
      expect(m.handshake?.responderSignPk).toBe(eve.device.signPk);
      // Bob's §8.3 flow, pinned to Alice's real keys.
      expectCode(() => receive(bob, alice, m), "E2EE_IDENTITY_MISMATCH");
      expect(bob.state).toBeNull();
      // Rewriting the handshake to name Bob passes the checks but changes SK: the AEAD fails.
      const retargeted = rewrite(
        m,
        {
          responderDeviceId: bob.device.deviceId,
          responderSignPk: bob.device.signPk,
        },
        { recipientDeviceId: bob.device.deviceId },
      );
      expectCode(() => receive(bob, alice, retargeted), "E2EE_DECRYPT_FAILED");
      expect(bob.state).toBeNull();
    });
});

describe("U-1 under suite v2: the misattributed sender", () => {
  it("Bob's pins for Eve (Alice's box key, Eve's signing key) refuse Alice's message", () => {
    const [alice, bob, eve] = three();
    evilList(eve, alice.device.deviceId, alice.device.boxPk);
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: bundleOf(bob),
    });
    const m = send(alice, "from Alice");
    const evePins = { box: alice.device.boxPk, sign: eve.device.signPk };
    expectCode(() => accept(bob, m, evePins), "E2EE_IDENTITY_MISMATCH");
    // Rewriting initiatorSignPk to Eve's passes the pin but changes SK.
    const relabelled = rewrite(m, { initiatorSignPk: eve.device.signPk });
    const cand = accept(bob, relabelled, evePins);
    expectCode(
      () =>
        bob.e.decrypt({
          state: cand,
          message: relabelled,
          expectedAd: adOf(V2, alice.device.deviceId, bob.device.deviceId),
        }),
      "E2EE_DECRYPT_FAILED",
    );
    // With Alice's real pins it decrypts.
    expect(receive(bob, alice, m)).toBe("from Alice");
  });

  it("a v2 message needs expectedPeerSignPk", () => {
    const [alice, bob] = [party("alice"), party("bob")];
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: bundleOf(bob),
    });
    const m = send(alice, "x");
    expectCode(
      () => accept(bob, m, { box: alice.device.boxPk }),
      "E2EE_INVALID_INPUT",
    );
  });
});

describe("U-1: downgrade", () => {
  it("the server cannot strip v2 from a bundle: the SPK signature covers the list", () => {
    const [alice, bob] = [party("alice"), party("bob")];
    const b = bundleOf(bob);
    expect(b.suites).toEqual([V2, V1]);
    expectCode(
      () =>
        alice.e.initiateSession({
          conversationId: CONV,
          self: alice.device,
          peerBundle: { ...b, suites: [V1] },
        }),
      "E2EE_BUNDLE_SIGNATURE_INVALID",
    );
  });

  it("Eve-forced v1 with default settings: Bob's [v2, v1] SPK admits it (the documented residual, SPEC §6.5)", () => {
    const [alice, bob, eve] = three();
    expect(bob.spks.get(1)!.suites).toEqual([V2, V1]);
    // Eve signs her own bundle around Bob's SPK public key and lists v1 only.
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: evilBundle(eve, bob, "eve-dev", [V1]),
    });
    const m = send(alice, "for Eve only");
    expect(m.suite).toBe(V1);
    expect(receive(bob, alice, m)).toBe("for Eve only");
  });

  it("Eve-forced v1, closed by the initiator: suite v2 refuses her bundle", () => {
    const [alice, bob, eve] = three();
    expectCode(
      () =>
        alice.e.initiateSession({
          conversationId: CONV,
          self: alice.device,
          peerBundle: evilBundle(eve, bob, "eve-dev", [V1]),
          suite: V2,
        }),
      "E2EE_UNSUPPORTED_SUITE",
    );
  });

  it("Eve-forced v1, closed by the responder: a v2-only SPK refuses the v1 founding message", () => {
    const [alice, eve] = [party("alice"), party("eve")];
    const strict = party("bob", undefined, [V2]);
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: evilBundle(eve, strict, "eve-dev", [V1]),
    });
    const m = send(alice, "v1 to Eve");
    expect(m.suite).toBe(V1);
    expectCode(() => receive(strict, alice, m), "E2EE_UNSUPPORTED_SUITE");
    expect(strict.state).toBeNull();
  });

  /** Alice and Bob on v2; Bob also holds a stale v1-only SPK a server could still serve. */
  function upgradedPair() {
    const [alice, bob] = [party("alice"), party("bob")];
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: bundleOf(bob),
    });
    receive(bob, alice, send(alice, "v2"));
    receive(alice, bob, send(bob, "v2 reply"));
    const stale = bob.e.generateSignedPrekey(bob.device, 2, [V1]);
    bob.spks.set(2, stale);
    const peerBundle = bob.e.buildDeviceBundle({
      device: bob.device,
      spk: stale,
    });
    return { alice, bob, peerBundle };
  }

  it("server-forced downgrade: an upgraded initiator refuses a v1-only bundle", () => {
    const { alice, peerBundle } = upgradedPair();
    expectCode(
      () =>
        alice.e.initiateSession({
          conversationId: CONV,
          self: alice.device,
          peerBundle,
          existing: alice.state!,
        }),
      "E2EE_UNSUPPORTED_SUITE",
    );
  });

  it("a v1 founding message (replayed, forged or sent by a fresh state) never enters a v2 state", () => {
    const { alice, bob, peerBundle } = upgradedPair();
    const fresh = party("alice");
    fresh.state = fresh.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle,
    });
    const m1 = send(fresh, "v1");
    expect(m1.suite).toBe(V1);
    const before = bob.e.serializeState(bob.state!);
    expectCode(() => receive(bob, alice, m1), "E2EE_UNSUPPORTED_SUITE");
    expectCode(
      () =>
        bob.e.acceptSession({
          conversationId: CONV,
          self: bob.device,
          expectedPeerBoxPk: alice.device.boxPk,
          expectedPeerSignPk: alice.device.signPk,
          message: m1,
          lookupSpk: (id) => bob.spks.get(id),
          lookupOtp: (id) => bob.otps.get(id),
          seenHandshake: () => false,
          existing: bob.state!,
        }),
      "E2EE_UNSUPPORTED_SUITE",
    );
    expect(bob.e.serializeState(bob.state!)).toBe(before);
  });

  it("a v1 message on a v1 session is refused once the state is v2", () => {
    const a = party("alice", undefined, [V1]);
    const b = party("bob", undefined, [V1]);
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b),
    });
    receive(b, a, send(a, "v1"));
    receive(a, b, send(b, "v1 reply"));
    const late = send(a, "v1, delivered late");
    const lateReply = send(b, "v1 reply, delivered late");
    b.spks.set(2, b.e.generateSignedPrekey(b.device, 2));
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b),
      existing: a.state,
    });
    expect(a.e.inspectSession(a.state).suite).toBe(V2);
    expect(receive(b, a, send(a, "v2"))).toBe("v2");
    expectCode(() => receive(b, a, late), "E2EE_UNSUPPORTED_SUITE");
    // Alice's state moved to v2 when she initiated: Bob's earlier v1 reply is refused too.
    expectCode(() => receive(a, b, lateReply), "E2EE_UNSUPPORTED_SUITE");
  });
});

describe("U-1: the state pins the peer's signing key", () => {
  it("re-initiating to a bundle with another signing key fails", () => {
    const [alice, bob, eve] = three();
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: bundleOf(bob),
    });
    expectCode(
      () =>
        alice.e.initiateSession({
          conversationId: CONV,
          self: alice.device,
          peerBundle: evilBundle(eve, bob, bob.device.deviceId),
          existing: alice.state!,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
  });

  it("accepting with existing needs the same signing pin, in either suite", () => {
    const [alice, bob, eve] = three();
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: bundleOf(bob),
    });
    receive(bob, alice, send(alice, "one"));
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: bundleOf(bob),
      existing: alice.state,
    });
    const m = send(alice, "two");
    const go = (sign?: string) =>
      bob.e.acceptSession({
        conversationId: CONV,
        self: bob.device,
        expectedPeerBoxPk: alice.device.boxPk,
        ...(sign ? { expectedPeerSignPk: sign } : {}),
        message: m,
        lookupSpk: (id) => bob.spks.get(id),
        lookupOtp: (id) => bob.otps.get(id),
        seenHandshake: () => false,
        existing: bob.state!,
      });
    expectCode(() => go(eve.device.signPk), "E2EE_IDENTITY_MISMATCH");
    expect(() => go(alice.device.signPk)).not.toThrow();
  });
});

describe("U-1 under suite v1: the known limitation (unchanged)", () => {
  const v1Party = (n: string) => party(n, undefined, [V1]);

  it("v1: Bob decrypts a message Alice encrypted to Eve's verified bundle", () => {
    const [alice, bob, eve] = three(v1Party);
    const bundle = evilBundle(eve, bob, "eve-dev");
    const list = evilList(eve, "eve-dev", bob.device.boxPk);
    expect(alice.e.bundleMatchesDeviceList(bundle, list)).toBe(true);
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: bundle,
    });
    const m = send(alice, "for Eve only");
    expect(m.suite).toBe(V1);
    expect(receive(bob, alice, m)).toBe("for Eve only");
  });

  it("v1: with a reused deviceId, Bob's reply is accepted on Alice's session with Eve", () => {
    const [alice, bob, eve] = three(v1Party);
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: evilBundle(eve, bob, bob.device.deviceId),
    });
    receive(bob, alice, send(alice, "hi"));
    const reply = send(bob, "I am Bob");
    const r = alice.e.decrypt({
      state: alice.state,
      message: reply,
      expectedAd: adOf(V1 as SuiteId, bob.device.deviceId, ""),
    });
    expect(new TextDecoder().decode(r.plaintext)).toBe("I am Bob");
  });

  it("v1: Bob's pin for Eve (Alice's box key) attributes Alice's message to Eve", () => {
    const [alice, bob, eve] = three(v1Party);
    alice.state = alice.e.initiateSession({
      conversationId: CONV,
      self: alice.device,
      peerBundle: bundleOf(bob),
    });
    const m = send(alice, "from Alice");
    // A v1 message ignores the signing pin: Eve's is accepted.
    const cand = accept(bob, m, {
      box: alice.device.boxPk,
      sign: eve.device.signPk,
    });
    const r = bob.e.decrypt({
      state: cand,
      message: m,
      expectedAd: adOf(V1, alice.device.deviceId, ""),
    });
    expect(new TextDecoder().decode(r.plaintext)).toBe("from Alice");
  });
});
