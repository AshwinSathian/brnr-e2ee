// X2: non-canonical X25519 public keys are rejected at decode (SPEC §4.2). F4: plain objects only (SPEC §4.8).
import { describe, expect, it } from "vitest";
import { b64uDecode, b64uEncode, isCanonicalX25519 } from "../../src/codec.js";
import { x25519Dh } from "../../src/primitives.js";
import { expectCode } from "../helpers.js";
import { bundleOf, CONV, party, send } from "../parties.js";

const P = 2n ** 255n - 19n;
const le = (n: bigint) => {
  const o = new Uint8Array(32);
  for (let i = 0; i < 32; i++) o[i] = Number((n >> BigInt(8 * i)) & 255n);
  return o;
};
const raw = (s: string) => b64uDecode(s) as Uint8Array;
const hiBit = (k: string) => {
  const b = raw(k).slice();
  b[31] = (b[31] as number) ^ 0x80;
  return b64uEncode(b);
};

describe("X2: canonical X25519 public keys", () => {
  it("bit 255 and u ≥ p are rejected; u = p − 1 and below are accepted", () => {
    expect(isCanonicalX25519(le(P - 1n))).toBe(true);
    expect(isCanonicalX25519(le(9n))).toBe(true);
    for (const u of [P, P + 1n, P + 18n, 2n ** 255n, 2n ** 255n + 9n])
      expect(isCanonicalX25519(le(u))).toBe(false);
    // Not ≥ p: top byte 0x7f with a byte below 0xff in the middle, or byte 0 just under 0xed.
    const mid = le(P);
    mid[15] = 0xfe;
    expect(isCanonicalX25519(mid)).toBe(true);
    expect(isCanonicalX25519(le(P - 1n))).toBe(true);
    const top7e = le(P);
    top7e[31] = 0x7e;
    expect(isCanonicalX25519(top7e)).toBe(true);
  });

  it("a high-bit ephemeral key, same DH, no longer yields a second handshake digest", () => {
    const a = party("alice");
    const b = party("bob");
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b, false),
    });
    const m = send(a, "x");
    const h = m.handshake!;
    const h2 = { ...h, initiatorEphPk: hiBit(h.initiatorEphPk) };
    const sk = raw(b.spks.get(1)!.sk);
    expect(x25519Dh(sk, raw(h2.initiatorEphPk))).toEqual(
      x25519Dh(sk, raw(h.initiatorEphPk)),
    );
    expectCode(() => a.e.handshakeDigest(h2), "E2EE_INVALID_INPUT");
    const err = expectCode(
      () => b.e.parseMessage({ ...m, handshake: h2 }),
      "E2EE_INVALID_INPUT",
    );
    expect(err.details).toEqual({ path: "handshake.initiatorEphPk" });
    expectCode(
      () =>
        b.e.parseMessage({
          ...m,
          header: { ...m.header, dh: hiBit(m.header.dh) },
        }),
      "E2EE_INVALID_INPUT",
    );
  });

  it("bundles, device lists, key pairs, state and link inputs reject them too", () => {
    const a = party("alice");
    const b = party("bob");
    const bun = bundleOf(b);
    for (const bad of [
      { ...bun, spkPk: hiBit(bun.spkPk) },
      { ...bun, deviceBoxPk: hiBit(bun.deviceBoxPk) },
      { ...bun, otp: { ...bun.otp!, pk: hiBit(bun.otp!.pk) } },
    ])
      expectCode(() => a.e.parseBundle(bad), "E2EE_INVALID_INPUT");
    expectCode(
      () =>
        a.e.parseDeviceList({
          v: 1,
          accountId: "a",
          accountSignPk: a.device.signPk,
          epoch: 1,
          devices: [
            {
              deviceId: "d",
              deviceSignPk: a.device.signPk,
              deviceBoxPk: hiBit(a.device.boxPk),
              addedAt: "2026-10-22T12:00:00.000Z",
            },
          ],
          sig: "A".repeat(86),
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        a.e.generateSignedPrekey(
          { ...a.device, boxPk: hiBit(a.device.boxPk) },
          2,
        ),
      "E2EE_INVALID_STATE",
    );
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bun,
    });
    const j = JSON.parse(JSON.stringify(a.state)) as { peerBoxPk: string };
    expectCode(
      () =>
        a.e.parseState(JSON.stringify({ ...j, peerBoxPk: hiBit(j.peerBoxPk) })),
      "E2EE_INVALID_STATE",
    );
    const eph = a.e.generateLinkEphemeral();
    const peer = a.e.generateLinkEphemeral();
    const account = a.e.generateAccountIdentity();
    const transcript = "A".repeat(43);
    expectCode(
      () =>
        a.e.sealAccountKey({
          account,
          transcript,
          ephSelf: eph,
          ephPeerPk: hiBit(peer.pk),
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => a.e.linkCommitment(transcript, hiBit(peer.pk)),
      "E2EE_INVALID_INPUT",
    );
    const c = a.e.linkCommitment(transcript, peer.pk);
    expect(a.e.verifyLinkCommitment(c, transcript, peer.pk)).toBe(true);
    expect(a.e.verifyLinkCommitment(c, transcript, hiBit(peer.pk))).toBe(false);
    for (const k of ["ephNewPk", "ephOldPk"] as const)
      expectCode(
        () =>
          a.e.linkConfirmationCode({
            transcript,
            ephNewPk: peer.pk,
            ephOldPk: eph.pk,
            [k]: hiBit(peer.pk),
          }),
        "E2EE_INVALID_INPUT",
      );
    expectCode(
      () =>
        a.e.linkTranscript({
          requestId: "r",
          accountId: "a",
          newDeviceId: "d",
          newDeviceSignPk: a.device.signPk,
          newDeviceBoxPk: hiBit(a.device.boxPk),
          suites: ["x25519-xchacha20poly1305-sha256-v1"],
        }),
      "E2EE_INVALID_INPUT",
    );
  });
});

describe("F4: only plain objects are parsed", () => {
  it("an object with another prototype is rejected; a null prototype is accepted", () => {
    const a = party("alice");
    const b = party("bob");
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b),
    });
    const m = send(a, "x");
    class Msg {
      readonly tag = 1;
    }
    expectCode(
      () => b.e.parseMessage(Object.assign(new Msg(), m)),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        b.e.parseMessage(Object.assign(Object.create({ v: 2 }) as object, m)),
      "E2EE_INVALID_INPUT",
    );
    expect(
      b.e.parseMessage(Object.assign(Object.create(null) as object, m)),
    ).toEqual(m);
    expectCode(
      () => a.e.parseState(JSON.stringify([a.state])),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () => a.e.serializeState(Object.assign(new Msg(), a.state)),
      "E2EE_INVALID_STATE",
    );
  });

  it("nested structs must be plain too: inherited fields are never read", () => {
    const a = party("alice");
    const b = party("bob");
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b),
    });
    const m = send(a, "x");
    // A class instance that copies its fields as own properties, so only the prototype differs.
    // eslint-disable-next-line @typescript-eslint/no-extraneous-class
    class Box {
      constructor(o: object) {
        Object.assign(this, o);
      }
    }
    for (const bad of [
      { ...m, header: new Box(m.header) },
      { ...m, ad: new Box(m.ad) },
      { ...m, handshake: new Box(m.handshake!) },
      { ...m, header: Object.create(m.header) as object },
      { ...m, header: Object.assign(new Date(), m.header) },
    ])
      expectCode(() => b.e.parseMessage(bad), "E2EE_INVALID_INPUT");
    const st = JSON.parse(a.e.serializeState(a.state)) as {
      sessions: object[];
    };
    expect(() => a.e.serializeState(st as never)).not.toThrow();
    st.sessions[0] = new Box(st.sessions[0]!);
    expectCode(() => a.e.serializeState(st as never), "E2EE_INVALID_STATE");
  });
});
