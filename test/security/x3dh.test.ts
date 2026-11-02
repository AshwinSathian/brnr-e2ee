// X3DH defences confirmed by the adversarial review: replay set, OTP stripping, forged pinned key.
import { describe, expect, it } from "vitest";
import type { MessageV2 } from "../../src/index.js";
import { sidOf } from "../../src/x3dh.js";
import { bundleOf, CONV, party, receive, send, V1, V2 } from "../parties.js";

/** sid(h) as SPEC §6.1. */
const sidFor = (_p: unknown, h: MessageV2["handshake"]): string => sidOf(h!);

describe("X3DH misc", () => {
  it("3-DH founding replay after 32+ newer handshakes hits the per-SPK replay set", () => {
    const a = party("alice");
    const b = party("bob");
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b, false),
    });
    const first = send(a, "first");
    receive(b, a, first);
    for (let i = 0; i < 33; i++) {
      a.state = a.e.initiateSession({
        conversationId: CONV,
        self: a.device,
        peerBundle: bundleOf(b, false),
        existing: a.state!,
      });
      receive(b, a, send(a, `m${i}`));
    }
    expect(() => receive(b, a, first)).toThrow(/already accepted|DUPLICATE/);
  });

  it("stripping otpId (4-DH -> 3-DH) in transit fails", () => {
    const a = party("alice");
    const b = party("bob");
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b, true),
    });
    const m = send(a, "x");
    const { otpId: _o, ...h3 } = m.handshake!;
    const m2: MessageV2 = {
      ...m,
      handshake: h3,
      header: { ...m.header, sid: sidFor(b, h3) },
    };
    expect(() => receive(b, a, m2)).toThrow();
    expect(b.state).toBeNull();
  });

  for (const [suites, keys] of [
    [[V1], ["initiatorBoxPk"]],
    [[V2], ["initiatorBoxPk", "initiatorSignPk"]],
  ] as const)
    it(`server-forged handshake with the pinned initiator keys cannot decrypt (${suites[0]})`, () => {
      const a = party("alice", undefined, [...suites]);
      const b = party("bob", undefined, [...suites]);
      const mallory = party("mallory", undefined, [...suites]);
      mallory.state = mallory.e.initiateSession({
        conversationId: CONV,
        self: mallory.device,
        peerBundle: bundleOf(b, false),
      });
      const m = send(mallory, "x");
      const own = {
        initiatorBoxPk: a.device.boxPk,
        initiatorSignPk: a.device.signPk,
      };
      const h = { ...m.handshake! };
      for (const k of keys) h[k] = own[k];
      const forged: MessageV2 = {
        ...m,
        ad: { ...m.ad, senderDeviceId: a.device.deviceId },
        handshake: h,
        header: { ...m.header, sid: sidFor(b, h) },
      };
      expect(() => receive(b, a, forged)).toThrow(/authentication|DECRYPT/);
      expect(b.state).toBeNull();
    });
});
