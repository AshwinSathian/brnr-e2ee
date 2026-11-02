// SPEC §14 report disclosure (F-6).
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../../src/codec.js";
import { sha256 } from "../../src/primitives.js";
import { expectCode } from "../helpers.js";
import { adFrom, initiate, party, send } from "../parties.js";

function delivered() {
  const a = party("alice");
  const b = party("bob");
  initiate(a, b);
  const m = send(a, "report me ✓");
  const cand = b.e.acceptSession({
    conversationId: "conv-1",
    self: b.device,
    expectedPeerBoxPk: a.device.boxPk,
    expectedPeerSignPk: a.device.signPk,
    message: m,
    lookupSpk: (id) => b.spks.get(id),
    lookupOtp: (id) => b.otps.get(id),
    seenHandshake: () => false,
  });
  const r = b.e.decrypt({ state: cand, message: m, expectedAd: adFrom(a) });
  return { b, m, r };
}

describe("report disclosure (SPEC §14)", () => {
  it("valid item verifies; wrong key, altered plaintext, altered message fail", () => {
    const { b, m, r } = delivered();
    const d = b.e.buildReportDisclosure([
      {
        envelopeId: "env-1",
        message: m,
        messageKey: r.messageKey,
        plaintext: r.plaintext,
      },
    ]);
    const item = d.items[0]!;
    expect(item.plaintext).toBe("report me ✓");
    expect(b.e.verifyReportDisclosureItem(item)).toBe(true);
    expect(
      b.e.verifyReportDisclosureItem({
        ...item,
        messageKey: b64uEncode(new Uint8Array(32)),
      }),
    ).toBe(false);
    expect(
      b.e.verifyReportDisclosureItem({ ...item, plaintext: "report me ✗" }),
    ).toBe(false);
    expect(
      b.e.verifyReportDisclosureItem({ ...item, plaintext: "report me" }),
    ).toBe(false);
    expect(
      b.e.verifyReportDisclosureItem({
        ...item,
        message: { ...m, header: { ...m.header, n: 1 } },
      }),
    ).toBe(false);
    expect(
      b.e.verifyReportDisclosureItem({ ...item, plaintext: "\ud800" }),
    ).toBe(false);
    expect(b.e.verifyReportDisclosureItem({ ...item, envelopeId: "" })).toBe(
      false,
    );
    expect(b.e.verifyReportDisclosureItem(null as never)).toBe(false);
    expect(
      b.e.verifyReportDisclosureItem({ ...item, message: "{" as never }),
    ).toBe(false);
  });

  it("server canonical-payload rule: only JCS payloads are accepted and digests match", () => {
    const { b, m, r } = delivered();
    const payload = b.e.canonicalJson(m);
    expect(payload === b.e.canonicalJson(b.e.parseMessage(payload))).toBe(true);
    const spaced = JSON.stringify(m, null, 1);
    expect(spaced === b.e.canonicalJson(b.e.parseMessage(spaced))).toBe(false);
    const reordered = JSON.stringify(
      Object.fromEntries(Object.entries(m).reverse()),
    );
    expect(reordered === b.e.canonicalJson(b.e.parseMessage(reordered))).toBe(
      false,
    );
    const dupKey = payload.replace('{"ad":', '{"v":2,"ad":');
    expect(dupKey === b.e.canonicalJson(b.e.parseMessage(dupKey))).toBe(false);
    const item = b.e.buildReportDisclosure([
      {
        envelopeId: "e",
        message: m,
        messageKey: r.messageKey,
        plaintext: r.plaintext,
      },
    ]).items[0]!;
    const enc = new TextEncoder();
    expect(sha256(enc.encode(b.e.canonicalJson(item.message)))).toEqual(
      sha256(enc.encode(payload)),
    );
  });

  it("buildReportDisclosure validates its input", () => {
    const { b, m, r } = delivered();
    const ok = {
      envelopeId: "e",
      message: m,
      messageKey: r.messageKey,
      plaintext: r.plaintext,
    };
    expectCode(() => b.e.buildReportDisclosure([]), "E2EE_INVALID_INPUT");
    expectCode(
      () =>
        b.e.buildReportDisclosure([
          { ...ok, plaintext: Uint8Array.of(0xc0, 0xaf) },
        ]),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        b.e.buildReportDisclosure([{ ...ok, messageKey: new Uint8Array(31) }]),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => b.e.buildReportDisclosure([{ ...ok, envelopeId: "a b" }]),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        b.e.buildReportDisclosure([
          { ...ok, message: { ...m, v: 3 } as never },
        ]),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () => b.e.buildReportDisclosure(null as never),
      "E2EE_INVALID_INPUT",
    );
  });
});
