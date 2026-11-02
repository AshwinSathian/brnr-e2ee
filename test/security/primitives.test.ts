// Defences confirmed by the adversarial review (low-order and non-canonical keys, Ed25519 malleability, secrets in outputs).
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { E2eeError } from "../../src/index.js";
import {
  ed25519PublicKeyValid,
  ed25519Verify,
  x25519Dh,
} from "../../src/primitives.js";
import { b64uEncode } from "../../src/codec.js";
import { party, bundleOf } from "../parties.js";

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const le = (n: bigint, len = 32) => {
  const o = new Uint8Array(len);
  for (let i = 0; i < len; i++) o[i] = Number((n >> BigInt(8 * i)) & 255n);
  return o;
};
const fromLe = (b: Uint8Array) =>
  b.reduceRight((a, x) => (a << 8n) | BigInt(x), 0n);
const code = (f: () => unknown) => {
  try {
    f();
    return "OK";
  } catch (e) {
    return e instanceof E2eeError ? e.code : String(e);
  }
};

describe("X25519 low-order / non-canonical peer keys", () => {
  const lowOrder = [
    0n,
    1n,
    325606250916557431795983626356110631294008115727848805560023387167927233504n,
    39382357235489614581723060781553021112529911719440698176882885853963445705823n,
    P - 1n,
    P,
    P + 1n,
  ];
  const sk = new Uint8Array(32).fill(7);
  it("every low-order u, with and without the masked top bit, is rejected", () => {
    for (const u of lowOrder)
      for (const hi of [0n, 2n ** 255n]) {
        const pk = le((u + hi) % 2n ** 256n);
        expect(code(() => x25519Dh(sk, pk))).toBe("E2EE_INVALID_KEY");
      }
  });
});

describe("Ed25519 malleability / small-order keys", () => {
  const seed = new Uint8Array(32).fill(3);
  const pk = ed25519.getPublicKey(seed);
  const msg = new Uint8Array([1, 2, 3]);
  const sig = ed25519.sign(msg, seed);

  it("S + L (malleated) does not verify", () => {
    const s = fromLe(sig.subarray(32));
    const mal = Uint8Array.from(sig);
    mal.set(le(s + L), 32);
    expect(ed25519Verify(sig, msg, pk)).toBe(true);
    expect(ed25519Verify(mal, msg, pk)).toBe(false);
  });

  it("identity public key + (R = identity, S = 0) universal forgery is blocked by the key check", () => {
    const id = le(1n); // encoding of the neutral point
    const forged = new Uint8Array(64);
    forged.set(id, 0);
    // Cofactorless RFC 8032 accepts this for any message; the library relies on ed25519PublicKeyValid.
    expect(ed25519PublicKeyValid(id)).toBe(false);
    const a = party("alice");
    const b = { ...bundleOf(a, false) };
    b.deviceSignPk = b64uEncode(id);
    b.deviceBoxPkSig = b64uEncode(forged);
    b.spkSig = b64uEncode(forged);
    expect(code(() => a.e.verifyDeviceBundle(b))).toBe("E2EE_INVALID_KEY");
  });

  it("non-canonical public key encoding (y + p) is rejected", () => {
    const y = fromLe(pk) & (2n ** 255n - 1n);
    if (y + P < 2n ** 255n) {
      const nc = le((y + P) | (fromLe(pk) & (2n ** 255n)));
      expect(ed25519PublicKeyValid(nc)).toBe(false);
    }
    // y = 1 + p (non-canonical identity) must also fail
    expect(ed25519PublicKeyValid(le(P + 1n))).toBe(false);
  });
});

describe("secrets in inspectSession / errors", () => {
  it("inspectSession output carries no key material", () => {
    const a = party("alice");
    const b = party("bob");
    const st = a.e.initiateSession({
      conversationId: "conv-1",
      self: a.device,
      peerBundle: bundleOf(b),
    });
    const json = JSON.stringify(a.e.inspectSession(st));
    const ser = JSON.stringify(st);
    for (const m of ser.matchAll(/"[A-Za-z0-9_-]{43}"/g))
      expect(json.includes(m[0])).toBe(false);
  });

  it("a corrupted state error reports only a path, never the value", () => {
    const a = party("alice");
    const b = party("bob");
    const r = a.e.initiateSession({
      conversationId: "conv-1",
      self: a.device,
      peerBundle: bundleOf(b),
    });
    const s = JSON.parse(JSON.stringify(r));
    const secret = s.sessions[0].rk as string;
    s.sessions[0].rk = secret + "!";
    try {
      a.e.inspectSession(s);
      throw new Error("accepted");
    } catch (e) {
      const blob = JSON.stringify({
        m: (e as Error).message,
        d: (e as E2eeError).details,
        s: (e as Error).stack,
      });
      expect(blob.includes(secret)).toBe(false);
    }
  });
});
