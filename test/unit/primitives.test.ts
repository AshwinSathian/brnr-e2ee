// Known-answer and Wycheproof tests for every primitive binding (D6).
import { describe, expect, it } from "vitest";
import * as p from "../../src/primitives.js";
import { E2eeError } from "../../src/errors.js";
import { hex, readJson, toHex } from "../helpers.js";

interface Kat {
  ed25519_rfc8032: {
    name: string;
    sk: string;
    pk: string;
    msg: string;
    sig: string;
  }[];
  hkdf_rfc5869: {
    ikm: string;
    salt: string;
    info: string;
    L: number;
    okm: string;
  }[];
  hmac_rfc4231: {
    case: number;
    key: string;
    data: string;
    sha256: string;
    sha512: string;
    truncatedTo128: boolean;
  }[];
  x25519_rfc7748: {
    vectors: { scalar: string; u: string; out: string }[];
    iterated: Record<string, string>;
    dh: Record<"a" | "A" | "b" | "B" | "K", string>;
  };
  xchacha_draft03: {
    aead: Record<
      "plaintext" | "aad" | "key" | "nonce" | "ciphertext" | "tag",
      string
    >;
  };
}
const kat = readJson<Kat>("./data/kat.json");

describe("RFC known answers", () => {
  it("X25519 RFC 7748 §5.2 and §6.1", () => {
    for (const v of kat.x25519_rfc7748.vectors)
      expect(toHex(p.x25519Dh(hex(v.scalar), hex(v.u)))).toBe(v.out);
    let k = hex("09".padEnd(64, "0"));
    let u = k;
    for (let i = 1; i <= 1000; i++) {
      [k, u] = [p.x25519Dh(k, u), k];
      if (i === 1) expect(toHex(k)).toBe(kat.x25519_rfc7748.iterated["1"]);
    }
    expect(toHex(k)).toBe(kat.x25519_rfc7748.iterated["1000"]);
    const d = kat.x25519_rfc7748.dh;
    expect(toHex(p.x25519PublicKey(hex(d.a)))).toBe(d.A);
    expect(toHex(p.x25519PublicKey(hex(d.b)))).toBe(d.B);
    expect(toHex(p.x25519Dh(hex(d.a), hex(d.B)))).toBe(d.K);
    expect(toHex(p.x25519Dh(hex(d.b), hex(d.A)))).toBe(d.K);
  });

  it("Ed25519 RFC 8032 §7.1", () => {
    expect(kat.ed25519_rfc8032).toHaveLength(5);
    for (const t of kat.ed25519_rfc8032) {
      expect(toHex(p.ed25519PublicKey(hex(t.sk)))).toBe(t.pk);
      expect(toHex(p.ed25519Sign(hex(t.sk), hex(t.msg)))).toBe(t.sig);
      expect(p.ed25519Verify(hex(t.sig), hex(t.msg), hex(t.pk))).toBe(true);
      expect(p.ed25519PublicKeyValid(hex(t.pk))).toBe(true);
      const bad = hex(t.sig);
      bad[0]! ^= 1;
      expect(p.ed25519Verify(bad, hex(t.msg), hex(t.pk))).toBe(false);
    }
  });

  it("HKDF-SHA256 RFC 5869 A.1-A.3", () => {
    expect(kat.hkdf_rfc5869).toHaveLength(3);
    for (const c of kat.hkdf_rfc5869)
      expect(
        toHex(p.hkdfSha256(hex(c.salt), hex(c.ikm), hex(c.info), c.L)),
      ).toBe(c.okm);
  });

  it("HMAC-SHA256 RFC 4231 §4.2-4.8", () => {
    expect(kat.hmac_rfc4231).toHaveLength(7);
    for (const c of kat.hmac_rfc4231) {
      const out = toHex(p.hmacSha256(hex(c.key), hex(c.data)));
      expect(c.truncatedTo128 ? out.slice(0, 32) : out).toBe(c.sha256);
    }
  });

  it("SHA-256 and SHA-512 (FIPS 180-4 'abc')", () => {
    const abc = Uint8Array.of(0x61, 0x62, 0x63);
    expect(toHex(p.sha256(abc))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(toHex(p.sha512(abc))).toBe(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
  });

  it("XChaCha20-Poly1305 draft-irtf-cfrg-xchacha-03 §A.3.1", () => {
    const v = kat.xchacha_draft03.aead;
    const sealed = p.aeadSeal(
      hex(v.key),
      hex(v.nonce),
      hex(v.plaintext),
      hex(v.aad),
    );
    expect(toHex(sealed)).toBe(v.ciphertext + v.tag);
    expect(
      toHex(p.aeadOpen(hex(v.key), hex(v.nonce), sealed, hex(v.aad))!),
    ).toBe(v.plaintext);
    sealed[0]! ^= 1;
    expect(p.aeadOpen(hex(v.key), hex(v.nonce), sealed, hex(v.aad))).toBeNull();
  });

  it("ctEqual", () => {
    expect(p.ctEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(p.ctEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(p.ctEqual(Uint8Array.of(1), Uint8Array.of(1, 2))).toBe(false);
  });
});

interface Wy<T> {
  numberOfTests: number;
  testGroups: ({ tests: T[] } & Record<string, unknown>)[];
}

describe("Wycheproof (Apache-2.0 test data)", () => {
  it("x25519_test.json", () => {
    const w = readJson<
      Wy<{
        tcId: number;
        public: string;
        private: string;
        shared: string;
        result: string;
        flags: string[];
      }>
    >("./data/wycheproof/x25519_test.json");
    let n = 0;
    for (const g of w.testGroups)
      for (const t of g.tests) {
        n++;
        const run = () => p.x25519Dh(hex(t.private), hex(t.public));
        if (/^0+$/.test(t.shared)) {
          // Low-order public keys: SPEC §4.2 rejects them.
          expect(run).toThrow(E2eeError);
        } else {
          expect(t.result).not.toBe("invalid");
          expect(toHex(run()), `tcId ${t.tcId}`).toBe(t.shared);
        }
      }
    expect(n).toBe(w.numberOfTests);
  });

  it("ed25519_test.json (strict RFC 8032 plus small-order rejection)", () => {
    const w = readJson<
      Wy<{ tcId: number; msg: string; sig: string; result: string }>
    >("./data/wycheproof/ed25519_test.json");
    let n = 0;
    for (const g of w.testGroups) {
      const pk = hex((g["publicKey"] as { pk: string }).pk);
      for (const t of g.tests) {
        n++;
        const ok =
          p.ed25519PublicKeyValid(pk) &&
          p.ed25519Verify(hex(t.sig), hex(t.msg), pk);
        expect(ok, `tcId ${t.tcId}`).toBe(t.result === "valid");
      }
    }
    expect(n).toBe(w.numberOfTests);
  });

  it("xchacha20_poly1305_test.json", () => {
    const w = readJson<
      Wy<{
        tcId: number;
        key: string;
        iv: string;
        aad: string;
        msg: string;
        ct: string;
        tag: string;
        result: string;
      }>
    >("./data/wycheproof/xchacha20_poly1305_test.json");
    let n = 0;
    for (const g of w.testGroups)
      for (const t of g.tests) {
        n++;
        const opened = p.aeadOpen(
          hex(t.key),
          hex(t.iv),
          hex(t.ct + t.tag),
          hex(t.aad),
        );
        if (t.result === "valid") {
          expect(toHex(opened!), `tcId ${t.tcId}`).toBe(t.msg);
          expect(
            toHex(p.aeadSeal(hex(t.key), hex(t.iv), hex(t.msg), hex(t.aad))),
          ).toBe(t.ct + t.tag);
        } else expect(opened, `tcId ${t.tcId}`).toBeNull();
      }
    expect(n).toBe(w.numberOfTests);
  });

  it("small-order Ed25519 keys are rejected (F-13)", () => {
    // Identity point (y = 1) and the order-2 point (y = -1).
    expect(p.ed25519PublicKeyValid(hex("01".padEnd(64, "0")))).toBe(false);
    expect(
      p.ed25519PublicKeyValid(
        hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
      ),
    ).toBe(false);
    // Non-canonical y >= p.
    expect(
      p.ed25519PublicKeyValid(
        hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
      ),
    ).toBe(false);
  });
});
