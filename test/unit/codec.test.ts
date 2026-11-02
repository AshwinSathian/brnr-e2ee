import { describe, expect, it } from "vitest";
import * as c from "../../src/codec.js";
import { toHex } from "../helpers.js";

describe("base64url (SPEC §4.1)", () => {
  it("round-trips every length", () => {
    for (let n = 0; n < 70; n++) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
      const s = c.b64uEncode(b);
      expect(s).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(c.b64uDecode(s)).toEqual(b);
    }
  });
  it("matches RFC 4648 §10 (base64url form)", () => {
    const t: [string, string][] = [
      ["", ""],
      ["f", "Zg"],
      ["fo", "Zm8"],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg"],
      ["fooba", "Zm9vYmE"],
      ["foobar", "Zm9vYmFy"],
    ];
    for (const [plain, enc] of t) expect(c.b64uEncode(c.utf8(plain))).toBe(enc);
    expect(c.b64uEncode(Uint8Array.of(0xfb, 0xff))).toBe("-_8");
  });
  it("rejects padding, bad characters, bad length and non-zero trailing bits", () => {
    for (const s of [
      "Zg==",
      "Zg=",
      "Z",
      "Zm9v+A",
      "Zm9v/A",
      "Zh",
      "Zm9",
      "Zm8 ",
      "Zm9vYg\n",
      "Zm-é",
    ])
      expect(c.b64uDecode(s), s).toBeNull();
    expect(c.b64uDecode("Zm8")).not.toBeNull();
    expect(c.b64uDecode(42)).toBeNull();
  });
  it("enforces exact length", () => {
    const k = c.b64uEncode(new Uint8Array(32));
    expect(c.b64uDecode(k, 32)).toHaveLength(32);
    expect(c.b64uDecode(k, 31)).toBeNull();
  });
});

describe("integers and lp", () => {
  it("encodes big-endian", () => {
    expect(toHex(c.u16be(0x1234))).toBe("1234");
    expect(toHex(c.u32be(0xdeadbeef))).toBe("deadbeef");
    expect(toHex(c.u64be(2 ** 53 - 1))).toBe("001fffffffffffff");
    expect(toHex(c.u64be(0x0102030405))).toBe("0000000102030405");
    expect(toHex(c.lp(Uint8Array.of(1, 2, 3)))).toBe("0003010203");
    expect(() => c.lp(new Uint8Array(65536))).toThrow();
  });
  it("compares bytes lexicographically", () => {
    expect(c.compareBytes(Uint8Array.of(1), Uint8Array.of(1, 0))).toBeLessThan(
      0,
    );
    expect(
      c.compareBytes(Uint8Array.of(2), Uint8Array.of(1, 9)),
    ).toBeGreaterThan(0);
  });
  it("checks integer ranges", () => {
    expect(c.isIntIn(0, 0, c.MAX_INT)).toBe(true);
    expect(c.isIntIn(c.MAX_INT + 1, 0, c.MAX_INT)).toBe(false);
    expect(c.isIntIn(1.5, 0, 9)).toBe(false);
    expect(c.isIntIn("1", 0, 9)).toBe(false);
    expect(c.isIntIn(-1, 0, 9)).toBe(false);
  });
});

describe("ids (SPEC §4.3)", () => {
  it("opaque ids", () => {
    expect(c.isOpaqueId("a")).toBe(true);
    expect(c.isOpaqueId("A-z_0.9:x")).toBe(true);
    expect(c.isOpaqueId("x".repeat(128))).toBe(true);
    for (const s of ["", "x".repeat(129), "a b", "é", "a/b", 5])
      expect(c.isOpaqueId(s)).toBe(false);
  });
  it("stable ids", () => {
    expect(c.isStableId("+14152222222")).toBe(true);
    expect(c.isStableId("é".repeat(128))).toBe(true);
    expect(c.isStableId("é".repeat(129))).toBe(false);
    expect(c.isStableId("")).toBe(false);
    expect(c.isStableId("\ud800")).toBe(false);
  });
});

describe("UTF-8", () => {
  it("encodes and strictly decodes", () => {
    for (const s of ["", "abc", "é", "€", "😀", "a\u0000b"]) {
      const b = c.utf8Encode(s)!;
      expect(Buffer.from(b).toString("utf8")).toBe(s);
      expect(c.utf8DecodeStrict(b)).toBe(s);
    }
    expect(c.utf8Encode("\udc00")).toBeNull();
    expect(c.utf8Encode("\ud800x")).toBeNull();
    expect(() => c.utf8("\ud800")).toThrow();
  });
  it("rejects malformed UTF-8", () => {
    for (const h of [
      "80",
      "c0af",
      "c1bf",
      "e080af",
      "eda080",
      "f4908080",
      "f5",
      "e282",
      "c3",
      "ff",
      "f0808080",
    ])
      expect(
        c.utf8DecodeStrict(
          Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16)),
        ),
        h,
      ).toBeNull();
  });
});

describe("timestamps (SPEC §4.5, F-5)", () => {
  it("accepts valid stamps", () => {
    expect(c.parseTimestamp("2026-10-22T00:00:00.000Z")).toBe(
      Date.UTC(2026, 9, 22),
    );
    expect(c.isTimestamp("2000-02-29T23:59:59.999Z")).toBe(true);
    expect(c.isTimestamp("2024-02-29T00:00:00.000Z")).toBe(true);
    expect(c.isTimestamp("9999-12-31T23:59:59.999Z")).toBe(true);
    expect(c.isTimestamp("2000-01-01T00:00:00.000Z")).toBe(true);
  });
  it("rejects invalid stamps", () => {
    for (const s of [
      "1969-02-30T00:00:00.000Z",
      "2026-02-30T00:00:00.000Z",
      "2100-02-29T00:00:00.000Z",
      "2026-04-31T00:00:00.000Z",
      "2016-12-31T23:59:60.000Z",
      "1999-12-31T23:59:59.999Z",
      "2026-13-01T00:00:00.000Z",
      "2026-00-01T00:00:00.000Z",
      "2026-01-00T00:00:00.000Z",
      "2026-01-01T24:00:00.000Z",
      "2026-01-01T00:60:00.000Z",
      "2026-01-01T00:00:00Z",
      "2026-01-01T00:00:00.000+00:00",
      "2026-01-01 00:00:00.000Z",
      "+02026-01-01T00:00:00.000Z",
      "２026-01-01T00:00:00.000Z",
      0,
    ])
      expect(c.parseTimestamp(s), String(s)).toBeNull();
  });
});
