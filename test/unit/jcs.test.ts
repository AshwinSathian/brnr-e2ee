import { describe, expect, it } from "vitest";
import { canonicalJson, jcs } from "../../src/jcs.js";
import { expectCode, toHex } from "../helpers.js";

describe("JCS subset (SPEC §4.6, RFC 8785)", () => {
  it("RFC 8785 §3.2.2.2 string serialisation", () => {
    const s = String.fromCharCode(
      0x20ac,
      0x24,
      0x0f,
      0x0a,
      0x41,
      0x27,
      0x42,
      0x22,
      0x5c,
      0x5c,
      0x22,
      0x2f,
    );
    // From the RFC 8785 §3.2.4 bytes for the "string" member.
    expect(toHex(jcs({ string: s }))).toBe(
      "7b22737472696e67223a22e282ac245c7530303066" +
        "5c6e41274" +
        "25c225c5c5c5c5c222f227d",
    );
  });

  it("RFC 8785 §3.2.3 property ordering by UTF-16 code units", () => {
    const o = {
      "€": "Euro Sign",
      "\r": "Carriage Return",
      דּ: "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "😀": "Emoji: Grinning Face",
      "\u0080": "Control",
      ö: "Latin Small Letter O With Diaeresis",
    };
    const values = Object.values(
      JSON.parse(canonicalJson(o)) as Record<string, string>,
    );
    // JSON.parse reorders integer-like keys; check the text order instead.
    const order = [...canonicalJson(o).matchAll(/:"([^"]+)"/g)].map(
      (m) => m[1],
    );
    expect(order).toEqual([
      "Carriage Return",
      "One",
      "Control",
      "Latin Small Letter O With Diaeresis",
      "Euro Sign",
      "Emoji: Grinning Face",
      "Hebrew Letter Dalet With Dagesh",
    ]);
    expect(values).toHaveLength(7);
  });

  it("sorts recursively, keeps array order, omits undefined", () => {
    expect(
      canonicalJson({
        b: [{ d: 1, c: "x" }, 0],
        a: undefined,
        aa: "",
        "": 2147483647,
      }),
    ).toBe('{"":2147483647,"aa":"","b":[{"c":"x","d":1},0]}');
    expect(canonicalJson([])).toBe("[]");
    expect(canonicalJson({})).toBe("{}");
    expect(
      canonicalJson(Object.assign(Object.create(null), { z: "1", y: "2" })),
    ).toBe('{"y":"2","z":"1"}');
  });

  it("rejects values outside the subset", () => {
    for (const v of [
      null,
      true,
      false,
      -1,
      1.5,
      -0,
      2 ** 31,
      NaN,
      Infinity,
      1n,
      undefined,
      [undefined],
      new Uint8Array(1),
      new Date(0),
      { a: null },
      "\ud800",
      { "\udc00": "x" },
      () => 1,
    ])
      expectCode(() => canonicalJson(v), "E2EE_INVALID_INPUT");
  });
});
