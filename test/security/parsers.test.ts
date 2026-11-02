// Parser probes from the adversarial review: canonicalJson against an independent RFC 8785 serialiser
// (property test), and state-parser injection.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../src/jcs.js";
import { E2eeError } from "../../src/index.js";
import { initiate, party, receive, send } from "../parties.js";

const RUNS = Number(process.env["FC_NUM_RUNS"] ?? 1000);

const ESC: Record<number, string> = {
  8: "\\b",
  9: "\\t",
  10: "\\n",
  12: "\\f",
  13: "\\r",
  34: '\\"',
  92: "\\\\",
};

/** RFC 8785 §3.2.2.2 string escaping, written by hand rather than with JSON.stringify. */
function esc(s: string): string {
  let o = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdfff) {
      const d = s.charCodeAt(i + 1);
      if (c > 0xdbff || !(d >= 0xdc00 && d <= 0xdfff)) throw new Error("lone");
      o += s[i]! + s[i + 1]!;
      i++;
    } else if (ESC[c]) o += ESC[c];
    else if (c < 0x20) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += s[i];
  }
  return o + '"';
}

const cmp = (a: string, b: string): number => {
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    if (a.charCodeAt(i) !== b.charCodeAt(i))
      return a.charCodeAt(i) - b.charCodeAt(i);
  return a.length - b.length;
};

function rfc8785(v: unknown): string {
  if (typeof v === "string") return esc(v);
  if (typeof v === "number") {
    if (
      !Number.isSafeInteger(v) ||
      v < 0 ||
      v > 2 ** 31 - 1 ||
      Object.is(v, -0)
    )
      throw new Error("num");
    return String(v);
  }
  if (Array.isArray(v)) return `[${v.map(rfc8785).join(",")}]`;
  if (
    v &&
    typeof v === "object" &&
    [Object.prototype, null].includes(Object.getPrototypeOf(v) as object)
  ) {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort(cmp)
      .map((k) => esc(k) + ":" + rfc8785(o[k]))
      .join(",")}}`;
  }
  throw new Error("type");
}

const str = fc.string({
  unit: fc.oneof(
    fc.constantFrom(
      "\ud800",
      "\udfff",
      " ",
      "\x7f",
      "\x00",
      "\x1f",
      '"',
      "\\",
      "\u{1F600}",
      "￿",
      "é",
      "é",
    ),
    fc.integer({ min: 0, max: 0xffff }).map((c) => String.fromCharCode(c)),
  ),
  maxLength: 6,
});
const val = fc.letrec((tie) => ({
  v: fc.oneof(
    { depthSize: "small", withCrossShrink: true },
    str,
    fc.oneof(
      fc.integer({ min: -2, max: 2 ** 31 + 2 }),
      fc.constantFrom(-0, 1e21, 5e-324, 2 ** 53, 0.5),
    ),
    fc.array(tie("v"), { maxLength: 4 }),
    fc.dictionary(str, tie("v"), { maxKeys: 4 }),
  ),
})).v;

describe("canonicalJson differential", () => {
  it("agrees with an independent RFC 8785 serialiser on accept/reject and bytes", () => {
    fc.assert(
      fc.property(val, (v) => {
        let a: string | Error;
        let b: string | Error;
        try {
          a = canonicalJson(v);
        } catch (e) {
          expect(e).toBeInstanceOf(E2eeError);
          a = e as Error;
        }
        try {
          b = rfc8785(v);
        } catch (e) {
          b = e as Error;
        }
        expect(typeof a).toBe(typeof b);
        if (typeof a === "string") expect(a).toBe(b);
      }),
      { numRuns: RUNS * 10 },
    );
  });
});

describe("state parser injection", () => {
  it("rejects __proto__, extra keys, duplicate sids and a 4th session without polluting prototypes", () => {
    const alice = party("alice");
    const bob = party("bob");
    initiate(bob, alice);
    receive(alice, bob, send(bob, "hi"));
    const ser = alice.e.serializeState(alice.state!);
    const o = JSON.parse(ser) as { sessions: unknown[] };
    const bad = [
      ser.replace(
        '{"acceptedHandshakes"',
        '{"__proto__":{"polluted":1},"acceptedHandshakes"',
      ),
      JSON.stringify({ ...o, extra: 1 }),
      JSON.stringify({ ...o, sessions: [o.sessions[0], o.sessions[0]] }),
      JSON.stringify({ ...o, sessions: Array(4).fill(o.sessions[0]) }),
    ];
    for (const b of bad) expect(() => alice.e.parseState(b)).toThrow(E2eeError);
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });
});
