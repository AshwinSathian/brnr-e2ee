// RFC 8785 restricted to objects, arrays, strings and integers in [0, 2^31−1] (SPEC §4.6).
import { MAX_INT, utf8, utf8Encode } from "./codec.js";
import { E2eeError, fail } from "./errors.js";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  // Stryker disable next-line ConditionalExpression,LogicalOperator: ser() only calls this for non-string, non-number,
  // non-array values; for those, a primitive's or null's prototype test (or its throw, wrapped by canonicalJson)
  // gives the same E2EE_INVALID_INPUT.
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

function str(s: string): string {
  if (utf8Encode(s) === null) fail("E2EE_INVALID_INPUT", "JCS: lone surrogate");
  // For well-formed strings, ECMAScript JSON.stringify is exactly RFC 8785 §3.2.2.2.
  return JSON.stringify(s);
}

const MAX_DEPTH = 32;

function ser(v: unknown, depth = 0): string {
  if (depth > MAX_DEPTH) fail("E2EE_INVALID_INPUT", "JCS: nesting too deep");
  if (typeof v === "string") return str(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0 || v > MAX_INT || Object.is(v, -0))
      fail("E2EE_INVALID_INPUT", "JCS: number out of range");
    return String(v);
  }
  if (Array.isArray(v)) {
    const parts: string[] = [];
    for (let i = 0; i < v.length; i++) {
      if (!(i in v)) fail("E2EE_INVALID_INPUT", "JCS: sparse array");
      parts.push(ser(v[i], depth + 1));
    }
    return `[${parts.join(",")}]`;
  }
  if (isPlainObject(v)) {
    // Each value is read once. Keys sort by UTF-16 code units (keys are unique, so no ties).
    const entries = Object.keys(v)
      .map((k): [string, unknown] => [k, v[k]])
      .filter((e) => e[1] !== undefined)
      .sort((x, y) => (x[0] < y[0] ? -1 : 1));
    return `{${entries.map(([k, x]) => `${str(k)}:${ser(x, depth + 1)}`).join(",")}}`;
  }
  return fail("E2EE_INVALID_INPUT", "JCS: unsupported value");
}

/** JCS text. Throws E2EE_INVALID_INPUT outside the subset. */
export function canonicalJson(value: unknown): string {
  try {
    return ser(value);
  } catch (e) {
    // Stryker disable next-line ConditionalExpression: every inner failure is E2EE_INVALID_INPUT too, so rethrowing or wrapping it is the same
    if (e instanceof E2eeError) throw e;
    // A getter or Proxy trap threw while being read (SPEC §4.8).
    return fail("E2EE_INVALID_INPUT", "JCS: input could not be read");
  }
}

/** UTF-8 bytes of the JCS text. */
export const jcs = (value: unknown): Uint8Array => utf8(ser(value));
