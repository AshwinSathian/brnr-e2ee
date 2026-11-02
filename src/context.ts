// Injected randomness and clock (SPEC §15, §4.8).
import { iso, parseTimestamp } from "./codec.js";
import { fail } from "./errors.js";
import { ctEqual } from "./primitives.js";
import { readParams } from "./schemas.js";
import type { E2eeOptions, Rng, RngPurpose } from "./types.js";

export interface Ctx {
  draw(n: number, purpose: RngPurpose): Uint8Array;
  /** Reads the clock once (SPEC §4.8). */
  clock(): Clock;
}

export interface Clock {
  ms: number;
  iso: string;
}

type GetRandomValues = (a: Uint8Array) => Uint8Array;

/** Brand on the brnr-e2ee/testing RNGs (SPEC §15). Symbol.for, so the ESM and CJS builds agree. */
export const TEST_RNG = Symbol.for("brnr-e2ee/test-rng");

function isTestRng(rng: unknown): boolean {
  try {
    return (
      (rng as Record<symbol, unknown> | null | undefined)?.[TEST_RNG] === true
    );
  } catch {
    return false; // a trapped Proxy is no test RNG; its draws are checked as usual
  }
}

/** SPEC §15: two seeds drawn back to back must differ. */
export function checkDistinct(a: Uint8Array, b: Uint8Array): void {
  if (ctEqual(a, b)) fail("E2EE_RNG_UNAVAILABLE", "RNG repeated a draw");
}

export function createCtx(opts: E2eeOptions | undefined): Ctx {
  if (opts != null && typeof opts !== "object")
    fail("E2EE_INVALID_INPUT", "options must be an object");
  // null rng or now means absent (SPEC §4.8), hence ?? below.
  const o = readParams(opts, [
    "rng",
    "now",
    "dangerouslyAllowTestRng",
  ] as const);
  // The default RNG is captured now, so a later polyfill cannot slip in unchecked. If it is missing,
  // the first draw throws and the health check below fails.
  const c = (globalThis as { crypto?: { getRandomValues?: GetRandomValues } })
    .crypto;
  const grv = c?.getRandomValues;
  const rng = (o.rng ??
    ((n: number) =>
      (grv as GetRandomValues).call(c, new Uint8Array(n)))) as Rng;
  const now = (o.now ?? (() => new Date())) as () => Date;
  if (typeof now !== "function")
    fail("E2EE_INVALID_INPUT", "now is not a function");
  if (isTestRng(o.rng) && o.dangerouslyAllowTestRng !== true)
    fail("E2EE_RNG_UNAVAILABLE", "test RNG without dangerouslyAllowTestRng");

  const draw = (n: number, purpose: RngPurpose): Uint8Array => {
    let r: unknown;
    try {
      r = rng(n, purpose);
    } catch {
      // A missing or throwing RNG fails the check below.
    }
    let copy: Uint8Array | undefined;
    try {
      if (r instanceof Uint8Array && r.length === n) copy = Uint8Array.from(r);
    } catch {
      // A Proxy with a throwing iterator fails the check below.
    }
    if (copy === undefined)
      return fail("E2EE_RNG_UNAVAILABLE", "RNG returned the wrong value");
    return copy;
  };

  const clock = (): Clock => {
    const d = now(); // caller exceptions propagate (SPEC §4.8)
    let t = NaN;
    try {
      t = Date.prototype.getTime.call(d); // throws for a non-Date, even one that passes instanceof
    } catch {
      // t stays NaN
    }
    if (!Number.isFinite(t)) return fail("E2EE_INVALID_INPUT", "invalid clock");
    const s = iso(t);
    if (parseTimestamp(s) !== t)
      fail("E2EE_INVALID_INPUT", "clock outside the timestamp range");
    return { ms: t, iso: s };
  };

  // Health check (SPEC §15): two 32-byte draws, neither all zero, and different.
  const a = draw(32, "health");
  const b = draw(32, "health");
  const zero = (x: Uint8Array) => x.every((v) => v === 0);
  if (zero(a) || zero(b) || a.every((v, i) => v === b[i]))
    fail("E2EE_RNG_UNAVAILABLE", "RNG health check failed");

  return { draw, clock };
}
