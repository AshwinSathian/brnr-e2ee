import { readFileSync } from "node:fs";
import { expect } from "vitest";
import { E2eeError, type E2eeErrorCode } from "../src/index.js";

export const hex = (s: string): Uint8Array =>
  Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
export const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export const readJson = <T = unknown>(path: string): T =>
  JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as T;

/** Asserts fn throws E2eeError with the code; returns the error. */
export function expectCode(fn: () => unknown, code: E2eeErrorCode): E2eeError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(E2eeError);
    expect((e as E2eeError).code).toBe(code);
    return e as E2eeError;
  }
  throw new Error(`expected ${code}, nothing thrown`);
}

import { createE2ee, type E2ee, type Rng } from "../src/index.js";
import { drbgRng, type TapeEntry } from "../src/testing.js";

export const T0 = Date.UTC(2026, 9, 22, 12, 0, 0);

/** A test clock that can be moved. */
export function testClock(start = T0) {
  let t = start;
  return {
    now: () => new Date(t),
    set: (ms: number) => {
      t = ms;
    },
    advance: (ms: number) => {
      t += ms;
    },
    get ms() {
      return t;
    },
  };
}

/** Deterministic E2ee: DRBG tape RNG (SPEC §15) seeded from a label, and a movable clock. */
export function makeE2ee(
  label = "default",
  clock = testClock(),
): {
  e: E2ee;
  tape: TapeEntry[];
  clock: ReturnType<typeof testClock>;
  rng: Rng;
} {
  const seed = new Uint8Array(32);
  for (let i = 0; i < label.length; i++)
    seed[i % 32] = (seed[i % 32]! + label.charCodeAt(i)) & 255;
  const { rng, tape } = drbgRng(seed);
  return {
    e: createE2ee({ rng, now: clock.now, dangerouslyAllowTestRng: true }),
    tape,
    clock,
    rng,
  };
}
