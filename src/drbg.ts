// HMAC-DRBG (SHA-256, NIST SP 800-90A §10.1.2) for deterministic test tapes (SPEC §15).
// Test-only: exported from brnr-e2ee/testing, never used by the protocol.
import { concat, utf8 } from "./codec.js";
import { hmacSha256 } from "./primitives.js";
import { TEST_RNG } from "./context.js";
import type { Rng, RngPurpose } from "./types.js";

export class HmacDrbg {
  private k: Uint8Array = new Uint8Array(32);
  private v: Uint8Array = new Uint8Array(32).fill(1);

  constructor(
    entropy: Uint8Array,
    nonce: Uint8Array,
    personalization: Uint8Array,
  ) {
    this.update(concat(entropy, nonce, personalization));
  }

  private update(provided: Uint8Array): void {
    this.k = hmacSha256(this.k, concat(this.v, Uint8Array.of(0), provided));
    this.v = hmacSha256(this.k, this.v);
    if (provided.length === 0) return;
    this.k = hmacSha256(this.k, concat(this.v, Uint8Array.of(1), provided));
    this.v = hmacSha256(this.k, this.v);
  }

  generate(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let o = 0; o < n; o += 32) {
      this.v = hmacSha256(this.k, this.v);
      out.set(this.v.subarray(0, Math.min(32, n - o)), o);
    }
    this.update(new Uint8Array(0));
    return out;
  }
}

export interface TapeEntry {
  purpose: RngPurpose;
  bytes: Uint8Array;
}

/** SPEC §15 test RNG (branded: createE2ee needs dangerouslyAllowTestRng): entropy = seed, empty nonce, personalisation "e2ee/v2/test", one Generate per draw. */
export function drbgRng(seed: Uint8Array): { rng: Rng; tape: TapeEntry[] } {
  const d = new HmacDrbg(seed, new Uint8Array(0), utf8("e2ee/v2/test"));
  const tape: TapeEntry[] = [];
  const draw: Rng = (n, purpose) => {
    const bytes = d.generate(n);
    tape.push({ purpose: purpose as RngPurpose, bytes }); // the library always passes a purpose
    return bytes;
  };
  return { rng: Object.assign(draw, { [TEST_RNG]: true }), tape };
}

/** Replays a recorded tape and asserts each draw's purpose and length. */
export function tapeRng(
  tape: readonly TapeEntry[],
): Rng & { remaining(): number } {
  let i = 0;
  const rng = (n: number, purpose?: RngPurpose) => {
    const e = tape[i++];
    if (e === undefined || e.purpose !== purpose || e.bytes.length !== n)
      throw new Error(
        `tape mismatch at draw ${i - 1}: wanted ${String(purpose)}/${n}`,
      );
    return e.bytes;
  };
  return Object.assign(rng, {
    remaining: () => tape.length - i,
    [TEST_RNG]: true,
  });
}
