// Safety numbers (SPEC §12): written from the libsignal displayable-fingerprint description only.
import { LIMITS } from "./constants.js";
import { b64uDecode, concat, isStableId, u16be, utf8 } from "./codec.js";
import { fail } from "./errors.js";
import { ctEqual, ed25519PublicKeyValid, sha512 } from "./primitives.js";
import { readParams } from "./schemas.js";
import type { SafetyNumber } from "./types.js";

/** h = SHA-512(u16be(0) ‖ key ‖ stableId ‖ key), then h = SHA-512(h ‖ key), `iterations` hashes in total. */
export function chain(
  key: Uint8Array,
  stableId: string,
  iterations: number = LIMITS.FINGERPRINT_ITERATIONS,
): Uint8Array {
  let h = sha512(concat(u16be(0), key, utf8(stableId), key));
  for (let i = 1; i < iterations; i++) h = sha512(concat(h, key));
  return h;
}

/** Six 5-byte big-endian chunks of fp[0..30], each mod 100,000, zero-padded. */
export function digits30(fp: Uint8Array): string {
  let out = "";
  for (let i = 0; i < 6; i++) {
    let c = 0;
    for (let k = 0; k < 5; k++) c = c * 256 + (fp[5 * i + k] as number);
    out += String(c % 100000).padStart(5, "0");
  }
  return out;
}

function party(x: unknown): Uint8Array {
  const p = readParams(x, ["accountSignPk", "stableId"] as const);
  const key = b64uDecode(p.accountSignPk, 32);
  if (key === null) return fail("E2EE_INVALID_INPUT", "invalid accountSignPk");
  if (!ed25519PublicKeyValid(key))
    fail("E2EE_INVALID_KEY", "invalid Ed25519 public key");
  if (!isStableId(p.stableId)) fail("E2EE_INVALID_INPUT", "invalid stableId");
  return chain(key, p.stableId).slice(0, 32);
}

export function computeSafetyNumber(params: unknown): SafetyNumber {
  const p = readParams(params, ["local", "remote"] as const);
  const local = party(p.local);
  const remote = party(p.remote);
  const [l, r] = [digits30(local), digits30(remote)];
  // Stryker disable next-line EqualityOperator: equal halves give the same digits either way
  const digits = l < r ? l + r : r + l;
  return {
    digits,
    groups: digits.match(/.{5}/g) as string[],
    qrPayload: concat(u16be(LIMITS.SAFETY_NUMBER_VERSION), local, remote),
  };
}

/** Never throws (SPEC §4.8). True iff the peer's payload mirrors ours. */
export function verifySafetyNumberPayload(
  local: unknown,
  scanned: unknown,
): boolean {
  try {
    const q = (local as SafetyNumber).qrPayload; // null or undefined throws → false below
    if (
      !(q instanceof Uint8Array) ||
      q.length !== 66 ||
      !(scanned instanceof Uint8Array) ||
      scanned.length !== 66
    )
      return false;
    const version = (b: Uint8Array) =>
      ((b[0] as number) << 8) | (b[1] as number);
    if (
      version(scanned) !== LIMITS.SAFETY_NUMBER_VERSION ||
      version(q) !== LIMITS.SAFETY_NUMBER_VERSION ||
      ctEqual(scanned, q)
    )
      return false;
    const a = ctEqual(scanned.subarray(2, 34), q.subarray(34, 66));
    const b = ctEqual(scanned.subarray(34, 66), q.subarray(2, 34));
    return a && b;
  } catch {
    return false;
  }
}
