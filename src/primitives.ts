// The only module that imports @noble/* (SPEC §3, enforced by ESLint).
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import {
  sha256 as nobleSha256,
  sha512 as nobleSha512,
} from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { fail } from "./errors.js";

/** Counted-operation budget units (SPEC §17). Read by the benchmark only. */
export const ops = { kdfCk: 0, hkdf: 0, x25519: 0, aeadOpen: 0 };

export const sha256 = (m: Uint8Array): Uint8Array => nobleSha256(m);
export const sha512 = (m: Uint8Array): Uint8Array => nobleSha512(m);
export const hmacSha256 = (k: Uint8Array, m: Uint8Array): Uint8Array =>
  hmac(nobleSha256, k, m);

export function hkdfSha256(
  salt: Uint8Array,
  ikm: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  ops.hkdf++;
  return hkdf(nobleSha256, ikm, salt, info, length);
}

/** `count = false` for input validation, which the SPEC §17 budget excludes. */
export function x25519PublicKey(sk: Uint8Array, count = true): Uint8Array {
  if (count) ops.x25519++;
  return x25519.getPublicKey(sk);
}

/** X25519 with the SPEC §4.2 check: a low-order peer key or an all-zero result → E2EE_INVALID_KEY. */
export function x25519Dh(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  ops.x25519++;
  let out: Uint8Array;
  try {
    // noble 2.x rejects low-order u-coordinates before the ladder; inputs are 32 bytes here.
    out = x25519.getSharedSecret(sk, pk);
  } catch {
    return fail("E2EE_INVALID_KEY", "X25519 result is all zero");
  }
  // Unreachable with noble 2.4.0, which rejects low-order inputs before the ladder (above).
  // Kept as the SPEC §4.2 all-zero check in case that behaviour changes.
  // Stryker disable all: unreachable, see above
  let acc = 0;
  for (const b of out) acc |= b;
  if (acc === 0) fail("E2EE_INVALID_KEY", "X25519 result is all zero");
  // Stryker restore all
  return out;
}

export const ed25519PublicKey = (seed: Uint8Array): Uint8Array =>
  ed25519.getPublicKey(seed);

export const ed25519Sign = (seed: Uint8Array, msg: Uint8Array): Uint8Array =>
  ed25519.sign(msg, seed);

/** Strict RFC 8032 verification (zip215: false). Never throws. */
export function ed25519Verify(
  sig: Uint8Array,
  msg: Uint8Array,
  pk: Uint8Array,
): boolean {
  try {
    return ed25519.verify(sig, msg, pk, { zip215: false });
  } catch {
    return false;
  }
}

/** SPEC §4.2: the key decodes strictly to a point that is not of small order. */
export function ed25519PublicKeyValid(pk: Uint8Array): boolean {
  try {
    return !ed25519.Point.fromBytes(pk, false).isSmallOrder();
  } catch {
    return false;
  }
}

export function aeadSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

/** Returns null on authentication failure. */
export function aeadOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  ops.aeadOpen++;
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    return null;
  }
}

/** Constant time for equal lengths; lengths are not secret. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= (a[i] as number) ^ (b[i] as number);
  return acc === 0;
}
