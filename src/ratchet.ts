// Double Ratchet KDFs, message key, AAD and padding (SPEC §7.1, §7.4, §7.5).
import { b64uDecode, concat, u32be, utf8 } from "./codec.js";
import { fail } from "./errors.js";
import { jcs } from "./jcs.js";
import { hkdfSha256, hmacSha256, ops, sha256 } from "./primitives.js";
import { BUCKETS, SUITE_V2 } from "./schemas.js";
import type { AssociatedData, HandshakeV2, MessageHeader } from "./types.js";
import type { SuiteId } from "./constants.js";

const LABEL_RK = utf8("e2ee/v2/rk");
const LABEL_MK = utf8("e2ee/v2/mk");
const LABEL_RK_S2 = utf8("e2ee/s2/rk");
const LABEL_MK_S2 = utf8("e2ee/s2/mk");
const ZERO32 = new Uint8Array(32);
const ONE = Uint8Array.of(1);
const TWO = Uint8Array.of(2);

/** KDF_RK(rk, dh) = HKDF(salt = rk, ikm = dh, "e2ee/v2/rk" (v1) or "e2ee/s2/rk" (v2), 64) split in two. */
export function kdfRk(
  rk: Uint8Array,
  dhOut: Uint8Array,
  suite: SuiteId,
): [Uint8Array, Uint8Array] {
  const out = hkdfSha256(
    rk,
    dhOut,
    suite === SUITE_V2 ? LABEL_RK_S2 : LABEL_RK,
    64,
  );
  return [out.slice(0, 32), out.slice(32, 64)];
}

/** KDF_CK(ck) → (ck', mk). */
export function kdfCk(ck: Uint8Array): [Uint8Array, Uint8Array] {
  ops.kdfCk++;
  return [hmacSha256(ck, TWO), hmacSha256(ck, ONE)];
}

/**
 * mk' = HKDF(0^32, mk, label ‖ SHA-256(JCS(ad) ‖ keys), 32), where the label follows ad.suite and
 * keys are IK_A ‖ IK_B (v1) or IK_A ‖ IK_B ‖ ED_A ‖ ED_B (v2), base64url here.
 */
export function messageKey(
  mk: Uint8Array,
  ad: AssociatedData,
  keys: readonly string[],
): Uint8Array {
  const adHash = sha256(
    concat(jcs(ad), ...keys.map((k) => b64uDecode(k) as Uint8Array)),
  );
  const label = ad.suite === SUITE_V2 ? LABEL_MK_S2 : LABEL_MK;
  return hkdfSha256(ZERO32, mk, concat(label, adHash), 32);
}

/** aad = JCS({ v, suite, ad, header, handshake? }). */
export const aadOf = (m: {
  v: 2;
  suite: SuiteId;
  ad: AssociatedData;
  header: MessageHeader;
  handshake?: HandshakeV2 | undefined;
}): Uint8Array =>
  jcs({
    v: m.v,
    suite: m.suite,
    ad: m.ad,
    header: m.header,
    handshake: m.handshake,
  });

const bucketFor = (n: number): number | undefined =>
  BUCKETS.find((b) => b >= n);

/** pad(p) = u32be(len) ‖ p ‖ 0^(B − 4 − len). No bucket fits a plaintext over 8,192 bytes. */
export function pad(p: Uint8Array): Uint8Array {
  const b = bucketFor(4 + p.length);
  if (b === undefined)
    return fail("E2EE_PLAINTEXT_TOO_LARGE", "plaintext over 8,192 bytes");
  const out = new Uint8Array(b);
  out.set(u32be(p.length), 0);
  out.set(p, 4);
  return out;
}

/** Strict unpad: the length's minimal bucket is exactly this buffer, and the padding is zero. */
export function unpad(b: Uint8Array): Uint8Array {
  // Fewer than 4 bytes read missing bytes as 0, so len = 0 and the 64-byte minimal bucket fails below.
  const len =
    (((b[0] as number) << 24) |
      ((b[1] as number) << 16) |
      ((b[2] as number) << 8) |
      (b[3] as number)) >>>
    0;
  // A length that does not fit gives a larger minimal bucket, so this also rejects it.
  if (bucketFor(4 + len) !== b.length)
    return fail("E2EE_INVALID_PADDING", "invalid padding");
  for (let i = 4 + len; i < b.length; i++)
    if (b[i] !== 0) fail("E2EE_INVALID_PADDING", "invalid padding");
  return b.slice(4, 4 + len);
}
