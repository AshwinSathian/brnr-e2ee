// Device-link ceremony (SPEC §13).
import {
  b64uDecode,
  b64uEncode,
  concat,
  decodeX25519Pk,
  isOpaqueId,
  lp,
  utf8,
  utf8DecodeStrict,
} from "./codec.js";
import type { Ctx } from "./context.js";
import { fail } from "./errors.js";
import { jcs } from "./jcs.js";
import { parseAccount } from "./keys.js";
import {
  aeadOpen,
  aeadSeal,
  ctEqual,
  ed25519PublicKey,
  ed25519PublicKeyValid,
  hkdfSha256,
  sha256,
  x25519Dh,
  x25519PublicKey,
} from "./primitives.js";
import { b64, readParams, suiteList, tryParse, xpk } from "./schemas.js";
import type { AccountIdentityKeyPair } from "./types.js";
import { z } from "zod";

const L_TRANSCRIPT = utf8("e2ee/v2/link-transcript");
const L_COMMIT = utf8("e2ee/v2/link-commit");
const L_CODE = utf8("e2ee/v2/link-code");
const L_SEAL = utf8("e2ee/v2/link-seal");

const ephSchema = z.strictObject({ pk: xpk, sk: b64(32) });

function key32(x: unknown, what: string): Uint8Array {
  const k = b64uDecode(x, 32);
  if (k === null) return fail("E2EE_INVALID_INPUT", `invalid ${what}`);
  return k;
}

/** An X25519 public key parameter (SPEC §4.2). */
function xkey(x: unknown, what: string): Uint8Array {
  const k = decodeX25519Pk(x);
  if (k === null) return fail("E2EE_INVALID_INPUT", `invalid ${what}`);
  return k;
}

export function generateLinkEphemeral(ctx: Ctx): { pk: string; sk: string } {
  const seed = ctx.draw(32, "seed");
  return { pk: b64uEncode(x25519PublicKey(seed)), sk: b64uEncode(seed) };
}

export const generateLinkRequestId = (ctx: Ctx): string =>
  b64uEncode(ctx.draw(16, "link-request"));

export function linkTranscript(params: unknown): string {
  const p = readParams(params, [
    "requestId",
    "accountId",
    "newDeviceId",
    "newDeviceSignPk",
    "newDeviceBoxPk",
    "suites",
  ] as const);
  for (const k of ["requestId", "accountId", "newDeviceId"] as const)
    if (!isOpaqueId(p[k])) fail("E2EE_INVALID_INPUT", `invalid ${k}`);
  const signPk = key32(p.newDeviceSignPk, "newDeviceSignPk");
  if (!ed25519PublicKeyValid(signPk))
    fail("E2EE_INVALID_KEY", "invalid Ed25519 public key");
  const boxPk = xkey(p.newDeviceBoxPk, "newDeviceBoxPk");
  const suites = tryParse(suiteList, p.suites);
  if (suites === undefined) return fail("E2EE_INVALID_INPUT", "invalid suites");
  return b64uEncode(
    sha256(
      concat(
        L_TRANSCRIPT,
        lp(utf8(p.requestId as string)),
        lp(utf8(p.accountId as string)),
        lp(utf8(p.newDeviceId as string)),
        signPk,
        boxPk,
        lp(jcs(suites)),
      ),
    ),
  );
}

const commitment = (t: Uint8Array, ephNew: Uint8Array): Uint8Array =>
  sha256(concat(L_COMMIT, t, ephNew));

export const linkCommitment = (
  transcript: unknown,
  ephNewPk: unknown,
): string =>
  b64uEncode(
    commitment(key32(transcript, "transcript"), xkey(ephNewPk, "ephNewPk")),
  );

/** Never throws (SPEC §4.8). */
export function verifyLinkCommitment(
  c: unknown,
  transcript: unknown,
  ephNewPk: unknown,
): boolean {
  const cb = b64uDecode(c, 32);
  const t = b64uDecode(transcript, 32);
  const e = decodeX25519Pk(ephNewPk);
  if (cb === null || t === null || e === null) return false;
  return ctEqual(cb, commitment(t, e));
}

export function linkConfirmationCode(params: unknown): string {
  const p = readParams(params, ["transcript", "ephNewPk", "ephOldPk"] as const);
  const t = key32(p.transcript, "transcript");
  const n = xkey(p.ephNewPk, "ephNewPk");
  const o = xkey(p.ephOldPk, "ephOldPk");
  const out = hkdfSha256(t, concat(n, o), L_CODE, 4);
  const v =
    ((out[0] as number) * 2 ** 24 +
      (out[1] as number) * 2 ** 16 +
      (out[2] as number) * 2 ** 8 +
      (out[3] as number)) %
    1_000_000;
  return String(v).padStart(6, "0");
}

interface SealParams {
  t: Uint8Array;
  self: { pk: string; sk: string };
  peer: Uint8Array;
}

function sealParams(
  p: Partial<Record<"transcript" | "ephSelf" | "ephPeerPk", unknown>>,
): SealParams {
  const t = key32(p.transcript, "transcript");
  let r;
  try {
    r = ephSchema.safeParse(p.ephSelf);
  } catch {
    r = undefined;
  }
  if (!r?.success) return fail("E2EE_INVALID_STATE", "invalid ephSelf");
  const self = r.data;
  return { t, self, peer: xkey(p.ephPeerPk, "ephPeerPk") };
}

const sealKey = (s: SealParams): Uint8Array =>
  hkdfSha256(
    s.t,
    x25519Dh(b64uDecode(s.self.sk) as Uint8Array, s.peer),
    L_SEAL,
    32,
  );

export function sealAccountKey(ctx: Ctx, params: unknown): string {
  const p = readParams(params, [
    "account",
    "transcript",
    "ephSelf",
    "ephPeerPk",
  ] as const);
  const account = parseAccount(p.account);
  const s = sealParams(p);
  const key = sealKey(s);
  const nonce = ctx.draw(24, "nonce");
  // Sealer is the old device: aad = T ‖ ephOld ‖ ephNew.
  const aad = concat(s.t, b64uDecode(s.self.pk) as Uint8Array, s.peer);
  return b64uEncode(concat(nonce, aeadSeal(key, nonce, jcs(account), aad)));
}

export function openAccountKey(params: unknown): AccountIdentityKeyPair {
  const p = readParams(params, [
    "sealed",
    "transcript",
    "ephSelf",
    "ephPeerPk",
  ] as const);
  const sealed = b64uDecode(p.sealed);
  if (sealed === null || sealed.length < 24 + 16)
    return fail("E2EE_INVALID_INPUT", "invalid sealed");
  const s = sealParams(p);
  // Opener is the new device: aad = T ‖ ephOld (peer) ‖ ephNew (self).
  const aad = concat(s.t, s.peer, b64uDecode(s.self.pk) as Uint8Array);
  const pt = aeadOpen(
    sealKey(s),
    sealed.subarray(0, 24),
    sealed.subarray(24),
    aad,
  );
  if (pt === null)
    return fail("E2EE_DECRYPT_FAILED", "link seal authentication failed");
  let account: AccountIdentityKeyPair;
  try {
    // Invalid UTF-8 gives "", which JSON.parse rejects.
    account = parseAccount(JSON.parse(utf8DecodeStrict(pt) ?? ""));
  } catch {
    return fail("E2EE_INVALID_INPUT", "invalid account key");
  }
  if (
    b64uEncode(ed25519PublicKey(b64uDecode(account.signSk) as Uint8Array)) !==
    account.signPk
  )
    fail("E2EE_INVALID_INPUT", "account key pair is inconsistent");
  return account;
}
