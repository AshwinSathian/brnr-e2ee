// Key generation, signed prekeys and device bundles (SPEC §5.1-§5.4).
import { SUITES } from "./constants.js";
import {
  b64uDecode,
  b64uEncode,
  concat,
  lp,
  ms,
  u32be,
  u64be,
  utf8,
} from "./codec.js";
import { checkDistinct, type Ctx } from "./context.js";
import { fail } from "./errors.js";
import { jcs } from "./jcs.js";
import {
  ed25519PublicKey,
  ed25519PublicKeyValid,
  ed25519Sign,
  ed25519Verify,
  x25519PublicKey,
} from "./primitives.js";
import {
  accountSchema,
  bundleSchema,
  deviceSchema,
  fromJsonText,
  int,
  otpSchema,
  parseStrict,
  readParams,
  spkSchema,
  tryParse,
  suiteList,
} from "./schemas.js";
import { isOpaqueId, isIntIn, MAX_INT } from "./codec.js";
import type {
  AccountIdentityKeyPair,
  DeviceBundleV2,
  DeviceIdentityKeyPair,
  OneTimePrekeyPair,
  SignedPrekeyPair,
} from "./types.js";

/** Decode a field that a schema already validated. */
export const raw = (s: string): Uint8Array => b64uDecode(s) as Uint8Array;

const LABEL_BOXPK = utf8("e2ee/v2/boxpk");
const LABEL_SPK = utf8("e2ee/v2/spk");

/** SPEC §4.2: Ed25519 point check → E2EE_INVALID_KEY. */
export function checkEd25519(pk: string): void {
  if (!ed25519PublicKeyValid(raw(pk)))
    fail("E2EE_INVALID_KEY", "invalid Ed25519 public key");
}

export function parseAccount(x: unknown): AccountIdentityKeyPair {
  const a = parseStrict(accountSchema, x, "state", { v: 1 });
  checkEd25519(a.signPk);
  return a;
}

export function parseDevice(x: unknown): DeviceIdentityKeyPair {
  const d = parseStrict(deviceSchema, x, "state", { v: 1 });
  checkEd25519(d.signPk);
  return d;
}

export const parseSpk = (x: unknown): SignedPrekeyPair =>
  parseStrict(spkSchema, x, "state", { v: 1 });

export const parseOtp = (x: unknown): OneTimePrekeyPair =>
  parseStrict(otpSchema, x, "state", { v: 1 });

export const parseBundle = (x: unknown): DeviceBundleV2 =>
  parseStrict(bundleSchema, fromJsonText(x, "E2EE_INVALID_INPUT"), "wire", {
    v: 2,
  });

export const boxPkSigPayload = (deviceId: string, boxPk: string): Uint8Array =>
  concat(LABEL_BOXPK, lp(utf8(deviceId)), raw(boxPk));

export const spkSigPayload = (
  deviceId: string,
  spkId: number,
  spkPk: string,
  createdAt: string,
  suites: string[],
): Uint8Array =>
  concat(
    LABEL_SPK,
    lp(utf8(deviceId)),
    u32be(spkId),
    raw(spkPk),
    u64be(ms(createdAt)),
    lp(jcs(suites)),
  );

export function generateAccountIdentity(ctx: Ctx): AccountIdentityKeyPair {
  const seed = ctx.draw(32, "seed");
  return {
    v: 1,
    signPk: b64uEncode(ed25519PublicKey(seed)),
    signSk: b64uEncode(seed),
  };
}

export function generateDeviceIdentity(
  ctx: Ctx,
  deviceId: string,
): DeviceIdentityKeyPair {
  if (!isOpaqueId(deviceId)) fail("E2EE_INVALID_INPUT", "invalid deviceId");
  const sign = ctx.draw(32, "seed");
  const box = ctx.draw(32, "seed");
  checkDistinct(sign, box);
  return {
    v: 1,
    deviceId,
    signPk: b64uEncode(ed25519PublicKey(sign)),
    signSk: b64uEncode(sign),
    boxPk: b64uEncode(x25519PublicKey(box)),
    boxSk: b64uEncode(box),
  };
}

export function generateSignedPrekey(
  ctx: Ctx,
  deviceIn: DeviceIdentityKeyPair,
  spkId: number,
  suitesIn: readonly string[] = SUITES,
): SignedPrekeyPair {
  const now = ctx.clock();
  const device = parseDevice(deviceIn);
  if (!int(1).safeParse(spkId).success)
    fail("E2EE_INVALID_INPUT", "invalid spkId");
  const parsed = tryParse(suiteList, suitesIn);
  if (parsed === undefined) return fail("E2EE_INVALID_INPUT", "invalid suites");
  const suites = [...parsed];
  const seed = ctx.draw(32, "seed");
  const pk = b64uEncode(x25519PublicKey(seed));
  const createdAt = now.iso;
  const sig = ed25519Sign(
    raw(device.signSk),
    spkSigPayload(device.deviceId, spkId, pk, createdAt, suites),
  );
  return {
    v: 1,
    spkId,
    pk,
    sk: b64uEncode(seed),
    sig: b64uEncode(sig),
    createdAt,
    suites,
  };
}

export function generateOneTimePrekeys(
  ctx: Ctx,
  first: number,
  count: number,
): OneTimePrekeyPair[] {
  if (
    !isIntIn(first, 1, MAX_INT) ||
    !isIntIn(count, 1, 1000) ||
    first + count - 1 > MAX_INT
  )
    fail("E2EE_INVALID_INPUT", "invalid one-time prekey range");
  const out: OneTimePrekeyPair[] = [];
  let prev: Uint8Array | undefined;
  for (let i = 0; i < count; i++) {
    const seed = ctx.draw(32, "seed");
    if (prev) checkDistinct(prev, seed);
    prev = seed;
    out.push({
      v: 1,
      otpId: first + i,
      pk: b64uEncode(x25519PublicKey(seed)),
      sk: b64uEncode(seed),
    });
  }
  return out;
}

export function buildDeviceBundle(params: {
  device: DeviceIdentityKeyPair;
  spk: SignedPrekeyPair;
}): Omit<DeviceBundleV2, "otp"> {
  const p = readParams(params, ["device", "spk"] as const);
  const device = parseDevice(p.device);
  const spk = parseSpk(p.spk);
  const sig = ed25519Sign(
    raw(device.signSk),
    boxPkSigPayload(device.deviceId, device.boxPk),
  );
  return {
    v: 2,
    suites: [...spk.suites],
    deviceId: device.deviceId,
    deviceSignPk: device.signPk,
    deviceBoxPk: device.boxPk,
    deviceBoxPkSig: b64uEncode(sig),
    spkId: spk.spkId,
    spkPk: spk.pk,
    spkSig: spk.sig,
    createdAt: spk.createdAt,
  };
}

/** SPEC §5.4 verifyDeviceBundle. Returns the parsed bundle. */
export function verifyDeviceBundle(bundleIn: unknown): DeviceBundleV2 {
  const b = parseBundle(bundleIn);
  checkEd25519(b.deviceSignPk);
  const signPk = raw(b.deviceSignPk);
  if (
    !ed25519Verify(
      raw(b.deviceBoxPkSig),
      boxPkSigPayload(b.deviceId, b.deviceBoxPk),
      signPk,
    )
  )
    fail("E2EE_BUNDLE_SIGNATURE_INVALID", "deviceBoxPkSig does not verify");
  if (
    !ed25519Verify(
      raw(b.spkSig),
      spkSigPayload(b.deviceId, b.spkId, b.spkPk, b.createdAt, b.suites),
      signPk,
    )
  )
    fail("E2EE_BUNDLE_SIGNATURE_INVALID", "spkSig does not verify");
  return b;
}
