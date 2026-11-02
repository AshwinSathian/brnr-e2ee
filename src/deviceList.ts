// Signed device lists (SPEC §5.5).
import { LIMITS } from "./constants.js";
import {
  b64uDecode,
  b64uEncode,
  concat,
  isIntIn,
  isOpaqueId,
  MAX_INT,
  ms,
  utf8,
} from "./codec.js";
import { fail } from "./errors.js";
import { jcs } from "./jcs.js";
import { checkEd25519, parseAccount, parseBundle, raw } from "./keys.js";
import { ed25519Sign, ed25519Verify, sha256 } from "./primitives.js";
import {
  deviceListEntrySchema,
  deviceListSchema,
  fromJsonText,
  parseStrict,
  readParams,
  tryParse,
} from "./schemas.js";
import type { SignedDeviceList, SignedDeviceListEntry } from "./types.js";
import { z } from "zod";

const LABEL = utf8("e2ee/v2/device-list");

const invalid = (msg: string): never => fail("E2EE_DEVICE_LIST_INVALID", msg);

/** The entry cap, checked before any schema walks the entries (SPEC §4.7). */
function checkCount(devices: unknown): void {
  let n = 0;
  try {
    n = Array.isArray(devices) ? devices.length : 0;
  } catch {
    // A trapped Proxy; the schema rejects it next.
  }
  if (n > LIMITS.MAX_DEVICES) invalid("entry count");
}

function checkEntries(devices: SignedDeviceListEntry[]): void {
  if (devices.length < 1) invalid("entry count");
  if (new Set(devices.map((d) => d.deviceId)).size !== devices.length)
    invalid("duplicate deviceId");
}

export function parseDeviceList(input: unknown): SignedDeviceList {
  const l = parseStrict(
    deviceListSchema,
    fromJsonText(input, "E2EE_INVALID_INPUT"),
    "wire",
    { v: 1, pre: (o) => checkCount(o["devices"]) },
  ) as SignedDeviceList;
  checkEntries(l.devices);
  return l;
}

/** "e2ee/v2/device-list" ‖ 0x00 ‖ JCS(list without sig). */
const signingBytes = (l: Omit<SignedDeviceList, "sig">): Uint8Array =>
  concat(
    LABEL,
    Uint8Array.of(0),
    jcs({
      v: l.v,
      accountId: l.accountId,
      accountSignPk: l.accountSignPk,
      epoch: l.epoch,
      devices: l.devices,
    }),
  );

/** Steps 2-3: key validity, then revokedAt ≥ addedAt. */
function checkKeysAndDates(l: Omit<SignedDeviceList, "sig">): void {
  checkEd25519(l.accountSignPk);
  for (const d of l.devices) checkEd25519(d.deviceSignPk);
  for (const d of l.devices)
    if (d.revokedAt !== undefined && ms(d.revokedAt) < ms(d.addedAt))
      invalid("revokedAt before addedAt");
}

export function buildSignedDeviceList(params: unknown): SignedDeviceList {
  const p = readParams(params, [
    "account",
    "accountId",
    "epoch",
    "devices",
  ] as const);
  const account = parseAccount(p.account);
  if (!isOpaqueId(p.accountId)) fail("E2EE_INVALID_INPUT", "invalid accountId");
  if (!isIntIn(p.epoch, 1, MAX_INT))
    fail("E2EE_INVALID_INPUT", "invalid epoch");
  checkCount(p.devices);
  const devices = tryParse(
    z.array(deviceListEntrySchema).max(LIMITS.MAX_DEVICES),
    p.devices,
  ) as SignedDeviceListEntry[] | undefined;
  if (devices === undefined)
    return fail("E2EE_INVALID_INPUT", "invalid devices");
  checkEntries(devices);
  const body = {
    v: 1 as const,
    accountId: p.accountId,
    accountSignPk: account.signPk,
    epoch: p.epoch,
    devices,
  };
  checkKeysAndDates(body);
  return {
    ...body,
    sig: b64uEncode(ed25519Sign(raw(account.signSk), signingBytes(body))),
  };
}

export function verifySignedDeviceList(list: unknown, opts?: unknown): void {
  const o = readParams(opts, ["pinnedAccountSignPk", "minEpoch"] as const);
  const pin =
    o.pinnedAccountSignPk === undefined
      ? undefined
      : b64uDecode(o.pinnedAccountSignPk, 32);
  if (pin === null) fail("E2EE_INVALID_INPUT", "invalid pinnedAccountSignPk");
  if (o.minEpoch !== undefined && !isIntIn(o.minEpoch, 1, MAX_INT))
    fail("E2EE_INVALID_INPUT", "invalid minEpoch");
  const l = parseDeviceList(list); // 1
  checkKeysAndDates(l); // 2-3
  if (pin !== undefined && b64uEncode(pin) !== l.accountSignPk)
    fail("E2EE_IDENTITY_MISMATCH", "account key does not match the pin"); // 4
  if (!ed25519Verify(raw(l.sig), signingBytes(l), raw(l.accountSignPk)))
    invalid("signature does not verify"); // 5
  if (l.epoch < ((o.minEpoch as number | undefined) ?? 1))
    invalid("epoch rollback"); // 6
}

export const deviceListDigest = (list: unknown): string =>
  b64uEncode(sha256(signingBytes(parseDeviceList(list))));

export function bundleMatchesDeviceList(
  bundle: unknown,
  list: unknown,
): boolean {
  const b = parseBundle(bundle);
  const l = parseDeviceList(list);
  return l.devices.some(
    (d) =>
      d.revokedAt === undefined &&
      d.deviceId === b.deviceId &&
      d.deviceSignPk === b.deviceSignPk &&
      d.deviceBoxPk === b.deviceBoxPk,
  );
}
