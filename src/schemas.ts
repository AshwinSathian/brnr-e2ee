// Strict parsing (SPEC §4.7) and the shared zod building blocks.
import { z } from "zod";
import { LIMITS, SUITES } from "./constants.js";
import {
  b64uDecode,
  decodeX25519Pk,
  isIntIn,
  isOpaqueId,
  isTimestamp,
  MAX_INT,
} from "./codec.js";
import { E2eeError, fail } from "./errors.js";

export type Kind = "wire" | "state";

export const invalidCode = (kind: Kind) =>
  kind === "state" ? "E2EE_INVALID_STATE" : "E2EE_INVALID_INPUT";

export const b64 = (len: number) =>
  z.string().refine((s) => b64uDecode(s, len) !== null, `base64url(${len})`);
/** An X25519 public key: base64url of 32 bytes, canonical (SPEC §4.2). */
export const xpk = z
  .string()
  .refine((s) => decodeX25519Pk(s) !== null, "X25519 public key");
export const id = z.string().refine(isOpaqueId, "opaque id");
export const stamp = z.string().refine(isTimestamp, "timestamp");
export const int = (lo: number, hi: number = MAX_INT) =>
  z.number().refine((x) => isIntIn(x, lo, hi), `integer in [${lo}, ${hi}]`);

const SUITE_RE = /^[a-z0-9-]{1,64}$/;
/** SPEC §5.3: non-empty, unique, ≤ 8 entries, each matching the format rule. */
export const suiteList = z
  .array(z.string().regex(SUITE_RE))
  .min(1)
  .max(8)
  .refine((a) => new Set(a).size === a.length, "duplicate suite");

export const isSuite = (s: unknown): boolean =>
  (SUITES as readonly unknown[]).includes(s);

/** SPEC §4.8: the prototype is Object.prototype or null (a throwing Proxy trap is caught by parseStrict). */
export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

/** Rule 0 for nested structs: every object inside `v` is plain. Run after the schema, so depth and sizes are bounded. */
function plainDeep(v: unknown): boolean {
  if (Array.isArray(v)) return v.every(plainDeep);
  if (typeof v !== "object" || v === null) return true;
  return isPlainObject(v) && Object.values(v).every(plainDeep);
}

interface ParseRules {
  v: number;
  /** Nested structs whose `v` is checked by rule 2, in depth-first key order. */
  nested?: (o: Record<string, unknown>) => Array<[unknown, number]>;
  /** Suite fields checked by rule 3 (messages only). */
  suites?: (o: Record<string, unknown>) => unknown[];
  /** Size caps checked after rule 3 and before the schema walks the input (SPEC §4.7). */
  pre?: (o: Record<string, unknown>) => void;
}

/** A schema, or a choice of schema made from the input after rule 3 (suite-specific shapes, SPEC §6.1). */
type SchemaFor<T> =
  z.ZodType<T> | ((o: Record<string, unknown>) => z.ZodType<T>);

/** SPEC §4.7 rules 0-4, first failure wins. */
export function parseStrict<T>(
  schema: SchemaFor<T>,
  input: unknown,
  kind: Kind,
  rules: ParseRules,
): T {
  try {
    return parseRules(schema, input, kind, rules);
  } catch (e) {
    if (e instanceof E2eeError) throw e;
    // A getter or Proxy on caller input threw while being read (SPEC §4.8).
    return fail(invalidCode(kind), "input could not be read");
  }
}

function parseRules<T>(
  schemaFor: SchemaFor<T>,
  input: unknown,
  kind: Kind,
  rules: ParseRules,
): T {
  if (!isPlainObject(input)) fail(invalidCode(kind), "not an object");
  if (input["v"] !== rules.v)
    fail("E2EE_UNSUPPORTED_VERSION", "unsupported version");
  for (const [nested, v] of rules.nested?.(input) ?? [])
    if (isPlainObject(nested) && nested["v"] !== v)
      fail("E2EE_UNSUPPORTED_VERSION", "unsupported nested version");
  for (const s of rules.suites?.(input) ?? [])
    if (s !== undefined && !isSuite(s))
      fail("E2EE_UNSUPPORTED_SUITE", "unsupported suite");
  rules.pre?.(input);
  const schema = typeof schemaFor === "function" ? schemaFor(input) : schemaFor;
  const r = schema.safeParse(input);
  if (!r.success) {
    const path = (r.error.issues[0] as z.core.$ZodIssue).path.join(".");
    fail(
      invalidCode(kind),
      `invalid ${kind} struct at "${path}"`,
      kind === "wire" ? { path } : undefined,
    );
  }
  // zod reads nested fields through the prototype chain, so check them here (SPEC §4.8).
  if (!plainDeep(input))
    fail(invalidCode(kind), "nested struct is not a plain object");
  return r.data;
}

/** safeParse of caller input; a getter or Proxy trap that throws counts as a failed parse (SPEC §4.8). */
export function tryParse<T>(schema: z.ZodType<T>, x: unknown): T | undefined {
  try {
    const r = schema.safeParse(x);
    return r.success ? r.data : undefined;
  } catch {
    return undefined;
  }
}

/** Copies the named fields of a caller's parameter object; a throwing getter → E2EE_INVALID_INPUT (SPEC §4.8). */
export function readParams<K extends string>(
  params: unknown,
  keys: readonly K[],
): Partial<Record<K, unknown>> {
  const out: Partial<Record<K, unknown>> = {};
  try {
    if (typeof params !== "object" || params === null) return out;
    for (const k of keys) out[k] = (params as Record<K, unknown>)[k];
  } catch {
    fail("E2EE_INVALID_INPUT", "parameters could not be read");
  }
  return out;
}

/** Accepts a parsed object or its JSON text (SPEC §4.7, "String input"). */
export function fromJsonText(
  raw: unknown,
  code: "E2EE_INVALID_INPUT" | "E2EE_INVALID_STATE",
): unknown {
  if (typeof raw !== "string") return raw;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return fail(code, "invalid JSON");
  }
}

// ── Key structs (SPEC §5.2), parsed as state ────────────────────────────────

export const accountSchema = z.strictObject({
  v: z.literal(1),
  signPk: b64(32),
  signSk: b64(32),
});

export const deviceSchema = z.strictObject({
  v: z.literal(1),
  deviceId: id,
  signPk: b64(32),
  signSk: b64(32),
  boxPk: xpk,
  boxSk: b64(32),
});

export const spkSchema = z.strictObject({
  v: z.literal(1),
  spkId: int(1),
  pk: xpk,
  sk: b64(32),
  sig: b64(64),
  createdAt: stamp,
  suites: suiteList,
});

export const otpSchema = z.strictObject({
  v: z.literal(1),
  otpId: int(1),
  pk: xpk,
  sk: b64(32),
});

// ── Device bundle (SPEC §5.4), wire ─────────────────────────────────────────

export const bundleSchema = z.strictObject({
  v: z.literal(2),
  suites: suiteList,
  deviceId: id,
  deviceSignPk: b64(32),
  deviceBoxPk: xpk,
  deviceBoxPkSig: b64(64),
  spkId: int(1),
  spkPk: xpk,
  spkSig: b64(64),
  otp: z.strictObject({ otpId: int(1), pk: xpk }).exactOptional(),
  createdAt: stamp,
});

// ── Messages (SPEC §6.1, §7.3, §7.4, §7.6), wire ────────────────────────────

export const SUITE_V1 = "x25519-xchacha20poly1305-sha256-v1" as const;
export const SUITE_V2 = "x25519-xchacha20poly1305-sha256-v2" as const;

/** SPEC §7.5 buckets. */
export const BUCKETS = [64, 128, 256, 512, 1024, 2048, 4096, 8196] as const;

/** Suite v1 handshake (SPEC §6.1). */
export const handshakeSchemaV1 = z.strictObject({
  v: z.literal(2),
  initiatorBoxPk: xpk,
  initiatorEphPk: xpk,
  spkId: int(1),
  otpId: int(1).exactOptional(),
});

/** Suite v2 handshake (SPEC §6.1): adds the initiator's signing key and the responder it targets. */
export const handshakeSchemaV2 = z.strictObject({
  v: z.literal(2),
  initiatorBoxPk: xpk,
  initiatorSignPk: b64(32),
  initiatorEphPk: xpk,
  responderDeviceId: id,
  responderSignPk: b64(32),
  spkId: int(1),
  otpId: int(1).exactOptional(),
});

/** SPEC §6.1: a handshake with an `initiatorSignPk` key has the suite v2 shape. */
export const isHandshakeV2 = (o: object): boolean =>
  Object.hasOwn(o, "initiatorSignPk");

export const handshakeSchemaFor = (o: object) =>
  isHandshakeV2(o) ? handshakeSchemaV2 : handshakeSchemaV1;

export const adSchemaV1 = z.strictObject({
  conversationId: id,
  senderDeviceId: id,
  suite: z.literal(SUITE_V1),
  v: z.literal(2),
});

export const adSchemaV2 = z.strictObject({
  conversationId: id,
  senderDeviceId: id,
  recipientDeviceId: id,
  suite: z.literal(SUITE_V2),
  v: z.literal(2),
});

export const headerSchema = z.strictObject({
  sid: b64(8),
  dh: xpk,
  pn: int(0, MAX_INT),
  n: int(0, MAX_INT - 1),
});

/** Base64url lengths of B + 16 bytes for each bucket B: a canonical string of one of these decodes to it. */
const CT_LENGTHS = BUCKETS.map((b) => Math.ceil(((b + 16) * 4) / 3));

/** SPEC §7.5 wire check: decoded length is B + 16 for some bucket B, checked on the string first. */
const ciphertext = z
  .string()
  .refine(
    (s) => CT_LENGTHS.includes(s.length) && b64uDecode(s) !== null,
    "ciphertext length",
  );

const messageSchemaOf = <
  S extends string,
  A extends z.ZodType,
  H extends z.ZodType,
>(
  suite: S,
  ad: A,
  handshake: H,
) =>
  z.strictObject({
    v: z.literal(2),
    suite: z.literal(suite),
    header: headerSchema,
    nonce: b64(24),
    ciphertext,
    ad,
    handshake: handshake.exactOptional(),
  });

export const messageSchemaV1 = messageSchemaOf(
  SUITE_V1,
  adSchemaV1,
  handshakeSchemaV1,
);
export const messageSchemaV2 = messageSchemaOf(
  SUITE_V2,
  adSchemaV2,
  handshakeSchemaV2,
);

/** SPEC §4.7 rule 4 for messages: the shape is chosen by `suite`; without a v2 suite it is v1's. */
export const messageSchemaFor = (o: Record<string, unknown>) =>
  o["suite"] === SUITE_V2 ? messageSchemaV2 : messageSchemaV1;

// ── Session state (SPEC §9.1), state ────────────────────────────────────────

export const sessionRecordSchema = z.strictObject({
  sid: b64(8),
  role: z.enum(["initiator", "responder"]),
  founding: z.union([handshakeSchemaV1, handshakeSchemaV2]),
  pending: z.strictObject({ createdAt: stamp }).exactOptional(),
  rk: b64(32),
  dhs: z.strictObject({ pk: xpk, sk: b64(32) }),
  dhr: xpk.exactOptional(),
  cks: b64(32).exactOptional(),
  ckr: b64(32).exactOptional(),
  ns: int(0),
  nr: int(0),
  pn: int(0),
  prevRemoteDh: z.array(xpk).max(64),
  createdAt: stamp,
  lastUsedAt: stamp,
  retiredAt: stamp.exactOptional(),
});

export const stateSchema = z.strictObject({
  v: z.literal(2),
  suite: z.string(),
  conversationId: id,
  selfDeviceId: id,
  peerDeviceId: id,
  selfBoxPk: xpk,
  peerBoxPk: xpk,
  selfSignPk: b64(32).exactOptional(),
  peerSignPk: b64(32).exactOptional(),
  activeSid: b64(8),
  sessions: z.array(sessionRecordSchema).min(1).max(3),
  skipped: z
    .array(
      z.strictObject({
        sid: b64(8),
        dh: xpk,
        keys: z
          .array(z.tuple([int(0), b64(32), stamp]))
          .max(LIMITS.MAX_SKIPPED_KEYS),
      }),
    )
    .max(LIMITS.MAX_SKIPPED_KEYS),
  acceptedHandshakes: z.array(b64(32)).max(32),
  pendingOtpDeletes: z.array(int(1)).max(LIMITS.MAX_PENDING_RECORDS),
  pendingReplayRecords: z
    .array(z.strictObject({ spkId: int(1), hsDigest: b64(32) }))
    .max(LIMITS.MAX_PENDING_RECORDS),
});

export const trackerSchema = z.strictObject({
  v: z.literal(1),
  sightings: z.array(stamp).max(4),
  attempts: int(0),
  lastAt: stamp.exactOptional(),
  window: z.array(stamp).max(3),
  lastRefreshAt: stamp.exactOptional(),
  seenAt: stamp.exactOptional(),
});

// ── Signed device list (SPEC §5.5), wire ────────────────────────────────────

export const deviceListEntrySchema = z.strictObject({
  deviceId: id,
  deviceSignPk: b64(32),
  deviceBoxPk: xpk,
  addedAt: stamp,
  revokedAt: stamp.exactOptional(),
});

export const deviceListSchema = z.strictObject({
  v: z.literal(1),
  accountId: id,
  accountSignPk: b64(32),
  epoch: int(1),
  devices: z.array(deviceListEntrySchema).max(LIMITS.MAX_DEVICES),
  sig: b64(64),
});
