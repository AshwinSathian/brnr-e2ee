// X3DH (SPEC §6.1-§6.2, X3DH §3).
import { b64uDecode, b64uEncode, concat, lp, utf8 } from "./codec.js";
import { jcs } from "./jcs.js";
import { hkdfSha256, sha256, x25519Dh } from "./primitives.js";
import {
  fromJsonText,
  handshakeSchemaFor,
  messageSchemaFor,
  parseStrict,
  SUITE_V2,
} from "./schemas.js";
import { fail } from "./errors.js";
import type { HandshakeV2, MessageV2 } from "./types.js";
import { LIMITS, type SuiteId } from "./constants.js";

const LABEL_HS = utf8("e2ee/v2/hs-digest");
const LABEL_SID = utf8("e2ee/v2/sid");
const LABEL_X3DH = utf8("e2ee/v2/x3dh");
const LABEL_X3DH_S2 = utf8("e2ee/s2/x3dh");
const FF32 = new Uint8Array(32).fill(0xff);
const ZERO32 = new Uint8Array(32);

const raw = (s: string): Uint8Array => b64uDecode(s) as Uint8Array;

/** hsDigest(h) = b64u(SHA-256("e2ee/v2/hs-digest" ‖ JCS(h))). `h` is already parsed. */
export const hsDigest = (h: HandshakeV2): string =>
  b64uEncode(sha256(concat(LABEL_HS, jcs(h))));

/** sid(h) = b64u(SHA-256("e2ee/v2/sid" ‖ JCS(h))[0..8]). */
export const sidOf = (h: HandshakeV2): string =>
  b64uEncode(sha256(concat(LABEL_SID, jcs(h))).subarray(0, 8));

/** Public handshakeDigest: parses the handshake as a wire struct first (either suite's shape). */
export function handshakeDigest(h: unknown): string {
  return hsDigest(
    parseStrict<unknown>(handshakeSchemaFor, h, "wire", {
      v: 2,
    }) as HandshakeV2,
  );
}

/** A device identity as bound by suite v2 (SPEC §6.2). Keys are base64url. */
export interface DeviceIdentity {
  deviceId: string;
  signPk: string;
  boxPk: string;
}

/** id(X) = lp(UTF-8(deviceId)) ‖ signPk ‖ boxPk. */
const identityBytes = (x: DeviceIdentity): Uint8Array =>
  concat(lp(utf8(x.deviceId)), raw(x.signPk), raw(x.boxPk));

/** X3DH KDF info: v1 "e2ee/v2/x3dh"; v2 "e2ee/s2/x3dh" ‖ id(initiator) ‖ id(responder). */
export function x3dhInfo(
  suite: SuiteId,
  initiator: DeviceIdentity,
  responder: DeviceIdentity,
): Uint8Array {
  return suite === SUITE_V2
    ? concat(LABEL_X3DH_S2, identityBytes(initiator), identityBytes(responder))
    : LABEL_X3DH;
}

/** SK = HKDF(0^32, 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], info, 32). */
export function x3dhSecret(dhs: Uint8Array[], info: Uint8Array): Uint8Array {
  return hkdfSha256(ZERO32, concat(FF32, ...dhs), info, 32);
}

/** Initiator side: DH1 = (IK_A, SPK_B), DH2 = (EK_A, IK_B), DH3 = (EK_A, SPK_B), DH4 = (EK_A, OPK_B). */
export function x3dhInitiator(p: {
  ikA: string;
  ekA: Uint8Array;
  ikB: string;
  spkB: string;
  opkB?: string | undefined;
  info: Uint8Array;
}): Uint8Array {
  const dh = [
    x25519Dh(raw(p.ikA), raw(p.spkB)),
    x25519Dh(p.ekA, raw(p.ikB)),
    x25519Dh(p.ekA, raw(p.spkB)),
  ];
  if (p.opkB !== undefined) dh.push(x25519Dh(p.ekA, raw(p.opkB)));
  return x3dhSecret(dh, p.info);
}

/** Responder side: the mirror values. */
export function x3dhResponder(p: {
  spkSk: string;
  ikSk: string;
  ikA: string;
  ekA: string;
  opkSk?: string | undefined;
  info: Uint8Array;
}): Uint8Array {
  const dh = [
    x25519Dh(raw(p.spkSk), raw(p.ikA)),
    x25519Dh(raw(p.ikSk), raw(p.ekA)),
    x25519Dh(raw(p.spkSk), raw(p.ekA)),
  ];
  if (p.opkSk !== undefined) dh.push(x25519Dh(raw(p.opkSk), raw(p.ekA)));
  return x3dhSecret(dh, p.info);
}

/** SPEC §4.7 parse of MessageV2, plus MAX_WIRE_BYTES. */
export function parseMessage(input: unknown): MessageV2 {
  const m = parseStrict<unknown>(
    messageSchemaFor,
    fromJsonText(input, "E2EE_INVALID_INPUT"),
    "wire",
    {
      v: 2,
      nested: (o) => [
        [o["ad"], 2],
        [o["handshake"], 2],
      ],
      suites: (o) => [
        o["suite"],
        (o["ad"] as Record<string, unknown> | undefined)?.["suite"],
      ],
    },
  ) as MessageV2;
  // Unreachable in suites v1 and v2, whose largest valid messages are 11,712 and 12,142 bytes
  // (vectors/wire-size.json, wire-size-v2.json). Kept because SPEC §4.7 requires the check.
  // Stryker disable all: unreachable, see above
  if (jcs(m).length > LIMITS.MAX_WIRE_BYTES)
    fail("E2EE_INVALID_INPUT", "message over MAX_WIRE_BYTES", { path: "" });
  // Stryker restore all
  return m;
}
