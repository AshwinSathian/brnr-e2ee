// Report disclosure (SPEC §14).
import {
  b64uDecode,
  b64uEncode,
  isOpaqueId,
  utf8DecodeStrict,
  utf8Encode,
  copyBytes,
} from "./codec.js";
import { fail } from "./errors.js";
import { aeadOpen, ctEqual } from "./primitives.js";
import { aadOf, unpad } from "./ratchet.js";
import { readParams } from "./schemas.js";
import type { ReportDisclosureV1 } from "./types.js";
import { parseMessage } from "./x3dh.js";

export function buildReportDisclosure(items: unknown): ReportDisclosureV1 {
  let list: unknown[] = [];
  try {
    if (Array.isArray(items)) list = Array.from(items as unknown[]);
  } catch {
    // A Proxy that throws while being read counts as no items (SPEC §4.8).
  }
  if (list.length < 1)
    return fail("E2EE_INVALID_INPUT", "at least one item is required");
  return {
    v: 1,
    items: list.map((x) => {
      const p = readParams(x, [
        "envelopeId",
        "message",
        "messageKey",
        "plaintext",
      ] as const);
      if (!isOpaqueId(p.envelopeId))
        fail("E2EE_INVALID_INPUT", "invalid envelopeId");
      const message = parseMessage(p.message);
      const key = copyBytes(p.messageKey);
      if (key === null || key.length !== 32)
        return fail("E2EE_INVALID_INPUT", "messageKey must be 32 bytes");
      const bytes = copyBytes(p.plaintext);
      const plaintext = bytes === null ? null : utf8DecodeStrict(bytes);
      if (plaintext === null)
        return fail("E2EE_INVALID_INPUT", "plaintext is not strict UTF-8");
      return {
        envelopeId: p.envelopeId,
        message,
        messageKey: b64uEncode(key),
        plaintext,
      };
    }),
  };
}

/** Never throws (SPEC §14, §4.8). */
export function verifyReportDisclosureItem(item: unknown): boolean {
  try {
    const p = readParams(item, [
      "envelopeId",
      "message",
      "messageKey",
      "plaintext",
    ] as const);
    if (!isOpaqueId(p.envelopeId) || typeof p.plaintext !== "string")
      return false;
    const expected = utf8Encode(p.plaintext);
    const key = b64uDecode(p.messageKey, 32);
    if (expected === null || key === null) return false;
    const m = parseMessage(p.message);
    const padded = aeadOpen(
      key,
      b64uDecode(m.nonce) as Uint8Array,
      b64uDecode(m.ciphertext) as Uint8Array,
      aadOf(m),
    );
    if (padded === null) return false;
    return ctEqual(unpad(padded), expected);
  } catch {
    return false;
  }
}
