/**
 * Closed set of failure codes.
 * Every failure inside the library throws E2eeError with one of these codes.
 */
export type E2eeErrorCode =
  | "E2EE_UNSUPPORTED_VERSION"
  | "E2EE_UNSUPPORTED_SUITE"
  | "E2EE_INVALID_INPUT"
  | "E2EE_INVALID_STATE"
  | "E2EE_INVALID_KEY"
  | "E2EE_BUNDLE_SIGNATURE_INVALID"
  | "E2EE_DEVICE_LIST_INVALID"
  | "E2EE_IDENTITY_MISMATCH"
  | "E2EE_SPK_UNKNOWN"
  | "E2EE_OTP_UNKNOWN"
  | "E2EE_HANDSHAKE_REQUIRED"
  | "E2EE_SESSION_CONFLICT"
  | "E2EE_SKIP_TOO_LARGE"
  | "E2EE_DUPLICATE_MESSAGE"
  | "E2EE_DECRYPT_FAILED"
  | "E2EE_INVALID_PADDING"
  | "E2EE_PLAINTEXT_TOO_LARGE"
  | "E2EE_AD_MISMATCH"
  | "E2EE_RNG_UNAVAILABLE";

export const E2EE_ERROR_CODES: readonly E2eeErrorCode[] = Object.freeze([
  "E2EE_UNSUPPORTED_VERSION",
  "E2EE_UNSUPPORTED_SUITE",
  "E2EE_INVALID_INPUT",
  "E2EE_INVALID_STATE",
  "E2EE_INVALID_KEY",
  "E2EE_BUNDLE_SIGNATURE_INVALID",
  "E2EE_DEVICE_LIST_INVALID",
  "E2EE_IDENTITY_MISMATCH",
  "E2EE_SPK_UNKNOWN",
  "E2EE_OTP_UNKNOWN",
  "E2EE_HANDSHAKE_REQUIRED",
  "E2EE_SESSION_CONFLICT",
  "E2EE_SKIP_TOO_LARGE",
  "E2EE_DUPLICATE_MESSAGE",
  "E2EE_DECRYPT_FAILED",
  "E2EE_INVALID_PADDING",
  "E2EE_PLAINTEXT_TOO_LARGE",
  "E2EE_AD_MISMATCH",
  "E2EE_RNG_UNAVAILABLE",
]);

export class E2eeError extends Error {
  readonly code: E2eeErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(
    code: E2eeErrorCode,
    message?: string,
    details?: Record<string, unknown>,
  ) {
    super(message ?? code);
    this.name = "E2eeError";
    this.code = code;
    if (details !== undefined) this.details = Object.freeze({ ...details });
  }
}

/**
 * True for an E2eeError from this copy of the library, or from another copy (the ESM and CJS builds
 * are separate classes): an object named "E2eeError" whose code is in E2EE_ERROR_CODES. Never throws.
 */
export function isE2eeError(value: unknown): value is E2eeError {
  if (value instanceof E2eeError) return true;
  try {
    // null passes the typeof test and then throws on .name, which gives false below.
    const v = value as { name?: unknown; code?: unknown };
    return (
      typeof value === "object" &&
      v.name === "E2eeError" &&
      (E2EE_ERROR_CODES as readonly unknown[]).includes(v.code)
    );
  } catch {
    return false;
  }
}

/** Internal: throw an E2eeError. Not exported from the package. */
export function fail(
  code: E2eeErrorCode,
  message?: string,
  details?: Record<string, unknown>,
): never {
  throw new E2eeError(code, message, details);
}
