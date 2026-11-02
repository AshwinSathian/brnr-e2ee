/**
 * Suite identifiers (SPEC §5.4, §6.5). v2 binds both devices' identities into the session; v1 is kept
 * for peers that have not upgraded.
 */
export type SuiteId =
  "x25519-xchacha20poly1305-sha256-v2" | "x25519-xchacha20poly1305-sha256-v1";

/** Preferred first: generateSignedPrekey offers these by default. */
export const SUITES: readonly SuiteId[] = Object.freeze([
  "x25519-xchacha20poly1305-sha256-v2",
  "x25519-xchacha20poly1305-sha256-v1",
]);

/**
 * Limits. Changing any value is a new suite.
 * Keys after SAFETY_NUMBER_VERSION are additive and do not change the wire format.
 */
export const LIMITS = Object.freeze({
  MAX_PLAINTEXT_BYTES: 8192,
  PADDING_BUCKETS: Object.freeze([
    64,
    128,
    256,
    512,
    1024,
    2048,
    4096,
    8192 + 4,
  ] as const),
  MAX_WIRE_BYTES: 12288,
  MAX_SKIP: 1000,
  /** Total stored skipped keys per state, across all of its sessions. */
  MAX_SKIPPED_KEYS: 2000,
  SKIPPED_KEY_TTL_MS: 30 * 24 * 60 * 60 * 1000,
  FINGERPRINT_ITERATIONS: 5200,
  SAFETY_NUMBER_DIGITS: 60,
  SAFETY_NUMBER_VERSION: 1,
  /** Live sessions per state: one active plus up to two others. */
  MAX_SESSIONS: 3,
  /** Per-state FIFO of accepted handshake digests. */
  MAX_ACCEPTED_HANDSHAKES: 32,
  /** Remote ratchet keys remembered per session for duplicate detection. */
  MAX_PREV_REMOTE_DH: 64,
  /** Opaque ids: 1..128 bytes of [A-Za-z0-9._:-]. */
  MAX_ID_BYTES: 128,
  /** stableId for fingerprints: 1..256 bytes of UTF-8. */
  MAX_STABLE_ID_BYTES: 256,
  /** Largest integer accepted for counters and ids (Postgres int4). */
  MAX_INT: 2 ** 31 - 1,
  /** Recovery re-initiations allowed per conversation per 24 h. */
  MAX_RECOVERIES_PER_DAY: 3,
  /** Minimum spacing for a second sighting, and the standing-sighting delay. */
  RECOVERY_SIGHTING_MS: 10 * 60 * 1000,
  /** Clock tolerance before a future stamp is re-stamped. */
  FUTURE_STAMP_TOLERANCE_MS: 24 * 60 * 60 * 1000,
  /** Device-list entries (SPEC §5.5). */
  MAX_DEVICES: 64,
  /** Suite ids in a bundle or SPK (SPEC §5.3). */
  MAX_SUITES: 8,
  /** Recovery backoff: base doubling from 1 h, capped at 24 h (SPEC §8.4). */
  RECOVERY_BACKOFF_BASE_MS: 60 * 60 * 1000,
  RECOVERY_BACKOFF_MAX_MS: 24 * 60 * 60 * 1000,
  /** At most one refresh re-initiation per this interval (SPEC §8.4). */
  REFRESH_INTERVAL_MS: 24 * 60 * 60 * 1000,
  /** A retired session still decrypts for this long, then is deleted (SPEC §8.1). Local state only. */
  RETIRED_SESSION_TTL_MS: 48 * 60 * 60 * 1000,
  /** pendingOtpDeletes and pendingReplayRecords entries per state (SPEC §9.1). Local state only. */
  MAX_PENDING_RECORDS: 256,
});
