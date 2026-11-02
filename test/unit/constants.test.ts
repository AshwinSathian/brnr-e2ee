// SPEC §17: every limit is pinned to its specified value; changing one is a new suite.
import { expect, it } from "vitest";
import { LIMITS, SUITES } from "../../src/index.js";

it("LIMITS match SPEC §17", () => {
  const H = 60 * 60 * 1000;
  expect({ ...LIMITS, PADDING_BUCKETS: [...LIMITS.PADDING_BUCKETS] }).toEqual({
    MAX_PLAINTEXT_BYTES: 8192,
    PADDING_BUCKETS: [64, 128, 256, 512, 1024, 2048, 4096, 8196],
    MAX_WIRE_BYTES: 12288,
    MAX_SKIP: 1000,
    MAX_SKIPPED_KEYS: 2000,
    SKIPPED_KEY_TTL_MS: 30 * 24 * H,
    FINGERPRINT_ITERATIONS: 5200,
    SAFETY_NUMBER_DIGITS: 60,
    SAFETY_NUMBER_VERSION: 1,
    MAX_SESSIONS: 3,
    MAX_ACCEPTED_HANDSHAKES: 32,
    MAX_PREV_REMOTE_DH: 64,
    MAX_ID_BYTES: 128,
    MAX_STABLE_ID_BYTES: 256,
    MAX_INT: 2147483647,
    MAX_RECOVERIES_PER_DAY: 3,
    RECOVERY_SIGHTING_MS: 10 * 60 * 1000,
    FUTURE_STAMP_TOLERANCE_MS: 24 * H,
    MAX_DEVICES: 64,
    MAX_SUITES: 8,
    RECOVERY_BACKOFF_BASE_MS: H,
    RECOVERY_BACKOFF_MAX_MS: 24 * H,
    REFRESH_INTERVAL_MS: 24 * H,
    RETIRED_SESSION_TTL_MS: 48 * H,
    MAX_PENDING_RECORDS: 256,
  });
  expect(SUITES).toEqual([
    "x25519-xchacha20poly1305-sha256-v2",
    "x25519-xchacha20poly1305-sha256-v1",
  ]);
  expect(
    Object.isFrozen(LIMITS) &&
      Object.isFrozen(SUITES) &&
      Object.isFrozen(LIMITS.PADDING_BUCKETS),
  ).toBe(true);
});
