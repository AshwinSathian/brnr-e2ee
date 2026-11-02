/**
 * brnr-e2ee public API. Every name exported here is listed in SPEC.md §API and
 * imported by test/api.types.test.ts. Nothing else is public.
 */

export { SUITES, LIMITS } from "./constants.js";
export type { SuiteId } from "./constants.js";
export { E2eeError, E2EE_ERROR_CODES, isE2eeError } from "./errors.js";
export type { E2eeErrorCode } from "./errors.js";
export type * from "./types.js";

export { createE2ee } from "./e2ee.js";
export { withSession } from "./withSession.js";
