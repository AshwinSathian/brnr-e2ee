// Internal test hooks (DRBG tape, fingerprint chain, operation counters). Outside SemVer guarantees.
export { HmacDrbg, drbgRng, tapeRng, type TapeEntry } from "./drbg.js";
export { ops } from "./primitives.js";
export { chain as fingerprintChain, digits30 } from "./fingerprint.js";
