// Session state: schema invariants, serialisation, re-stamping, pruning, eviction (SPEC §9).
import { LIMITS } from "./constants.js";
import { b64uDecode, b64uEncode, compareBytes, ms } from "./codec.js";
import type { Clock } from "./context.js";
import { fail } from "./errors.js";
import { canonicalJson } from "./jcs.js";
import { x25519PublicKey } from "./primitives.js";
import {
  isHandshakeV2,
  parseStrict,
  stateSchema,
  SUITE_V1,
  SUITE_V2,
} from "./schemas.js";
import type { SessionInfo, SessionState } from "./types.js";
import type { SuiteId } from "./constants.js";
import { sidOf } from "./x3dh.js";
import type { z } from "zod";

export type State = z.infer<typeof stateSchema>;
export type Session = State["sessions"][number];
export type SkippedGroup = State["skipped"][number];

const raw = (s: string): Uint8Array => b64uDecode(s) as Uint8Array;
const bad = (msg: string): never => fail("E2EE_INVALID_STATE", msg);

/** Byte order of (sid, dh). */
export const cmpGroup = (
  a: { sid: string; dh: string },
  b: { sid: string; dh: string },
): number =>
  compareBytes(raw(a.sid), raw(b.sid)) || compareBytes(raw(a.dh), raw(b.dh));

/** A session's suite is fixed by its founding handshake's shape (SPEC §9.1). */
export const sessionSuite = (x: Session): SuiteId =>
  isHandshakeV2(x.founding) ? SUITE_V2 : SUITE_V1;

/** SPEC §9.1: the v2 founding fields agree with the state's identities for the session's role. */
function checkV2Founding(s: State, x: Session): void {
  const f = x.founding as Session["founding"] & {
    initiatorSignPk: string;
    responderDeviceId: string;
    responderSignPk: string;
  };
  const [init, resp, respId] =
    x.role === "initiator"
      ? [s.selfSignPk, s.peerSignPk, s.peerDeviceId]
      : [s.peerSignPk, s.selfSignPk, s.selfDeviceId];
  if (
    f.initiatorSignPk !== init ||
    f.responderSignPk !== resp ||
    f.responderDeviceId !== respId
  )
    bad("founding identity");
}

/** SPEC §9.2 invariants. `allowCandidate`: the §9.2a exception for decrypt. */
export function checkInvariants(s: State, allowCandidate: boolean): void {
  if (s.selfBoxPk === s.peerBoxPk) bad("selfBoxPk equals peerBoxPk");
  if ((s.selfSignPk === undefined) !== (s.peerSignPk === undefined))
    bad("selfSignPk and peerSignPk");
  const sids = new Set<string>();
  let candidates = 0;
  for (const x of s.sessions) {
    if (sids.has(x.sid)) bad("duplicate sid");
    sids.add(x.sid);
    if (x.sid !== sidOf(x.founding))
      bad("sid does not match founding handshake");
    const ik = x.role === "initiator" ? s.selfBoxPk : s.peerBoxPk;
    if (x.founding.initiatorBoxPk !== ik) bad("founding initiator key");
    // Also requires the sign keys: an absent one never equals a founding key.
    if (sessionSuite(x) === SUITE_V2) checkV2Founding(s, x);
    if (b64uEncode(x25519PublicKey(raw(x.dhs.sk), false)) !== x.dhs.pk)
      bad("dhs key pair");
    const has = [x.dhr, x.cks, x.ckr].map((k) => k !== undefined);
    if (x.role === "responder") {
      const candidate = allowCandidate && has.every((h) => !h);
      if (candidate) candidates++;
      if (!candidate && !has.every(Boolean))
        bad("responder session without chains");
    } else if (x.cks === undefined) bad("initiator session without cks");
    if (x.pending !== undefined && x.role !== "initiator")
      bad("pending on responder");
    if (x.ckr !== undefined && x.dhr === undefined) bad("ckr without dhr");
  }
  const active = s.sessions.find((x) => x.sid === s.activeSid);
  if (active === undefined) return bad("activeSid");
  if (active.retiredAt !== undefined) bad("active session is retired");
  if (sessionSuite(active) !== s.suite) bad("suite of the active session");
  if (candidates > 1) bad("more than one candidate session");
  let total = 0;
  s.skipped.forEach((g, i) => {
    if (!sids.has(g.sid)) bad("skipped sid");
    const prev = s.skipped[i - 1];
    if (prev !== undefined && cmpGroup(prev, g) >= 0) bad("skipped order");
    if (g.keys.length === 0) bad("empty skipped group");
    g.keys.forEach((k, j) => {
      const p = g.keys[j - 1];
      if (p !== undefined && p[0] >= k[0]) bad("skipped n order");
    });
    total += g.keys.length;
  });
  if (total > LIMITS.MAX_SKIPPED_KEYS) bad("too many skipped keys");
}

/** Strict parse of a state object (§4.7) plus invariants. Returns a fresh copy. */
export function parseStateObject(x: unknown, allowCandidate = false): State {
  const s = parseStrict(stateSchema, x, "state", {
    v: 2,
    nested: (o) =>
      Array.isArray(o["sessions"])
        ? (o["sessions"] as unknown[]).map((r): [unknown, number] => [
            (r as { founding?: unknown } | null)?.founding,
            2,
          ])
        : [],
  });
  checkInvariants(s, allowCandidate);
  return s;
}

export function parseState(rawText: unknown): SessionState {
  if (typeof rawText !== "string") return bad("state is not a string");
  let x: unknown;
  try {
    x = JSON.parse(rawText);
  } catch {
    // Invalid JSON leaves x undefined, which fails as INVALID_STATE below.
  }
  return parseStateObject(x) as unknown as SessionState;
}

export const serializeState = (state: unknown): string =>
  canonicalJson(parseStateObject(state));

/** SPEC §9.3 step 1 for one stamp. */
export const restamp = (s: string, now: Clock): string =>
  ms(s) > now.ms + LIMITS.FUTURE_STAMP_TOLERANCE_MS ? now.iso : s;

/**
 * SPEC §8.1: a retired session expires RETIRED_SESSION_TTL_MS after retiredAt. retiredAt is never
 * re-stamped; one more than FUTURE_STAMP_TOLERANCE_MS ahead of now has expired too, so a clock
 * stepped back cannot extend the window.
 */
export function isExpired(x: Session, now: Clock): boolean {
  if (x.retiredAt === undefined) return false;
  const age = now.ms - ms(x.retiredAt);
  return (
    age > LIMITS.RETIRED_SESSION_TTL_MS ||
    -age > LIMITS.FUTURE_STAMP_TOLERANCE_MS
  );
}

/** SPEC §9.3 step 1 on every stamp except retiredAt. Mutates `s`. */
export function restampAll(s: State, now: Clock): void {
  for (const x of s.sessions) {
    x.createdAt = restamp(x.createdAt, now);
    x.lastUsedAt = restamp(x.lastUsedAt, now);
    if (x.pending) x.pending.createdAt = restamp(x.pending.createdAt, now);
  }
  for (const g of s.skipped) for (const k of g.keys) k[2] = restamp(k[2], now);
}

/** SPEC §9.3: re-stamp, then prune skipped keys, then idle sessions. Mutates `s`. */
export function restampAndPrune(s: State, now: Clock): State {
  restampAll(s, now);
  const TTL = LIMITS.SKIPPED_KEY_TTL_MS;
  for (const g of s.skipped) {
    g.keys = g.keys.filter((k) => now.ms - ms(k[2]) <= TTL);
  }
  const all = s.skipped.flatMap((g) => g.keys.map((k) => ({ g, k })));
  // Stryker disable next-line ConditionalExpression,EqualityOperator: within the cap the drop below is empty; the check only skips the sort
  if (all.length > LIMITS.MAX_SKIPPED_KEYS) {
    all.sort(
      (a, b) =>
        ms(a.k[2]) - ms(b.k[2]) || cmpGroup(a.g, b.g) || a.k[0] - b.k[0],
    );
    const drop = new Set(
      all.slice(0, all.length - LIMITS.MAX_SKIPPED_KEYS).map((x) => x.k),
    );
    for (const g of s.skipped) g.keys = g.keys.filter((k) => !drop.has(k));
  }
  s.skipped = s.skipped.filter((g) => g.keys.length > 0);
  const gone = new Set(
    s.sessions
      .filter(
        (x) =>
          (x.sid !== s.activeSid && now.ms - ms(x.lastUsedAt) > TTL) ||
          isExpired(x, now),
      )
      .map((x) => x.sid),
  );
  removeSessions(s, gone);
  return s;
}

function removeSessions(s: State, sids: Set<string>): void {
  s.sessions = s.sessions.filter((x) => !sids.has(x.sid));
  s.skipped = s.skipped.filter((g) => !sids.has(g.sid));
}

/** SPEC §9.1 eviction, run before adding a session when there are already MAX_SESSIONS. */
export function evictIfFull(s: State, now: Clock): void {
  restampAll(s, now);
  if (s.sessions.length < LIMITS.MAX_SESSIONS) return;
  const victim = s.sessions
    .filter((x) => x.sid !== s.activeSid)
    .sort(
      (a, b) =>
        Number(b.retiredAt !== undefined) - Number(a.retiredAt !== undefined) ||
        ms(a.lastUsedAt) - ms(b.lastUsedAt) ||
        compareBytes(raw(a.sid), raw(b.sid)),
    )[0] as Session; // with MAX_SESSIONS sessions, at least two are non-active
  removeSessions(s, new Set([victim.sid]));
}

/** FIFO append with a cap (SPEC §9.1 array order). */
export function pushFifo<T>(a: T[], x: T, cap: number): void {
  a.push(x);
  while (a.length > cap) a.shift();
}

/** SPEC §9.4. */
export function inspect(stateIn: unknown, now: Clock): SessionInfo {
  const s = parseStateObject(stateIn);
  // Stryker disable next-line EqualityOperator: at equality both branches return the same stamp
  const clamp = (t: string) => (ms(t) > now.ms ? now.iso : t);
  return {
    suite: s.suite as SuiteId,
    activeSid: s.activeSid,
    sessions: s.sessions.map((x) => ({
      sid: x.sid,
      role: x.role,
      createdAt: clamp(x.createdAt),
      lastUsedAt: clamp(x.lastUsedAt),
      retiredAt: x.retiredAt === undefined ? null : clamp(x.retiredAt),
      pending: x.pending
        ? {
            spkId: x.founding.spkId,
            ...(x.founding.otpId === undefined
              ? {}
              : { otpId: x.founding.otpId }),
            createdAt: clamp(x.pending.createdAt),
          }
        : null,
    })),
    pendingOtpDeletes: [...s.pendingOtpDeletes],
    pendingReplayRecords: s.pendingReplayRecords.map((r) => ({ ...r })),
  };
}

/** A responder session with no chains: a candidate from acceptSession (SPEC §9.2a). */
/** The invariants allow a chainless responder only as a whole candidate, so no receive chain identifies it. */
export const isCandidate = (x: Session): boolean =>
  x.role === "responder" && x.ckr === undefined;
