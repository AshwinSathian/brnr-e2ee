// Session API: initiateSession, acceptSession, encrypt, decrypt (SPEC §6.3, §6.4, §7.6, §8.2).
import { LIMITS, SUITES } from "./constants.js";
import { b64uDecode, b64uEncode, copyBytes, isOpaqueId } from "./codec.js";
import { checkDistinct, type Clock, type Ctx } from "./context.js";
import { fail } from "./errors.js";
import { canonicalJson } from "./jcs.js";
import { parseDevice, parseOtp, parseSpk, verifyDeviceBundle } from "./keys.js";
import {
  aeadOpen,
  aeadSeal,
  ctEqual,
  x25519Dh,
  x25519PublicKey,
} from "./primitives.js";
import { aadOf, kdfCk, kdfRk, messageKey, pad, unpad } from "./ratchet.js";
import { readParams, SUITE_V2 } from "./schemas.js";
import {
  cmpGroup,
  evictIfFull,
  isCandidate,
  isExpired,
  parseStateObject,
  pushFifo,
  restampAndPrune,
  sessionSuite,
  type Session,
  type State,
} from "./state.js";
import type {
  AssociatedData,
  AssociatedDataV2,
  DecryptResult,
  DeviceBundleV2,
  DeviceIdentityKeyPair,
  HandshakeV2,
  MessageV2,
  OneTimePrekeyPair,
  SessionState,
  SignedPrekeyPair,
} from "./types.js";
import type { SuiteId } from "./constants.js";
import {
  hsDigest,
  parseMessage,
  sidOf,
  x3dhInfo,
  x3dhInitiator,
  x3dhResponder,
} from "./x3dh.js";

const raw = (s: string): Uint8Array => b64uDecode(s) as Uint8Array;
const enc = b64uEncode;
const out = (s: State): SessionState => s as unknown as SessionState;

/** SUITES lists the newest suite first; a state never moves to an older suite (SPEC §9.1). */
const older = (a: string, b: string): boolean =>
  SUITES.indexOf(a as SuiteId) > SUITES.indexOf(b as SuiteId);

function checkConversationId(c: unknown): asserts c is string {
  if (!isOpaqueId(c)) fail("E2EE_INVALID_INPUT", "invalid conversationId");
}

function newState(p: {
  suite: SuiteId;
  conversationId: string;
  self: DeviceIdentityKeyPair;
  peerDeviceId: string;
  peerBoxPk: string;
  peerSignPk: string;
  session: Session;
}): State {
  return {
    v: 2,
    suite: p.suite,
    conversationId: p.conversationId,
    selfDeviceId: p.self.deviceId,
    peerDeviceId: p.peerDeviceId,
    selfBoxPk: p.self.boxPk,
    peerBoxPk: p.peerBoxPk,
    // Suite v1 states never carry sign keys, so their bytes are those of 1.0 (SPEC §9.1).
    ...(p.suite === SUITE_V2
      ? { selfSignPk: p.self.signPk, peerSignPk: p.peerSignPk }
      : {}),
    activeSid: p.session.sid,
    sessions: [p.session],
    skipped: [],
    acceptedHandshakes: [],
    pendingOtpDeletes: [],
    pendingReplayRecords: [],
  };
}

// ── initiateSession (SPEC §6.3) ─────────────────────────────────────────────

export function initiateSession(
  ctx: Ctx,
  params: {
    conversationId: string;
    self: DeviceIdentityKeyPair;
    peerBundle: DeviceBundleV2;
    suite?: SuiteId;
    existing?: SessionState;
  },
): SessionState {
  const now = ctx.clock();
  const p = readParams(params, [
    "conversationId",
    "self",
    "peerBundle",
    "suite",
    "existing",
  ] as const) as Partial<typeof params>;
  checkConversationId(p.conversationId);
  const self = parseDevice(p.self);
  if (
    p.suite !== undefined &&
    !(SUITES as readonly unknown[]).includes(p.suite)
  )
    fail("E2EE_UNSUPPORTED_SUITE", "unsupported suite");
  // 1-2.
  const bundle = verifyDeviceBundle(p.peerBundle);
  if (bundle.deviceBoxPk === self.boxPk)
    fail("E2EE_INVALID_INPUT", "reflection");
  // 3.
  const suite = (p.suite ??
    bundle.suites.find((s) => (SUITES as readonly string[]).includes(s))) as
    SuiteId | undefined;
  if (suite === undefined || !bundle.suites.includes(suite))
    fail("E2EE_UNSUPPORTED_SUITE", "no common suite");
  // 4.
  let existing: State | undefined;
  if (p.existing !== undefined) {
    existing = parseStateObject(p.existing);
    if (
      existing.peerBoxPk !== bundle.deviceBoxPk ||
      existing.selfBoxPk !== self.boxPk ||
      existing.selfDeviceId !== self.deviceId ||
      existing.peerDeviceId !== bundle.deviceId ||
      (existing.peerSignPk !== undefined &&
        (existing.peerSignPk !== bundle.deviceSignPk ||
          existing.selfSignPk !== self.signPk))
    )
      fail("E2EE_IDENTITY_MISMATCH", "existing does not match");
    if (existing.conversationId !== p.conversationId)
      fail("E2EE_INVALID_INPUT", "conversation mismatch");
    if (older(suite, existing.suite))
      fail("E2EE_UNSUPPORTED_SUITE", "suite older than the existing state's");
  }
  const v2 = suite === SUITE_V2;
  // 5.
  const ek = ctx.draw(32, "ek");
  const dhsSk = ctx.draw(32, "dhs");
  checkDistinct(ek, dhsSk);
  const sk = x3dhInitiator({
    ikA: self.boxSk,
    ekA: ek,
    ikB: bundle.deviceBoxPk,
    spkB: bundle.spkPk,
    opkB: bundle.otp?.pk,
    info: x3dhInfo(suite, self, {
      deviceId: bundle.deviceId,
      signPk: bundle.deviceSignPk,
      boxPk: bundle.deviceBoxPk,
    }),
  });
  // 6.
  const handshake: HandshakeV2 = {
    v: 2,
    initiatorBoxPk: self.boxPk,
    ...(v2
      ? {
          initiatorSignPk: self.signPk,
          responderDeviceId: bundle.deviceId,
          responderSignPk: bundle.deviceSignPk,
        }
      : {}),
    initiatorEphPk: enc(x25519PublicKey(ek)),
    spkId: bundle.spkId,
    ...(bundle.otp ? { otpId: bundle.otp.otpId } : {}),
  };
  // 7. DR §3.3 initiator.
  const dhsPk = x25519PublicKey(dhsSk);
  const [rk, cks] = kdfRk(sk, x25519Dh(dhsSk, raw(bundle.spkPk)), suite);
  const session: Session = {
    sid: sidOf(handshake),
    role: "initiator",
    founding: handshake,
    pending: { createdAt: now.iso },
    rk: enc(rk),
    dhs: { pk: enc(dhsPk), sk: enc(dhsSk) },
    dhr: bundle.spkPk,
    cks: enc(cks),
    ns: 0,
    nr: 0,
    pn: 0,
    prevRemoteDh: [],
    createdAt: now.iso,
    lastUsedAt: now.iso,
  };
  // 8.
  let state: State;
  if (existing) {
    evictIfFull(existing, now);
    existing.sessions.push(session);
    existing.activeSid = session.sid;
    existing.suite = suite;
    if (v2) {
      // Equal to any stored value (step 4); set here when a v1 state gains its first v2 session.
      existing.selfSignPk = self.signPk;
      existing.peerSignPk = bundle.deviceSignPk;
    }
    state = existing;
  } else
    state = newState({
      suite,
      conversationId: p.conversationId,
      self,
      peerDeviceId: bundle.deviceId,
      peerBoxPk: bundle.deviceBoxPk,
      peerSignPk: bundle.deviceSignPk,
      session,
    });
  return out(restampAndPrune(state, now));
}

// ── acceptSession (SPEC §6.4) ───────────────────────────────────────────────

export function acceptSession(
  ctx: Ctx,
  params: {
    conversationId: string;
    self: DeviceIdentityKeyPair;
    expectedPeerBoxPk: string;
    expectedPeerSignPk?: string;
    message: MessageV2;
    lookupSpk: (spkId: number) => SignedPrekeyPair | undefined;
    lookupOtp: (otpId: number) => OneTimePrekeyPair | undefined;
    seenHandshake: (spkId: number, hsDigest: string) => boolean;
    existing?: SessionState;
  },
): SessionState {
  const now = ctx.clock();
  const p = readParams(params, [
    "conversationId",
    "self",
    "expectedPeerBoxPk",
    "expectedPeerSignPk",
    "message",
    "lookupSpk",
    "lookupOtp",
    "seenHandshake",
    "existing",
  ] as const) as Partial<typeof params>;
  checkConversationId(p.conversationId);
  const self = parseDevice(p.self);
  const pin = b64uDecode(p.expectedPeerBoxPk, 32);
  if (pin === null)
    return fail("E2EE_INVALID_INPUT", "invalid expectedPeerBoxPk");
  const signPin =
    p.expectedPeerSignPk === undefined
      ? undefined
      : b64uDecode(p.expectedPeerSignPk, 32);
  if (signPin === null)
    return fail("E2EE_INVALID_INPUT", "invalid expectedPeerSignPk");
  const { lookupSpk, lookupOtp, seenHandshake } = p;
  if (
    typeof lookupSpk !== "function" ||
    typeof lookupOtp !== "function" ||
    typeof seenHandshake !== "function"
  )
    return fail("E2EE_INVALID_INPUT", "callbacks must be functions");
  // 1.
  const message = parseMessage(p.message);
  const h = message.handshake;
  if (h === undefined)
    return fail("E2EE_HANDSHAKE_REQUIRED", "message has no handshake");
  const v2 = message.suite === SUITE_V2;
  if (v2 && signPin === undefined)
    return fail("E2EE_INVALID_INPUT", "suite v2 requires expectedPeerSignPk");
  // 2-4.
  if (h.initiatorBoxPk === self.boxPk) fail("E2EE_INVALID_INPUT", "reflection");
  if (!ctEqual(raw(h.initiatorBoxPk), pin))
    fail("E2EE_IDENTITY_MISMATCH", "initiator key does not match the pin");
  if (v2) {
    // SPEC §6.4 step 3: the initiator's signing key matches its pin, and the handshake targets us.
    if (!ctEqual(raw(h.initiatorSignPk as string), signPin as Uint8Array))
      fail(
        "E2EE_IDENTITY_MISMATCH",
        "initiator sign key does not match the pin",
      );
    if (
      h.responderDeviceId !== self.deviceId ||
      h.responderSignPk !== self.signPk
    )
      fail("E2EE_IDENTITY_MISMATCH", "handshake targets another device");
  }
  const sid = sidOf(h);
  if (message.header.sid !== sid) fail("E2EE_INVALID_INPUT", "sid mismatch");
  const digest = hsDigest(h);
  // 5.
  let existing: State | undefined;
  if (p.existing !== undefined) {
    existing = parseStateObject(p.existing);
    if (
      existing.peerBoxPk !== p.expectedPeerBoxPk ||
      existing.selfBoxPk !== self.boxPk ||
      existing.selfDeviceId !== self.deviceId ||
      existing.peerDeviceId !== message.ad.senderDeviceId ||
      (existing.peerSignPk !== undefined &&
        (existing.peerSignPk !== p.expectedPeerSignPk ||
          existing.selfSignPk !== self.signPk))
    )
      fail("E2EE_IDENTITY_MISMATCH", "existing does not match");
    if (existing.conversationId !== p.conversationId)
      fail("E2EE_INVALID_INPUT", "conversation mismatch");
    if (older(message.suite, existing.suite))
      fail("E2EE_UNSUPPORTED_SUITE", "suite older than the existing state's");
    if (existing.sessions.some((x) => x.sid === sid))
      fail("E2EE_DUPLICATE_MESSAGE", "session already held");
    if (existing.acceptedHandshakes.includes(digest))
      fail("E2EE_DUPLICATE_MESSAGE", "handshake already accepted", {
        reason: "evicted-session",
      });
  }
  // 6.
  const spkRaw = lookupSpk(h.spkId);
  if (spkRaw == null) return fail("E2EE_SPK_UNKNOWN", "unknown spkId");
  const spk = parseSpk(spkRaw);
  if (spk.spkId !== h.spkId || enc(x25519PublicKey(raw(spk.sk))) !== spk.pk)
    fail("E2EE_INVALID_STATE", "lookupSpk returned a mismatched key");
  if (!spk.suites.includes(message.suite))
    fail("E2EE_UNSUPPORTED_SUITE", "suite not offered by the SPK");
  // 7.
  const seen: unknown = seenHandshake(h.spkId, digest);
  if (typeof seen !== "boolean")
    return fail("E2EE_INVALID_STATE", "seenHandshake did not return a boolean");
  if (seen)
    fail("E2EE_DUPLICATE_MESSAGE", "handshake already accepted", {
      reason: "evicted-session",
    });
  // 8.
  let otp: OneTimePrekeyPair | undefined;
  if (h.otpId !== undefined) {
    const otpRaw = lookupOtp(h.otpId);
    if (otpRaw == null) return fail("E2EE_OTP_UNKNOWN", "unknown otpId");
    otp = parseOtp(otpRaw);
    if (otp.otpId !== h.otpId || enc(x25519PublicKey(raw(otp.sk))) !== otp.pk)
      fail("E2EE_INVALID_STATE", "lookupOtp returned a mismatched key");
  }
  // 9. DR §3.3 responder.
  const sk = x3dhResponder({
    spkSk: spk.sk,
    ikSk: self.boxSk,
    ikA: h.initiatorBoxPk,
    ekA: h.initiatorEphPk,
    opkSk: otp?.sk,
    info: x3dhInfo(
      message.suite,
      {
        deviceId: message.ad.senderDeviceId,
        signPk: h.initiatorSignPk as string,
        boxPk: h.initiatorBoxPk,
      },
      self,
    ),
  });
  const session: Session = {
    sid,
    role: "responder",
    founding: h,
    rk: enc(sk),
    dhs: { pk: spk.pk, sk: spk.sk },
    ns: 0,
    nr: 0,
    pn: 0,
    prevRemoteDh: [],
    createdAt: now.iso,
    lastUsedAt: now.iso,
  };
  // 10.
  let state: State;
  if (existing) {
    evictIfFull(existing, now);
    existing.sessions.push(session);
    if (v2) {
      // Equal to any stored value (step 5); set here when a v1 state gains its first v2 session.
      existing.selfSignPk = self.signPk;
      existing.peerSignPk = p.expectedPeerSignPk as string;
    }
    state = existing;
  } else
    state = newState({
      suite: message.suite,
      conversationId: p.conversationId,
      self,
      peerDeviceId: message.ad.senderDeviceId,
      peerBoxPk: h.initiatorBoxPk,
      peerSignPk: p.expectedPeerSignPk as string,
      session,
    });
  pushFifo(state.acceptedHandshakes, digest, LIMITS.MAX_ACCEPTED_HANDSHAKES);
  if (h.otpId !== undefined) state.pendingOtpDeletes.push(h.otpId);
  state.pendingReplayRecords.push({ spkId: h.spkId, hsDigest: digest });
  return out(restampAndPrune(state, now));
}

// ── encrypt (SPEC §7.6) ─────────────────────────────────────────────────────

/** Keys bound into the message key (SPEC §7.4): IK_A ‖ IK_B, then ED_A ‖ ED_B for a v2 session. */
function sessionKeys(s: State, x: Session): string[] {
  const self = [s.selfBoxPk, s.selfSignPk as string];
  const peer = [s.peerBoxPk, s.peerSignPk as string];
  const [a, b] = x.role === "initiator" ? [self, peer] : [peer, self];
  const keys = [a[0], b[0]];
  if (sessionSuite(x) === SUITE_V2) keys.push(a[1], b[1]);
  return keys as string[];
}

function sameAd(a: unknown, b: AssociatedData): boolean {
  try {
    return canonicalJson(a) === canonicalJson(b);
  } catch {
    return false;
  }
}

export function encrypt(
  ctx: Ctx,
  params: { state: SessionState; plaintext: Uint8Array; ad: AssociatedData },
): { state: SessionState; message: MessageV2 } {
  const now = ctx.clock();
  const p = readParams(params, [
    "state",
    "plaintext",
    "ad",
  ] as const) as Partial<typeof params>;
  const plaintext = copyBytes(p.plaintext);
  if (plaintext === null)
    return fail("E2EE_INVALID_INPUT", "plaintext must be a Uint8Array");
  // 1.
  const s = parseStateObject(p.state);
  if (plaintext.length > LIMITS.MAX_PLAINTEXT_BYTES)
    fail("E2EE_PLAINTEXT_TOO_LARGE", "plaintext over 8,192 bytes");
  // 2.
  const suite = s.suite as SuiteId;
  const ad = {
    conversationId: s.conversationId,
    senderDeviceId: s.selfDeviceId,
    ...(suite === SUITE_V2 ? { recipientDeviceId: s.peerDeviceId } : {}),
    suite,
    v: 2,
  } as AssociatedData;
  if (!sameAd(p.ad, ad))
    fail("E2EE_AD_MISMATCH", "ad does not match the state");
  // 3-4.
  const x = s.sessions.find((y) => y.sid === s.activeSid) as Session;
  // Stryker disable next-line all: unreachable; the state invariants require cks on every non-candidate session, and encrypt rejects candidates
  if (x.cks === undefined)
    return fail("E2EE_INVALID_STATE", "no sending chain");
  if (x.ns === LIMITS.MAX_INT) fail("E2EE_INVALID_STATE", "Ns exhausted");
  // 5-6.
  const [cks, mk] = kdfCk(raw(x.cks));
  x.cks = enc(cks);
  const header = { sid: x.sid, dh: x.dhs.pk, pn: x.pn, n: x.ns };
  x.ns += 1;
  // 7.
  const nonce = ctx.draw(24, "nonce");
  const handshake = x.pending ? { ...x.founding } : undefined;
  const fields = { v: 2 as const, suite, ad, header, handshake };
  const ct = aeadSeal(
    messageKey(mk, ad, sessionKeys(s, x)),
    nonce,
    pad(plaintext),
    aadOf(fields),
  );
  const message: MessageV2 = {
    v: 2,
    suite,
    header,
    nonce: enc(nonce),
    ciphertext: enc(ct),
    ad,
    ...(handshake ? { handshake } : {}),
  };
  // 8.
  return { state: out(restampAndPrune(s, now)), message };
}

// ── decrypt (SPEC §7.6, §8.2) ───────────────────────────────────────────────

function findSkipped(
  s: State,
  sid: string,
  dh: string,
  n: number,
): { gi: number; ki: number } | undefined {
  const gi = s.skipped.findIndex((g) => g.sid === sid && g.dh === dh);
  const g = s.skipped[gi];
  if (g === undefined) return undefined;
  const ki = g.keys.findIndex((k) => k[0] === n);
  return ki < 0 ? undefined : { gi, ki };
}

function storeSkipped(
  s: State,
  sid: string,
  dh: string,
  n: number,
  mk: Uint8Array,
  now: Clock,
): void {
  let g = s.skipped.find((y) => y.sid === sid && y.dh === dh);
  if (g === undefined) {
    g = { sid, dh, keys: [] };
    // Stryker disable next-line EqualityOperator: no existing group equals g (find returned undefined above)
    const at = s.skipped.findIndex((y) => cmpGroup(y, g as typeof y) > 0);
    s.skipped.splice(at < 0 ? s.skipped.length : at, 0, g);
  }
  g.keys.push([n, enc(mk), now.iso]);
}

/** skip(S, until) (SPEC §7.6). */
function skip(s: State, x: Session, until: number, now: Clock): void {
  if (until - x.nr > LIMITS.MAX_SKIP)
    fail("E2EE_SKIP_TOO_LARGE", "skip over MAX_SKIP");
  if (x.ckr === undefined) return;
  let ck = raw(x.ckr);
  while (x.nr < until) {
    const [next, mk] = kdfCk(ck);
    storeSkipped(s, x.sid, x.dhr as string, x.nr, mk, now);
    ck = next;
    x.nr += 1;
  }
  x.ckr = enc(ck);
}

export function decrypt(
  ctx: Ctx,
  params: {
    state: SessionState;
    message: MessageV2;
    expectedAd: AssociatedData;
  },
): DecryptResult {
  const now = ctx.clock();
  const p = readParams(params, [
    "state",
    "message",
    "expectedAd",
  ] as const) as Partial<typeof params>;
  const s = parseStateObject(p.state, true);
  // 1.
  const m = parseMessage(p.message);
  // 2.
  // expectedAd is read once (by sameAd); the equal parsed m.ad is used after that.
  if (
    !sameAd(m.ad, p.expectedAd as AssociatedData) ||
    m.ad.conversationId !== s.conversationId ||
    m.ad.senderDeviceId !== s.peerDeviceId ||
    (m.suite === SUITE_V2 &&
      (m.ad as AssociatedDataV2).recipientDeviceId !== s.selfDeviceId)
  )
    fail("E2EE_AD_MISMATCH", "associated data mismatch");
  // 3.
  const h = m.handshake;
  if (h !== undefined) {
    if (h.initiatorBoxPk === s.selfBoxPk)
      fail("E2EE_INVALID_INPUT", "reflection");
    if (sidOf(h) !== m.header.sid) fail("E2EE_INVALID_INPUT", "sid mismatch");
  }
  // 4. A candidate state must decrypt on its new session (SPEC §9.2a), then route (SPEC §8.2).
  const candidate = s.sessions.find(isCandidate);
  if (candidate !== undefined && candidate.sid !== m.header.sid)
    fail(
      "E2EE_INVALID_STATE",
      "a candidate state must decrypt on its new session",
    );
  // An expired retired session routes as if it were already deleted (SPEC §8.2).
  const x = s.sessions.find(
    (y) => y.sid === m.header.sid && !isExpired(y, now),
  );
  if (x === undefined) {
    if (h === undefined) return fail("E2EE_HANDSHAKE_REQUIRED", "unknown sid");
    const digest = hsDigest(h);
    if (s.acceptedHandshakes.includes(digest))
      return fail("E2EE_DUPLICATE_MESSAGE", "evicted session", {
        reason: "evicted-session",
      });
    return fail("E2EE_SESSION_CONFLICT", "unknown sid with a new handshake", {
      handshake: h,
      hsDigest: digest,
    });
  }
  // A session decrypts only messages of its own suite, and a session older in suite than the
  // state is dead: once a state is v2, no v1 message is decrypted (SPEC §7.6 step 4).
  if (m.suite !== sessionSuite(x) || older(m.suite, s.suite))
    fail("E2EE_UNSUPPORTED_SUITE", "message suite differs from the session's");
  // Stryker disable next-line all: not testable through the API: it needs two handshakes with the same 64-bit sid (about 2^32 work to find); step 3 already checked sid(h) == header.sid
  if (h !== undefined && canonicalJson(h) !== canonicalJson(x.founding))
    fail(
      "E2EE_INVALID_INPUT",
      "handshake is not this session's founding handshake",
    );
  // 5. DR §3.5.
  const { dh, n, pn } = m.header;
  let mk: Uint8Array;
  let advanced = true;
  // A DH ratchet step over an existing dhr: the peer has received a message on this session.
  let confirmed = false;
  if (dh === x.dhr && x.ckr === undefined)
    return fail("E2EE_DECRYPT_FAILED", "no receiving chain");
  const hit = findSkipped(s, x.sid, dh, n);
  if (hit) {
    mk = raw(
      (s.skipped[hit.gi] as State["skipped"][number]).keys[
        hit.ki
      ]?.[1] as string,
    );
    advanced = false;
  } else {
    if (dh === x.dhr && n < x.nr) fail("E2EE_DUPLICATE_MESSAGE", "old message");
    if (
      x.prevRemoteDh.includes(dh) ||
      (dh !== x.dhr && s.skipped.some((g) => g.sid === x.sid && g.dh === dh))
    )
      fail("E2EE_DUPLICATE_MESSAGE", "old ratchet key");
    if (dh !== x.dhr) {
      confirmed = x.dhr !== undefined;
      skip(s, x, pn, now);
      if (x.dhr !== undefined)
        pushFifo(x.prevRemoteDh, x.dhr, LIMITS.MAX_PREV_REMOTE_DH);
      x.pn = x.ns;
      x.ns = 0;
      x.nr = 0;
      x.dhr = dh;
      let [rk, ck] = kdfRk(
        raw(x.rk),
        x25519Dh(raw(x.dhs.sk), raw(dh)),
        m.suite,
      );
      x.ckr = enc(ck);
      const dhsSk = ctx.draw(32, "dhs");
      x.dhs = { pk: enc(x25519PublicKey(dhsSk)), sk: enc(dhsSk) };
      [rk, ck] = kdfRk(rk, x25519Dh(dhsSk, raw(dh)), m.suite);
      x.rk = enc(rk);
      x.cks = enc(ck);
    }
    skip(s, x, n, now);
    const [ckr, k] = kdfCk(raw(x.ckr as string));
    x.ckr = enc(ckr);
    x.nr += 1;
    mk = k;
  }
  // 6.
  const key = messageKey(mk, m.ad, sessionKeys(s, x));
  const padded = aeadOpen(key, raw(m.nonce), raw(m.ciphertext), aadOf(m));
  if (padded === null)
    return fail("E2EE_DECRYPT_FAILED", "authentication failed");
  const plaintext = unpad(padded);
  // 7. Commit.
  if (hit) {
    const g = s.skipped[hit.gi] as State["skipped"][number];
    g.keys.splice(hit.ki, 1);
    // An emptied group is removed by the pruning below (SPEC §9.1 array order).
  }
  delete x.pending;
  x.lastUsedAt = now.iso;
  // SPEC §8.1: a confirmed decrypt on the session that was already active retires every
  // session before it in `sessions` (creation order, not the clock, which can step back);
  // a retired session never becomes active again.
  if (confirmed && x.sid === s.activeSid)
    for (const y of s.sessions.slice(0, s.sessions.indexOf(x)))
      y.retiredAt ??= now.iso;
  if (advanced && x.retiredAt === undefined) {
    s.activeSid = x.sid;
    s.suite = m.suite;
  }
  restampAndPrune(s, now);
  return {
    state: out(s),
    plaintext,
    messageKey: key,
    advancedReceiveChain: advanced,
    sessionCreatedAt: x.createdAt,
  };
}
