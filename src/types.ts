import type { SuiteId } from "./constants.js";

/** base64url, RFC 4648 §5, no padding, canonical (re-encodes to the same string). */
export type B64u = string;

// ── RNG ────────────────────────────────────────────

export type RngPurpose =
  "health" | "seed" | "ek" | "dhs" | "nonce" | "link-request";

export interface Rng {
  (n: number, purpose?: RngPurpose): Uint8Array;
}

export interface E2eeOptions {
  rng?: Rng;
  now?: () => Date;
  /**
   * Accept a test RNG from `brnr-e2ee/testing` (deterministic, never secret). Without it,
   * createE2ee refuses one with E2EE_RNG_UNAVAILABLE (SPEC §15). Tests and vector generation only.
   */
  dangerouslyAllowTestRng?: boolean;
}

// ── Keys and bundles ─────────────────────────────────

export interface AccountIdentityKeyPair {
  v: 1;
  signPk: B64u;
  signSk: B64u;
}

export interface DeviceIdentityKeyPair {
  v: 1;
  deviceId: string;
  signPk: B64u;
  signSk: B64u;
  boxPk: B64u;
  boxSk: B64u;
}

export interface SignedPrekeyPair {
  v: 1;
  spkId: number;
  pk: B64u;
  sk: B64u;
  sig: B64u;
  createdAt: string;
  /** Ordered, preferred first; may contain ids unknown to this version (SPEC §5.4). */
  suites: string[];
}

export interface OneTimePrekeyPair {
  v: 1;
  otpId: number;
  pk: B64u;
  sk: B64u;
}

export interface DeviceBundleV2 {
  v: 2;
  suites: string[];
  deviceId: string;
  deviceSignPk: B64u;
  deviceBoxPk: B64u;
  deviceBoxPkSig: B64u;
  spkId: number;
  spkPk: B64u;
  spkSig: B64u;
  otp?: { otpId: number; pk: B64u };
  createdAt: string;
}

export interface SignedDeviceListEntry {
  deviceId: string;
  deviceSignPk: B64u;
  deviceBoxPk: B64u;
  addedAt: string;
  revokedAt?: string;
}

export interface SignedDeviceList {
  v: 1;
  accountId: string;
  accountSignPk: B64u;
  epoch: number;
  devices: SignedDeviceListEntry[];
  sig: B64u;
}

// ── Sessions and messages ───────────────────

/** Suite v1 associated data (SPEC §7.4). */
export interface AssociatedDataV1 {
  conversationId: string;
  senderDeviceId: string;
  suite: "x25519-xchacha20poly1305-sha256-v1";
  v: 2;
}

/** Suite v2 associated data (SPEC §7.4): also names the recipient device. */
export interface AssociatedDataV2 {
  conversationId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  suite: "x25519-xchacha20poly1305-sha256-v2";
  v: 2;
}

/** The AD shape is fixed by `suite`: build it from `inspectSession(state).suite` or `message.suite`. */
export type AssociatedData = AssociatedDataV1 | AssociatedDataV2;

/**
 * Founding handshake (SPEC §6.1). Suite v2 handshakes carry the three identity fields; suite v1
 * handshakes never do.
 */
export interface HandshakeV2 {
  v: 2;
  initiatorBoxPk: B64u;
  /** Suite v2 only: the initiator's Ed25519 device key. */
  initiatorSignPk?: B64u;
  initiatorEphPk: B64u;
  /** Suite v2 only: the deviceId of the bundle the initiator used. */
  responderDeviceId?: string;
  /** Suite v2 only: the deviceSignPk of the bundle the initiator used. */
  responderSignPk?: B64u;
  spkId: number;
  otpId?: number;
}

export interface MessageHeader {
  /** 8-byte session id, base64url. */
  sid: B64u;
  dh: B64u;
  pn: number;
  n: number;
}

export interface MessageV2 {
  v: 2;
  suite: SuiteId;
  header: MessageHeader;
  nonce: B64u;
  ciphertext: B64u;
  ad: AssociatedData;
  handshake?: HandshakeV2;
}

/** Opaque, versioned, schema-validated. Callers persist it and never read its fields. */
export type SessionState = { readonly v: 2; readonly [k: string]: unknown };

export interface DecryptResult {
  state: SessionState;
  plaintext: Uint8Array;
  messageKey: Uint8Array;
  /** False when a stored skipped key was used. */
  advancedReceiveChain: boolean;
  /** createdAt of the session that decrypted. */
  sessionCreatedAt: string;
}

export interface SessionInfo {
  /** Suite of the active session: the suite `encrypt` uses and its `ad` must name (SPEC §9.4). */
  suite: SuiteId;
  activeSid: B64u;
  sessions: Array<{
    sid: B64u;
    role: "initiator" | "responder";
    createdAt: string;
    pending: { spkId: number; otpId?: number; createdAt: string } | null;
    lastUsedAt: string;
    /** When a decrypt on the active session retired this one (SPEC §8.1); null while live. */
    retiredAt: string | null;
  }>;
  pendingOtpDeletes: number[];
  pendingReplayRecords: Array<{ spkId: number; hsDigest: B64u }>;
}

export interface RecoveryTrackerV1 {
  v: 1;
  /** Up to 4 timestamps, FIFO. */
  sightings: string[];
  attempts: number;
  lastAt?: string;
  /** Recovery and refresh re-initiations in the last 24 h; at most LIMITS.MAX_RECOVERIES_PER_DAY. */
  window: string[];
  /** Last refresh re-initiation (stale pending handshake, repeated SKIP_TOO_LARGE); at most one per 24 h. */
  lastRefreshAt?: string;
  /** The latest clock reading any tracker function has seen (SPEC §8.4). */
  seenAt?: string;
}

export type RecoveryReason = "handshake-required" | "evicted-session";

// ── KeyStore ─────────────────────

export interface StoredSession {
  serialized: string | null;
  version: number;
  tracker: string | null;
}

export interface PutSessionOptions {
  deleteOtpIds?: number[];
  tracker?: string;
  acceptedHandshakes?: Array<{ spkId: number; hsDigest: B64u }>;
}

export interface KeyStore {
  getSession(
    peerDeviceId: string,
    conversationId: string,
  ): Promise<StoredSession | null>;
  /** One transaction where the backend allows it. Throws on version mismatch. `serialized = null` leaves the session untouched. */
  putSession(
    peerDeviceId: string,
    conversationId: string,
    serialized: string | null,
    expectedVersion: number | null,
    opts?: PutSessionOptions,
  ): Promise<number>;
  getSpk(spkId: number): Promise<SignedPrekeyPair | undefined>;
  getOtp(otpId: number): Promise<OneTimePrekeyPair | undefined>;
  /** Idempotent. */
  deleteOtp(otpId: number): Promise<void>;
  /** Device-level replay set, kept as long as the SPK private key. */
  hasAcceptedHandshake(spkId: number, hsDigest: B64u): Promise<boolean>;
  withLock<T>(conversationId: string, fn: () => Promise<T>): Promise<T>;
}

// ── Safety numbers ─────────────────────────────────

export interface SafetyNumber {
  digits: string;
  groups: string[];
  /** u16be(version) ‖ localFp32 ‖ remoteFp32: directional, not sorted. */
  qrPayload: Uint8Array;
}

// ── Reports ────────────────────────────────────────

export interface ReportDisclosureV1 {
  v: 1;
  items: Array<{
    envelopeId: string;
    message: MessageV2;
    messageKey: B64u;
    plaintext: string;
  }>;
}

// ── The E2ee object ───────────────────

export interface E2ee {
  generateAccountIdentity(): AccountIdentityKeyPair;
  generateDeviceIdentity(deviceId: string): DeviceIdentityKeyPair;
  generateSignedPrekey(
    device: DeviceIdentityKeyPair,
    spkId: number,
    suites?: SuiteId[],
  ): SignedPrekeyPair;
  generateOneTimePrekeys(
    firstOtpId: number,
    count: number,
  ): OneTimePrekeyPair[];

  buildDeviceBundle(params: {
    device: DeviceIdentityKeyPair;
    spk: SignedPrekeyPair;
  }): Omit<DeviceBundleV2, "otp">;
  verifyDeviceBundle(bundle: DeviceBundleV2): void;

  buildSignedDeviceList(params: {
    account: AccountIdentityKeyPair;
    accountId: string;
    epoch: number;
    devices: SignedDeviceListEntry[];
  }): SignedDeviceList;
  verifySignedDeviceList(
    list: SignedDeviceList,
    opts?: { pinnedAccountSignPk?: B64u; minEpoch?: number },
  ): void;
  deviceListDigest(list: SignedDeviceList): B64u;
  bundleMatchesDeviceList(
    bundle: DeviceBundleV2,
    list: SignedDeviceList,
  ): boolean;
  /** hsDigest (SPEC §6.1). Use it for KeyStore.hasAcceptedHandshake pre-loads. */
  handshakeDigest(handshake: HandshakeV2): B64u;

  initiateSession(params: {
    conversationId: string;
    self: DeviceIdentityKeyPair;
    peerBundle: DeviceBundleV2;
    suite?: SuiteId;
    existing?: SessionState;
  }): SessionState;
  acceptSession(params: {
    conversationId: string;
    self: DeviceIdentityKeyPair;
    expectedPeerBoxPk: B64u;
    /** The peer's pinned Ed25519 device key. Required when `message.suite` is v2 (SPEC §6.4). */
    expectedPeerSignPk?: B64u;
    message: MessageV2;
    lookupSpk: (spkId: number) => SignedPrekeyPair | undefined;
    lookupOtp: (otpId: number) => OneTimePrekeyPair | undefined;
    seenHandshake: (spkId: number, hsDigest: B64u) => boolean;
    existing?: SessionState;
  }): SessionState;
  encrypt(params: {
    state: SessionState;
    plaintext: Uint8Array;
    ad: AssociatedData;
  }): {
    state: SessionState;
    message: MessageV2;
  };
  decrypt(params: {
    state: SessionState;
    message: MessageV2;
    expectedAd: AssociatedData;
  }): DecryptResult;
  inspectSession(state: SessionState): SessionInfo;

  recordRecoverySignal(
    tracker: RecoveryTrackerV1 | null,
    reason: RecoveryReason,
  ): RecoveryTrackerV1;
  recoveryDecision(tracker: RecoveryTrackerV1): {
    due: boolean;
    tracker: RecoveryTrackerV1;
  };
  refreshDecision(tracker: RecoveryTrackerV1 | null): {
    due: boolean;
    tracker: RecoveryTrackerV1;
  };
  onDecrypt(
    tracker: RecoveryTrackerV1,
    info: { advancedReceiveChain: boolean; sessionCreatedAt: string },
  ): RecoveryTrackerV1;

  serializeState(state: SessionState): string;
  parseState(raw: string): SessionState;
  serializeTracker(tracker: RecoveryTrackerV1): string;
  parseTracker(raw: string): RecoveryTrackerV1;
  parseMessage(raw: unknown): MessageV2;
  parseBundle(raw: unknown): DeviceBundleV2;
  parseDeviceList(raw: unknown): SignedDeviceList;
  canonicalJson(value: unknown): string;

  computeSafetyNumber(params: {
    local: { accountSignPk: B64u; stableId: string };
    remote: { accountSignPk: B64u; stableId: string };
  }): SafetyNumber;
  verifySafetyNumberPayload(local: SafetyNumber, scanned: Uint8Array): boolean;

  generateLinkEphemeral(): { pk: B64u; sk: B64u };
  generateLinkRequestId(): string;
  linkTranscript(params: {
    requestId: string;
    accountId: string;
    newDeviceId: string;
    newDeviceSignPk: B64u;
    newDeviceBoxPk: B64u;
    suites: string[];
  }): B64u;
  linkCommitment(transcript: B64u, ephNewPk: B64u): B64u;
  verifyLinkCommitment(
    commitment: B64u,
    transcript: B64u,
    ephNewPk: B64u,
  ): boolean;
  linkConfirmationCode(params: {
    transcript: B64u;
    ephNewPk: B64u;
    ephOldPk: B64u;
  }): string;
  sealAccountKey(params: {
    account: AccountIdentityKeyPair;
    transcript: B64u;
    ephSelf: { pk: B64u; sk: B64u };
    ephPeerPk: B64u;
  }): B64u;
  openAccountKey(params: {
    sealed: B64u;
    transcript: B64u;
    ephSelf: { pk: B64u; sk: B64u };
    ephPeerPk: B64u;
  }): AccountIdentityKeyPair;

  buildReportDisclosure(
    items: Array<{
      envelopeId: string;
      message: MessageV2;
      messageKey: Uint8Array;
      plaintext: Uint8Array;
    }>,
  ): ReportDisclosureV1;
  verifyReportDisclosureItem(
    item: ReportDisclosureV1["items"][number],
  ): boolean;
}

export type WithSessionFn<T> = (
  state: SessionState | null,
  tracker: RecoveryTrackerV1 | null,
) => Promise<{
  state: SessionState | null;
  tracker: RecoveryTrackerV1 | null;
  result: T;
}>;
