// A consumer app built on the public API, following the SPEC §8.3/§8.4/§19 caller rules.
import {
  E2eeError,
  SUITES,
  withSession,
  type AssociatedData,
  type DeviceBundleV2,
  type DeviceIdentityKeyPair,
  type E2ee,
  type E2eeErrorCode,
  type MessageV2,
  type SessionState,
  type SuiteId,
} from "../src/index.js";
import { makeE2ee, testClock } from "./helpers.js";
import { MemStore } from "./store.js";

export const CONV = "conv-app";

export interface Received {
  text?: string;
  error?: E2eeErrorCode;
  reason?: unknown;
}

export class Device {
  readonly e: E2ee;
  readonly device: DeviceIdentityKeyPair;
  readonly store: MemStore;
  private nextOtp = 1;
  private nextSpk = 1;
  /** The conversation is live (the app's own rule), for null-state recovery. */
  live = true;

  /** Suites this device's library offers and initiates with; v1 only simulates a 1.0 peer. */
  suites: SuiteId[] = [...SUITES];

  constructor(
    readonly name: string,
    readonly clock = testClock(),
    transactional = true,
    lockEnabled = true,
    suites?: SuiteId[],
  ) {
    if (suites) this.suites = suites;
    this.e = makeE2ee(name, clock).e;
    this.device = this.e.generateDeviceIdentity(`${name}-dev`);
    this.store = new MemStore(transactional, lockEnabled);
    this.rotateSpk();
  }

  get id(): string {
    return this.device.deviceId;
  }

  rotateSpk(): number {
    const id = this.nextSpk++;
    this.store.spks.set(
      id,
      this.e.generateSignedPrekey(this.device, id, this.suites),
    );
    return id;
  }

  /** What the server serves; OTPs come from a persisted counter (SPEC §19 item 12). */
  bundle(withOtp = true): DeviceBundleV2 {
    const spkId = Math.max(...this.store.spks.keys());
    const b: DeviceBundleV2 = this.e.buildDeviceBundle({
      device: this.device,
      spk: this.store.spks.get(spkId)!,
    });
    if (!withOtp) return b;
    const [otp] = this.e.generateOneTimePrekeys(this.nextOtp++, 1);
    this.store.otps.set(otp!.otpId, otp!);
    return { ...b, otp: { otpId: otp!.otpId, pk: otp!.pk } };
  }

  /** Upgrade to a library with suite v2: offer it from a new SPK (SPEC §19 item 16). */
  upgrade(): void {
    this.suites = [...SUITES];
    this.rotateSpk();
  }

  /** The AD of `suite` from this device to `to` (SPEC §7.4, §19 item 15). */
  ad(to: Device, suite: SuiteId): AssociatedData {
    return suite === "x25519-xchacha20poly1305-sha256-v2"
      ? {
          conversationId: CONV,
          senderDeviceId: this.id,
          recipientDeviceId: to.id,
          suite,
          v: 2,
        }
      : { conversationId: CONV, senderDeviceId: this.id, suite, v: 2 };
  }

  /** initiateSession with the suite this device's library would pick (the first it supports). */
  initiate(peer: Device, existing: SessionState | null, withOtp = true) {
    const peerBundle = peer.bundle(withOtp);
    const suite = peerBundle.suites.find((x) =>
      (this.suites as string[]).includes(x),
    ) as SuiteId | undefined;
    return this.e.initiateSession({
      conversationId: CONV,
      self: this.device,
      peerBundle,
      ...(suite ? { suite } : {}),
      ...(existing ? { existing } : {}),
    });
  }

  /** encrypt with the AD of the state's active suite. */
  encrypt(peer: Device, s: SessionState, text: string) {
    return this.e.encrypt({
      state: s,
      plaintext: new TextEncoder().encode(text),
      ad: this.ad(peer, this.e.inspectSession(s).suite),
    });
  }

  /** Send; initiates on first contact. The state is persisted before the message is returned. */
  send(peer: Device, text: string, withOtp = true): Promise<MessageV2> {
    return withSession(
      this.e,
      this.store,
      peer.id,
      CONV,
      async (state, _tracker) => {
        const s = state ?? this.initiate(peer, null, withOtp);
        const r = this.encrypt(peer, s, text);
        return { state: r.state, tracker: null, result: r.message };
      },
    );
  }

  /** SPEC §8.3 receive flow with recovery signals. */
  receive(peer: Device, m: MessageV2): Promise<Received> {
    const e = this.e;
    const store = this.store;
    return withSession<Received>(
      e,
      store,
      peer.id,
      CONV,
      async (state, tracker) => {
        const acceptFrom = async (existing: SessionState | null) => {
          const h = m.handshake;
          const spk = h ? await store.getSpk(h.spkId) : undefined;
          const otp =
            h?.otpId !== undefined ? await store.getOtp(h.otpId) : undefined;
          const seen = h
            ? await store.hasAcceptedHandshake(h.spkId, e.handshakeDigest(h))
            : false;
          return e.acceptSession({
            conversationId: CONV,
            self: this.device,
            expectedPeerBoxPk: peer.device.boxPk, // pinned, never from the message (F-4)
            expectedPeerSignPk: peer.device.signPk,
            message: m,
            lookupSpk: (id) => (h && id === h.spkId ? spk : undefined),
            lookupOtp: (id) => (h && id === h.otpId ? otp : undefined),
            seenHandshake: () => seen,
            ...(existing ? { existing } : {}),
          });
        };
        try {
          let r;
          if (state === null)
            r = e.decrypt({
              state: await acceptFrom(null),
              message: m,
              expectedAd: peer.ad(this, m.suite),
            });
          else
            try {
              r = e.decrypt({
                state,
                message: m,
                expectedAd: peer.ad(this, m.suite),
              });
            } catch (err) {
              if (
                !(err instanceof E2eeError) ||
                err.code !== "E2EE_SESSION_CONFLICT"
              )
                throw err;
              r = e.decrypt({
                state: await acceptFrom(state),
                message: m,
                expectedAd: peer.ad(this, m.suite),
              });
            }
          const t = tracker === null ? null : e.onDecrypt(tracker, r);
          return {
            state: r.state,
            tracker: t,
            result: { text: new TextDecoder().decode(r.plaintext) },
          };
        } catch (err) {
          if (!(err instanceof E2eeError)) throw err;
          const reason =
            err.code === "E2EE_HANDSHAKE_REQUIRED" &&
            (state !== null || this.live)
              ? "handshake-required"
              : err.code === "E2EE_DUPLICATE_MESSAGE" &&
                  err.details?.["reason"] === "evicted-session"
                ? "evicted-session"
                : null;
          if (reason !== null)
            return {
              state: null,
              tracker: e.recordRecoverySignal(tracker, reason),
              result: { error: err.code, reason },
            };
          return {
            state: null,
            tracker: null,
            result: { error: err.code, reason: err.details?.["reason"] },
          };
        }
      },
    );
  }

  /** SPEC §8.4: re-initiate when recovery is due, then send the control message. */
  maybeRecover(peer: Device): Promise<MessageV2 | null> {
    return withSession(
      this.e,
      this.store,
      peer.id,
      CONV,
      async (state, tracker) => {
        if (tracker === null)
          return { state: null, tracker: null, result: null };
        const d = this.e.recoveryDecision(tracker);
        if (!d.due || (state === null && !this.live))
          return { state: null, tracker: d.tracker, result: null };
        const s = this.initiate(peer, state);
        const r = this.encrypt(peer, s, "session-refresh");
        return { state: r.state, tracker: d.tracker, result: r.message };
      },
    );
  }

  /** Session-delete path, under the conversation lock: flush pending lists, then delete session and tracker (SPEC §8.5). */
  deleteSession(peer: Device): Promise<void> {
    return this.store.withLock(CONV, async () => {
      const cur = await this.store.getSession(peer.id, CONV);
      if (cur?.serialized) {
        const info = this.e.inspectSession(this.e.parseState(cur.serialized));
        await this.store.putSession(peer.id, CONV, null, cur.version, {
          deleteOtpIds: info.pendingOtpDeletes,
          acceptedHandshakes: info.pendingReplayRecords,
        });
        for (const id of info.pendingOtpDeletes) await this.store.deleteOtp(id);
      }
      this.store.deleteSession(peer.id, CONV);
    });
  }

  async state(peer: Device): Promise<Record<string, unknown> | null> {
    const raw = (await this.store.getSession(peer.id, CONV))?.serialized;
    return raw ? (JSON.parse(raw) as Record<string, unknown>) : null;
  }
}
