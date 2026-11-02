// In-memory reference KeyStore (SPEC §10.1), transactional or not, with crash injection.
import type {
  KeyStore,
  OneTimePrekeyPair,
  PutSessionOptions,
  SignedPrekeyPair,
  StoredSession,
} from "../src/index.js";

export class Crash extends Error {
  constructor(readonly point: string) {
    super(`crash at ${point}`);
  }
}

export type CrashPoint =
  | "put:before" // nothing written
  | "put:after-session" // non-transactional: session written, device records not yet
  | "put:mid-device" // non-transactional: some device records written
  | "put:after" // everything written, caller never sees the version
  | "deleteOtp:before";

const tick = () => new Promise<void>((r) => setTimeout(r, 0));

export class MemStore implements KeyStore {
  readonly sessions = new Map<string, StoredSession>();
  readonly spks = new Map<number, SignedPrekeyPair>();
  readonly otps = new Map<number, OneTimePrekeyPair>();
  readonly replay = new Map<number, Set<string>>();
  readonly writes: Array<{
    serialized: string | null;
    opts: PutSessionOptions;
  }> = [];
  crashAt: CrashPoint | null = null;
  /** Test knob: ignore deleteOtpIds in putSession, so only withSession's deleteOtp calls delete. */
  ignoreDeleteOtpIds = false;
  /** Test knob: apply replay records before OTP deletions in the device-level write. */
  replayFirst = false;
  private locks = new Map<string, Promise<unknown>>();
  private deviceMutex: Promise<unknown> = Promise.resolve();

  constructor(
    readonly transactional = true,
    readonly lockEnabled = true,
  ) {}

  private crash(p: CrashPoint): void {
    if (this.crashAt === p) {
      this.crashAt = null;
      throw new Crash(p);
    }
  }

  private applyDevice(opts: PutSessionOptions, crashMid: boolean): void {
    const otp = (this.ignoreDeleteOtpIds ? [] : (opts.deleteOtpIds ?? [])).map(
      (id) => () => void this.otps.delete(id),
    );
    const rec = (opts.acceptedHandshakes ?? []).map((r) => () => {
      if (!this.spks.has(r.spkId)) return; // SPEC §10.1: SPK gone, nothing to protect
      let s = this.replay.get(r.spkId);
      if (!s) this.replay.set(r.spkId, (s = new Set()));
      s.add(r.hsDigest);
    });
    const items: Array<() => void> = this.replayFirst
      ? [...rec, ...otp]
      : [...otp, ...rec];
    items.forEach((f, i) => {
      if (crashMid && i === Math.floor(items.length / 2))
        this.crash("put:mid-device");
      f();
    });
  }

  async getSession(peer: string, conv: string): Promise<StoredSession | null> {
    await tick();
    const s = this.sessions.get(`${peer}|${conv}`);
    return s ? { ...s } : null;
  }

  async putSession(
    peer: string,
    conv: string,
    serialized: string | null,
    expectedVersion: number | null,
    opts: PutSessionOptions = {},
  ): Promise<number> {
    await tick();
    const key = `${peer}|${conv}`;
    const cur = this.sessions.get(key);
    if ((cur?.version ?? null) !== expectedVersion)
      throw new Error("version mismatch");
    this.crash("put:before");
    const next: StoredSession = {
      serialized: serialized ?? cur?.serialized ?? null,
      version: (cur?.version ?? 0) + 1,
      tracker: opts.tracker ?? cur?.tracker ?? null,
    };
    this.writes.push({ serialized, opts: structuredClone(opts) });
    if (this.transactional) {
      this.sessions.set(key, next);
      this.applyDevice(opts, false);
    } else {
      this.sessions.set(key, next);
      this.crash("put:after-session");
      const run = this.deviceMutex.then(() => this.applyDevice(opts, true));
      this.deviceMutex = run.catch(() => undefined);
      await run;
    }
    this.crash("put:after");
    return next.version;
  }

  async getSpk(id: number) {
    await tick();
    return this.spks.get(id);
  }

  async getOtp(id: number) {
    await tick();
    return this.otps.get(id);
  }

  async deleteOtp(id: number): Promise<void> {
    await tick();
    this.crash("deleteOtp:before");
    this.otps.delete(id);
  }

  async hasAcceptedHandshake(spkId: number, d: string): Promise<boolean> {
    await tick();
    return this.replay.get(spkId)?.has(d) ?? false;
  }

  withLock<T>(conv: string, fn: () => Promise<T>): Promise<T> {
    if (!this.lockEnabled) return fn();
    const prev = this.locks.get(conv) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    this.locks.set(
      conv,
      run.catch(() => undefined),
    );
    return run;
  }

  /** Session-delete path (SPEC §8.5, §19 items 6 and 11). */
  deleteSession(peer: string, conv: string): void {
    this.sessions.delete(`${peer}|${conv}`);
  }
}
