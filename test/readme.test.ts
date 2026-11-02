// The README example, kept runnable. If this file changes, update README.md to match.
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import {
  createE2ee,
  E2eeError,
  withSession,
  type AssociatedData,
  type KeyStore,
  type MessageV2,
  type OneTimePrekeyPair,
  type SignedPrekeyPair,
  type StoredSession,
  type SuiteId,
} from "../src/index.js";

// README:begin
/** A minimal in-memory KeyStore. Real apps use IndexedDB, SQLite or an encrypted file store. */
class MemoryKeyStore implements KeyStore {
  sessions = new Map<string, StoredSession>();
  spks = new Map<number, SignedPrekeyPair>();
  otps = new Map<number, OneTimePrekeyPair>();
  replay = new Set<string>();
  private locks = new Map<string, Promise<unknown>>();

  async getSession(peer: string, conv: string) {
    return this.sessions.get(`${peer}|${conv}`) ?? null;
  }
  async putSession(
    peer: string,
    conv: string,
    serialized: string | null,
    expected: number | null,
    opts: Parameters<KeyStore["putSession"]>[4] = {},
  ) {
    const key = `${peer}|${conv}`;
    const cur = this.sessions.get(key);
    if ((cur?.version ?? null) !== expected)
      throw new Error("version mismatch");
    const version = (cur?.version ?? 0) + 1;
    // One "transaction": session, tracker, OTP deletions and replay records together.
    this.sessions.set(key, {
      serialized: serialized ?? cur?.serialized ?? null,
      version,
      tracker: opts.tracker ?? cur?.tracker ?? null,
    });
    for (const id of opts.deleteOtpIds ?? []) this.otps.delete(id);
    for (const r of opts.acceptedHandshakes ?? [])
      if (this.spks.has(r.spkId)) this.replay.add(`${r.spkId}:${r.hsDigest}`);
    return version;
  }
  async getSpk(id: number) {
    return this.spks.get(id);
  }
  async getOtp(id: number) {
    return this.otps.get(id);
  }
  async deleteOtp(id: number) {
    this.otps.delete(id);
  }
  async hasAcceptedHandshake(spkId: number, digest: string) {
    return this.replay.has(`${spkId}:${digest}`);
  }
  withLock<T>(conv: string, fn: () => Promise<T>): Promise<T> {
    const run = (this.locks.get(conv) ?? Promise.resolve()).then(fn, fn);
    this.locks.set(
      conv,
      run.catch(() => undefined),
    );
    return run;
  }
}

const e2ee = createE2ee(); // pass { rng } on React Native / Hermes
const conversationId = "conv-1";

// Bob publishes a bundle (the server stores it and hands out one OTP per fetch).
const bobStore = new MemoryKeyStore();
const bob = e2ee.generateDeviceIdentity("bob-phone");
const spk = e2ee.generateSignedPrekey(bob, 1);
const [otp] = e2ee.generateOneTimePrekeys(1, 1);
bobStore.spks.set(spk.spkId, spk);
bobStore.otps.set(otp!.otpId, otp!);
const bobBundle = {
  ...e2ee.buildDeviceBundle({ device: bob, spk }),
  otp: { otpId: otp!.otpId, pk: otp!.pk },
};

// Alice sends the first message. The state is persisted before the message leaves.
const aliceStore = new MemoryKeyStore();
const alice = e2ee.generateDeviceIdentity("alice-laptop");
// The AD's shape follows the suite: suite v2 also names the recipient device.
const ad = (suite: SuiteId, from: string, to: string): AssociatedData =>
  suite === "x25519-xchacha20poly1305-sha256-v2"
    ? {
        conversationId,
        senderDeviceId: from,
        recipientDeviceId: to,
        suite,
        v: 2,
      }
    : { conversationId, senderDeviceId: from, suite, v: 2 };

async function aliceSends(text: string): Promise<MessageV2> {
  return withSession(
    e2ee,
    aliceStore,
    bob.deviceId,
    conversationId,
    async (state, tracker) => {
      const s =
        state ??
        e2ee.initiateSession({
          conversationId,
          self: alice,
          peerBundle: bobBundle,
        });
      const r = e2ee.encrypt({
        state: s,
        plaintext: new TextEncoder().encode(text),
        ad: ad(e2ee.inspectSession(s).suite, alice.deviceId, bob.deviceId),
      });
      return { state: r.state, tracker, result: r.message };
    },
  );
}

// Bob receives (SPEC §8.3). The pinned keys come from a verified bundle, never from the message.
async function bobReceives(m: MessageV2): Promise<string | null> {
  return withSession(
    e2ee,
    bobStore,
    alice.deviceId,
    conversationId,
    async (state, tracker) => {
      const accept = async (existing: typeof state) => {
        const h = m.handshake!;
        const s = await bobStore.getSpk(h.spkId);
        const o =
          h.otpId === undefined ? undefined : await bobStore.getOtp(h.otpId);
        const seen = await bobStore.hasAcceptedHandshake(
          h.spkId,
          e2ee.handshakeDigest(h),
        );
        return e2ee.acceptSession({
          conversationId,
          self: bob,
          expectedPeerBoxPk: alice.boxPk,
          expectedPeerSignPk: alice.signPk,
          message: m,
          lookupSpk: () => s,
          lookupOtp: () => o,
          seenHandshake: () => seen,
          ...(existing ? { existing } : {}),
        });
      };
      try {
        let r;
        try {
          r = e2ee.decrypt({
            state: state ?? (await accept(null)),
            message: m,
            expectedAd: ad(m.suite, alice.deviceId, bob.deviceId),
          });
        } catch (err) {
          if (
            !(err instanceof E2eeError) ||
            err.code !== "E2EE_SESSION_CONFLICT" ||
            !state
          )
            throw err;
          r = e2ee.decrypt({
            state: await accept(state),
            message: m,
            expectedAd: ad(m.suite, alice.deviceId, bob.deviceId),
          });
        }
        const t = tracker ? e2ee.onDecrypt(tracker, r) : null;
        return {
          state: r.state,
          tracker: t,
          result: new TextDecoder().decode(r.plaintext),
        };
      } catch (err) {
        // Recovery triggers update the tracker (SPEC §8.4); other errors drop the message.
        const reason =
          err instanceof E2eeError && err.code === "E2EE_HANDSHAKE_REQUIRED"
            ? "handshake-required"
            : err instanceof E2eeError &&
                err.details?.["reason"] === "evicted-session"
              ? "evicted-session"
              : null;
        if (reason)
          return {
            state: null,
            tracker: e2ee.recordRecoverySignal(tracker, reason),
            result: null,
          };
        if (err instanceof E2eeError)
          return { state: null, tracker: null, result: null };
        throw err;
      }
    },
  );
}
// README:end

it("README.md carries this example verbatim", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const self = readFileSync(new URL(import.meta.url), "utf8");
  const snippet = self
    .slice(
      self.indexOf("// README:begin\n") + 16,
      self.indexOf("// README:end"),
    )
    .trimEnd();
  expect(readme).toContain(snippet);
});

it("README example runs", async () => {
  expect(await bobReceives(await aliceSends("hello bob"))).toBe("hello bob");
  expect(bobStore.otps.size).toBe(0);
  expect(await bobReceives(await aliceSends("second"))).toBe("second");
});
