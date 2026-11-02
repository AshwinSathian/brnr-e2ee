# brnr-e2ee

[![npm](https://img.shields.io/npm/v/brnr-e2ee)](https://www.npmjs.com/package/brnr-e2ee)
[![CI](https://github.com/AshwinSathian/brnr-e2ee/actions/workflows/ci.yml/badge.svg)](https://github.com/AshwinSathian/brnr-e2ee/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/AshwinSathian/brnr-e2ee/badge)](https://scorecard.dev/viewer/?uri=github.com/AshwinSathian/brnr-e2ee)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

End-to-end encryption for one-to-one messaging, in TypeScript. It implements X3DH key agreement, the Double Ratchet with XChaCha20-Poly1305, and Sesame-style management of several sessions per peer device, on top of the [`@noble`](https://paulmillr.com/noble/) primitives.

> [!WARNING]
> **brnr-e2ee has not had an independent security audit.** It has a byte-exact specification, an independent reference implementation, Wycheproof and known-answer tests, property-based and fuzz tests, and mutation testing, all described below. None of that replaces an audit. Read [THREATMODEL.md](THREATMODEL.md) before you rely on it.

I wrote it for two of my apps, BRNR and lowercase, which both depend on it. It's published so that anyone can read it, check it and use it.

## Contents

- [What it does](#what-it-does)
- [What it doesn't do](#what-it-doesnt-do)
- [Install](#install)
- [Quick start](#quick-start)
- [API](#api)
- [Your responsibilities as a consumer](#your-responsibilities-as-a-consumer)
- [How it is tested](#how-it-is-tested)
- [Supply chain](#supply-chain)
- [Test vectors](#test-vectors)
- [Versioning](#versioning)
- [Contributing](#contributing)
- [Licence](#licence)

## What it does

- **X3DH** with separate Ed25519 signing keys and X25519 box keys. 4-DH when a one-time prekey is available, 3-DH when it isn't ([SPEC §6](SPEC.md)).
- **Identity binding.** Suite v2, the default from 1.1.0, binds both devices' id, signing key and box key into the key agreement and every message key, which stops the unknown-key-share attacks that v1 allows. A conversation that reaches v2 never drops back to v1 ([SPEC §6.5](SPEC.md)).
- **The Double Ratchet** with XChaCha20-Poly1305. The header, the handshake and your associated data are all bound into the AEAD, message sizes are padded to buckets, and skipped keys are capped and expire ([SPEC §7](SPEC.md)).
- **Sessions in the style of Sesame**: up to three live sessions per peer device, routed by a session id, with rate-limited recovery when the two sides disagree ([SPEC §8](SPEC.md)).
- **Device identity**: signed device bundles and device lists, Signal-compatible safety numbers, a device-link ceremony and report disclosure ([SPEC §5, §12-§14](SPEC.md#5-keys-bundles-and-device-lists)).
- **Strict, typed failure.** Every error is an `E2eeError` with one of 19 codes, inputs are parsed against strict schemas, and a rejected message never changes state ([SPEC §16](SPEC.md#16-errors)).

It holds no storage and makes no network calls. You give it a `KeyStore`, and it tells you exactly what to persist and when.

The four runtime dependencies are `@noble/curves`, `@noble/ciphers`, `@noble/hashes` and `zod`, each pinned to an exact version. The build is ESM and CommonJS with type declarations for both, and it runs on Node 22.12 or later, in browsers, and on React Native (Hermes).

## What it doesn't do

These are deferred, not forgotten ([SPEC §2](SPEC.md#2-scope)):

- header encryption, sealed sender, and other metadata protection; the server still sees who talks to whom and when;
- post-quantum key agreement (PQXDH) or ratchets;
- groups (MLS), the Sesame multi-device send loop, and history sync or key backup;
- message franking and key transparency.

It also doesn't wipe keys from memory, because JavaScript strings can't be wiped ([THREATMODEL item 8](THREATMODEL.md#known-limits-and-accepted-risks)).

## Install

```sh
npm install --save-exact brnr-e2ee
```

Pin the exact version: a minor release can add a cipher suite, and you'll want to review that before you take it ([Versioning](#versioning)).

On React Native, where `globalThis.crypto` doesn't exist, install a `crypto.getRandomValues` polyfill before anything imports this library, and pass a secure `rng` to `createE2ee`. `@noble/curves` checks for WebCrypto once, when it loads, and uses it to blind secret scalar multiplications ([THREATMODEL item 16](THREATMODEL.md#known-limits-and-accepted-risks)).

## Quick start

Alice starts a session with Bob from his published bundle and sends him a message. This exact code runs in CI as [`test/readme.test.ts`](https://github.com/AshwinSathian/brnr-e2ee/blob/main/test/readme.test.ts).

```ts
import {
  createE2ee,
  E2eeError,
  SUITES,
  withSession,
  type KeyStore,
  type MessageV2,
  type OneTimePrekeyPair,
  type SignedPrekeyPair,
  type StoredSession,
} from "brnr-e2ee";

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

const m = await aliceSends("hello bob");
console.log(await bobReceives(m)); // "hello bob"
```

A real app also follows the recovery and refresh rules in [SPEC §8.4](SPEC.md) (`recoveryDecision`, `refreshDecision`, and a control message after every re-initiation), and its delete paths flush the pending lists first (§8.5).

## API

Everything starts from `createE2ee()`, which returns an object with the protocol functions. The full reference, generated from the type declarations, is at **[ashwinsathian.github.io/brnr-e2ee](https://ashwinsathian.github.io/brnr-e2ee/)**, and [SPEC.md](SPEC.md) defines what each function does, byte for byte.

| Area                     | Functions                                                                                                                                                                     |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Keys                     | `generateAccountIdentity`, `generateDeviceIdentity`, `generateSignedPrekey`, `generateOneTimePrekeys`                                                                         |
| Bundles and device lists | `buildDeviceBundle`, `verifyDeviceBundle`, `parseBundle`, `buildSignedDeviceList`, `verifySignedDeviceList`, `parseDeviceList`, `deviceListDigest`, `bundleMatchesDeviceList` |
| Sessions                 | `initiateSession`, `acceptSession`, `encrypt`, `decrypt`, `inspectSession`, `handshakeDigest`, `parseMessage`, `serializeState`, `parseState`                                 |
| Recovery                 | `recordRecoverySignal`, `recoveryDecision`, `refreshDecision`, `onDecrypt`, `serializeTracker`, `parseTracker`                                                                |
| Safety numbers           | `computeSafetyNumber`, `verifySafetyNumberPayload`                                                                                                                            |
| Device linking           | `generateLinkEphemeral`, `generateLinkRequestId`, `linkTranscript`, `linkCommitment`, `verifyLinkCommitment`, `linkConfirmationCode`, `sealAccountKey`, `openAccountKey`      |
| Reports                  | `buildReportDisclosure`, `verifyReportDisclosureItem`                                                                                                                         |
| Top-level exports        | `createE2ee`, `withSession`, `E2eeError`, `isE2eeError`, `E2EE_ERROR_CODES`, `SUITES`, `LIMITS`, and the types (`KeyStore`, `MessageV2`, `StoredSession`, …)                  |

`brnr-e2ee/testing` exports the deterministic RNG, the fingerprint chain and operation counters that the vectors and benchmarks use. It's outside the SemVer guarantees; don't use it in an app. `createE2ee` refuses its RNGs unless you pass `dangerouslyAllowTestRng: true`.

## Your responsibilities as a consumer

The library can only keep its promises if the app around it does its part. [SPEC §19](SPEC.md#19-consumer-responsibilities) is the normative list. You MUST:

1. Provide a cryptographically secure `rng` where `globalThis.crypto` is absent (React Native/Hermes). Also install a `globalThis.crypto.getRandomValues` polyfill before the library first loads, so `@noble/curves` can blind secret scalar multiplications (see THREATMODEL.md item 16).
2. Persist every state returned by `encrypt` **before** sending.
3. Route every encrypt and decrypt through `withSession`.
4. Take `expectedPeerBoxPk` and `expectedPeerSignPk` from a pinned, verified bundle or device list, **never** from the message being processed.
5. Keep retired SPK private keys for at least the maximum offline-delivery window (the longest time your server holds an undelivered message), and delete each SPK's replay set with it.
6. Flush `pendingOtpDeletes` and `pendingReplayRecords` before deleting any session.
7. Catch the recovery triggers in `fn`, follow §8.4, and send the control message after every re-initiation.
8. Never restore session state from backups.
9. Enforce server caps of at least `MAX_WIRE_BYTES`, and require canonical payloads (`payload === canonicalJson(parseMessage(payload))`) where reports are supported.
10. Never send error codes to the server.
11. Delete a session's tracker on every path that deletes the session.
12. Never reuse an `spkId` or `otpId` on a device; take ids from a persisted counter.
13. If `parseState` fails inside `withSession`, delete the session and tracker through the app's delete path, and run an OTP expiry as §19 item 13 describes.
14. Compute handshake digests with `handshakeDigest`, never by hand.
15. Once every client you support runs 1.1.0 or later, publish SPKs that list only suite v2 and pass `suite: "x25519-xchacha20poly1305-sha256-v2"` to `initiateSession`. Until then, a first contact can still fall back to v1 and its unknown-key-share weakness (§19 item 17).

## How it is tested

What was done instead of an audit, so you can judge it for yourself:

- **A normative spec.** [SPEC.md](SPEC.md) is written so that a second implementation can be built from it alone. [`scripts/ref/`](https://github.com/AshwinSathian/brnr-e2ee/tree/main/scripts/ref) is one, written from the spec without reading the library, and CI checks that the two agree on every vector (319 checks).
- **Deterministic vectors.** The 22 files in [`vectors/`](https://github.com/AshwinSathian/brnr-e2ee/tree/main/vectors) are regenerated from fixed seeds on every run and must match byte for byte.
- **Known-answer tests** from RFC 7748, RFC 8032, RFC 5869, RFC 4231 and the XChaCha20 draft, **Wycheproof** vectors for X25519, Ed25519 and XChaCha20-Poly1305, and libsignal's published test values for safety numbers.
- **A fast-check command model** that runs two parties and three devices through sessions, crashes, replays, reordering and recovery, plus fuzzing of every parser and of `decrypt` and `acceptSession` with mutated input. `npm run test:release` runs 10,000 cases of each.
- **Mutation testing** with Stryker. The gate is 90% overall and 85% per file; 1.1.0 scores 97.4%.
- **A counted-operation budget** for the worst-case decrypt, so a hostile peer can't make one message cost more than [SPEC §17](SPEC.md#17-limits) allows.
- **Adversarial reviews** of the spec and the code, done by the author with automated tooling. The exploits and checks from the 1.1.0 review are kept as tests in [`test/security/`](https://github.com/AshwinSathian/brnr-e2ee/tree/main/test/security). They're no substitute for an independent reviewer.

## Supply chain

- Four runtime dependencies, pinned exact. [`scripts/check-deps.mjs`](https://github.com/AshwinSathian/brnr-e2ee/blob/main/scripts/check-deps.mjs) fails the build if the list changes or if any package in the production tree has a non-permissive licence.
- No install scripts, here or in any runtime dependency, and CI installs with `--ignore-scripts`.
- Releases are built and published by [`release.yml`](https://github.com/AshwinSathian/brnr-e2ee/blob/main/.github/workflows/release.yml) through npm trusted publishing. There is no npm token to steal, and every version carries a provenance attestation that ties the tarball to the commit and the workflow run. Check it with:

  ```sh
  npm audit signatures
  ```

- Each GitHub release has the same tarball attached, with its SHA-256.
- Workflow actions are pinned to commit SHAs and audited with zizmor; gitleaks, semgrep and OSV-Scanner run on every push to `main` and on every pull request.

## Test vectors

The vectors ship in the package, so another implementation can test against them without cloning this repo:

```ts
import x3dh from "brnr-e2ee/vectors/x3dh.json" with { type: "json" };
```

Each file starts with a `description`. Most hold a list of `cases` with inputs and expected outputs; the conversation vectors hold `parties` and a list of `events` to replay in order. [SPEC §15](SPEC.md#15-randomness) describes the deterministic RNG the vectors were generated with.

## Versioning

The package follows SemVer, and the wire format is versioned separately ([SPEC §18](SPEC.md#18-versioning)):

- any change to a label, KDF input, primitive or limit that affects the wire is a new **suite id**; 1.0 implements `x25519-xchacha20poly1305-sha256-v1`, and 1.1 adds `x25519-xchacha20poly1305-sha256-v2` and prefers it;
- a new suite or a new optional field is a minor release;
- removing a suite, or changing how an existing one behaves, is a major release.

Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Bug reports, questions about the spec, and pull requests are welcome; [CONTRIBUTING.md](CONTRIBUTING.md) explains how to set up and what the checks expect. Please report security issues privately, as [SECURITY.md](SECURITY.md) describes, and not in a public issue.

## Licence

[MIT](LICENSE) © Ashwin Sathian
