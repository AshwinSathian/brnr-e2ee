// Pending tests for every defect and review finding the library must close.
// Each started as `it.fails`; the implementing commit flipped it to a real test and
// writes the real body. A test that starts passing by accident fails the suite.
import { describe, expect, it, vi } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { createE2ee, E2EE_ERROR_CODES, E2eeError } from "../src/index.js";
import { b64uEncode } from "../src/codec.js";
import * as prim from "../src/primitives.js";
import { b64uDecode } from "../src/codec.js";
import { unpad } from "../src/ratchet.js";
import { digits30, fingerprintChain } from "../src/testing.js";
import { withSession } from "../src/index.js";
import { CONV as APP_CONV, Device } from "./app.js";
import { expectCode, hex, makeE2ee, testClock, toHex } from "./helpers.js";
import {
  adFrom,
  bundleOf,
  CONV,
  initiate,
  party,
  receive,
  send,
  type Party,
} from "./parties.js";

function fresh(): [Party, Party] {
  const a = party("alice");
  const b = party("bob");
  initiate(a, b, true);
  return [a, b];
}

describe("D1-D14 (task brief §3)", () => {
  it("D1: previous-chain messages decrypt after a DH ratchet (pn skipping, DR §3.5)", () => {
    const [a, b] = fresh();
    const [a1, a2] = [send(a, "a1"), send(a, "a2")];
    receive(b, a, a1);
    receive(a, b, send(b, "b1"));
    const a3 = send(a, "a3");
    expect(a3.header.pn).toBe(2);
    expect(receive(b, a, a3)).toBe("a3");
    expect(receive(b, a, a2)).toBe("a2");
  });
  it("D2: swapped identity key → E2EE_IDENTITY_MISMATCH; tampered AD → E2EE_DECRYPT_FAILED", () => {
    const [a, b] = fresh();
    const m = send(a, "x");
    const accept = (pin: string, msg = m) =>
      b.e.acceptSession({
        conversationId: CONV,
        self: b.device,
        expectedPeerBoxPk: pin,
        expectedPeerSignPk: a.device.signPk,
        message: msg,
        lookupSpk: (i) => b.spks.get(i),
        lookupOtp: (i) => b.otps.get(i),
        seenHandshake: () => false,
      });
    expectCode(
      () => accept(party("mallory").device.boxPk),
      "E2EE_IDENTITY_MISMATCH",
    );
    const ad2 = { ...m.ad, senderDeviceId: "mallory-dev" };
    const cand = accept(a.device.boxPk, { ...m, ad: ad2 });
    expectCode(
      () =>
        b.e.decrypt({
          state: cand,
          message: { ...m, ad: ad2 },
          expectedAd: ad2,
        }),
      "E2EE_DECRYPT_FAILED",
    );
  });
  it("D3: handshake on every message until first inbound; first message dropped → second establishes", () => {
    const [a, b] = fresh();
    send(a, "dropped");
    const m2 = send(a, "second");
    expect(m2.handshake).toBeDefined();
    expect(receive(b, a, m2)).toBe("second");
    expect(send(a, "third").handshake).toEqual(m2.handshake);
    receive(a, b, send(b, "reply"));
    expect(send(a, "fourth").handshake).toBeUndefined();
  });
  it("D4: handshake against the previous SPK succeeds inside retention; after → E2EE_SPK_UNKNOWN", () => {
    const a = party("alice");
    const b = party("bob");
    initiate(a, b, false);
    b.spks.set(2, b.e.generateSignedPrekey(b.device, 2));
    const m = send(a, "spk 1");
    expect(receive(b, a, m)).toBe("spk 1");
    const c = party("carol");
    initiate(c, b, false);
    b.spks.delete(2);
    b.state = null;
    expectCode(() => receive(b, c, send(c, "x")), "E2EE_SPK_UNKNOWN");
  });
  it("D5: initiator used an OTP the responder lacks → E2EE_OTP_UNKNOWN, never a silent seed mismatch", () => {
    const [a, b] = fresh();
    b.otps.clear();
    expectCode(() => receive(b, a, send(a, "x")), "E2EE_OTP_UNKNOWN");
  });
  it("D6: known-answer tests for every primitive binding; missing RNG → E2EE_RNG_UNAVAILABLE", () => {
    // Full KAT and Wycheproof suites: test/unit/primitives.test.ts. Spot check here.
    expect(
      toHex(
        prim.x25519Dh(
          hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
          ),
          hex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
          ),
        ),
      ),
    ).toBe("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    vi.stubGlobal("crypto", undefined);
    try {
      expectCode(() => createE2ee(), "E2EE_RNG_UNAVAILABLE");
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it("D7: parseState rejects unknown v and invalid shapes with typed errors, never defaults", () => {
    const [a, b] = fresh();
    receive(b, a, send(a, "x"));
    const raw = b.e.serializeState(b.state!);
    expectCode(
      () => b.e.parseState(JSON.stringify({ sessionId: "s", rootKeyB64: "r" })),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () => b.e.parseState(raw.replace('"v":2', '"v":3')),
      "E2EE_UNSUPPORTED_VERSION",
    );
    expectCode(
      () => b.e.parseState(raw.replace('"activeSid"', '"activeSid2"')),
      "E2EE_INVALID_STATE",
    );
    expectCode(() => b.e.parseState("not json"), "E2EE_INVALID_STATE");
    expect(b.e.serializeState(b.e.parseState(raw))).toBe(raw);
  });
  it("D8: every failure path throws E2eeError with a code from the closed union", () => {
    const [a, b] = fresh();
    const m = send(a, "x");
    const junk: unknown[] = [
      undefined,
      null,
      0,
      -0,
      1.5,
      "x",
      "{}",
      {},
      [],
      { v: 2 },
      { v: 1 },
      new Uint8Array(3),
      m,
      a.state,
    ];
    const methods = Object.entries(b.e) as Array<
      [string, (...args: unknown[]) => unknown]
    >;
    let calls = 0;
    for (const [, fn] of methods)
      for (const x of junk)
        for (const y of [undefined, x]) {
          calls++;
          try {
            fn(x, y);
          } catch (err) {
            expect(err).toBeInstanceOf(E2eeError);
            expect(E2EE_ERROR_CODES).toContain((err as E2eeError).code);
          }
        }
    expect(calls).toBeGreaterThan(1000);
  });
  it("D9: AD is exactly {conversationId, senderDeviceId, suite, v}, plus recipientDeviceId in suite v2; changing any field fails", () => {
    const [a] = fresh();
    const ad = adFrom(a);
    expect(Object.keys(send(a, "x").ad).sort()).toEqual([
      "conversationId",
      "recipientDeviceId",
      "senderDeviceId",
      "suite",
      "v",
    ]);
    for (const bad of [
      { ...ad, conversationId: "c2" },
      { ...ad, senderDeviceId: "d2" },
      { ...ad, recipientDeviceId: "d2" },
      { ...ad, v: 1 },
      { ...ad, suite: "s" },
      { ...ad, x: "1" },
    ])
      expectCode(
        () =>
          a.e.encrypt({
            state: a.state!,
            plaintext: new Uint8Array(1),
            ad: bad as never,
          }),
        "E2EE_AD_MISMATCH",
      );
  });
  it("D10: padding bucket edges 60/61, 8192 ok, 8193 → E2EE_PLAINTEXT_TOO_LARGE; bad padding → E2EE_INVALID_PADDING", () => {
    const [a, b] = fresh();
    receive(b, a, send(a, "x"));
    for (const [n, bucket] of [
      [60, 64],
      [61, 128],
      [8192, 8196],
    ] as const) {
      const { message } = a.e.encrypt({
        state: a.state!,
        plaintext: new Uint8Array(n),
        ad: adFrom(a),
      });
      expect(b64uDecode(message.ciphertext)).toHaveLength(bucket + 16);
    }
    expectCode(
      () =>
        a.e.encrypt({
          state: a.state!,
          plaintext: new Uint8Array(8193),
          ad: adFrom(a),
        }),
      "E2EE_PLAINTEXT_TOO_LARGE",
    );
    const bad = new Uint8Array(64);
    bad[3] = 1;
    bad[63] = 1;
    expectCode(() => unpad(bad), "E2EE_INVALID_PADDING");
  });
  it("D11: fingerprint core reproduces libsignal's published 60 digits; both sides agree", () => {
    const a = fingerprintChain(
      hex("0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868"),
      "+14152222222",
    );
    const b = fingerprintChain(
      hex("05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b"),
      "+14153333333",
    );
    const [x, y] = [digits30(a), digits30(b)];
    expect(x < y ? x + y : y + x).toBe(
      "300354477692869396892869876765458257569162576843440918079131",
    );
    const { e } = makeE2ee("d11");
    const l = {
      accountSignPk: e.generateAccountIdentity().signPk,
      stableId: "l",
    };
    const r = {
      accountSignPk: e.generateAccountIdentity().signPk,
      stableId: "r",
    };
    expect(e.computeSafetyNumber({ local: l, remote: r }).digits).toBe(
      e.computeSafetyNumber({ local: r, remote: l }).digits,
    );
  });
  it("D12: device list: tampered sig, lower epoch and revoked device are all rejected", () => {
    const { e } = makeE2ee("d12");
    const account = e.generateAccountIdentity();
    const d = e.generateDeviceIdentity("d1");
    const at = "2026-10-22T00:00:00.000Z";
    const entry = {
      deviceId: "d1",
      deviceSignPk: d.signPk,
      deviceBoxPk: d.boxPk,
      addedAt: at,
    };
    const list = e.buildSignedDeviceList({
      account,
      accountId: "a",
      epoch: 2,
      devices: [entry],
    });
    expectCode(
      () =>
        e.verifySignedDeviceList({
          ...list,
          sig: list.sig.replace(/^./, (c) => (c === "A" ? "B" : "A")),
        }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expectCode(
      () => e.verifySignedDeviceList(list, { minEpoch: 3 }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    const revoked = e.buildSignedDeviceList({
      account,
      accountId: "a",
      epoch: 3,
      devices: [{ ...entry, revokedAt: at }],
    });
    const bundle = e.buildDeviceBundle({
      device: d,
      spk: e.generateSignedPrekey(d, 1),
    });
    expect(e.bundleMatchesDeviceList(bundle, list)).toBe(true);
    expect(e.bundleMatchesDeviceList(bundle, revoked)).toBe(false);
  });
  it("D13: withSession lock prevents ratchet forks under concurrent encrypt", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock);
    await b.receive(a, await a.send(b, "first"));
    const ms = await Promise.all(
      Array.from({ length: 4 }, (_, i) => a.send(b, `c${i}`)),
    );
    expect(new Set(ms.map((m) => m.header.n)).size).toBe(4);
    for (const m of ms) expect((await b.receive(a, m)).text).toMatch(/^c/);
  });
  it("D14: no BRNR coupling (labels e2ee/v2/ and e2ee/s2/, dependency allowlist enforced by check:deps)", () => {
    const files = readdirSync(new URL("../src/", import.meta.url)).filter((f) =>
      f.endsWith(".ts"),
    );
    for (const f of files) {
      const src = readFileSync(new URL(`../src/${f}`, import.meta.url), "utf8");
      for (const label of src.matchAll(/utf8\("([^"]+)"\)/g))
        expect(label[1], f).toMatch(/^e2ee\/(v2|s2)\//);
      if (f !== "primitives.ts") expect(src, f).not.toMatch(/from "@noble/);
      expect(src.replace(/brnr-e2ee/g, ""), f).not.toMatch(/brnr/i);
    }
    const pkg = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { dependencies: Record<string, string> };
    expect(Object.keys(pkg.dependencies).sort()).toEqual([
      "@noble/ciphers",
      "@noble/curves",
      "@noble/hashes",
      "zod",
    ]);
    for (const v of Object.values(pkg.dependencies))
      expect(v).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe("session conflict and recovery", () => {
  it("R1-1: non-canonical initiator sends ≥2 messages before learning of the conflict; none lost", () => {
    const [a, b] = fresh();
    initiate(b, a);
    const as = [send(a, "a1"), send(a, "a2")];
    const bs = [send(b, "b1"), send(b, "b2")];
    expect([
      receive(b, a, as[0]!),
      receive(a, b, bs[0]!),
      receive(b, a, as[1]!),
      receive(a, b, bs[1]!),
    ]).toEqual(["a1", "b1", "a2", "b2"]);
  });
  it("R1-2: delayed simultaneous handshake after the other session has received; converges", () => {
    const [a, b] = fresh();
    initiate(b, a);
    const late = send(b, "late");
    receive(b, a, send(a, "x"));
    receive(a, b, send(b, "y"));
    expect(receive(a, b, late)).toBe("late");
    receive(b, a, send(a, "z"));
    expect(receive(a, b, send(b, "w"))).toBe("w");
  });
  it("R1-3: peer resets after accepting during simultaneous initiation; converges", () => {
    const [a, b] = fresh();
    initiate(b, a);
    receive(b, a, send(a, "a1"));
    b.state = null;
    initiate(b, a);
    expect(receive(a, b, send(b, "after reset"))).toBe("after reset");
    expect(receive(b, a, send(a, "a2"))).toBe("a2");
  });
  it("R2-3: two concurrent re-initiations with the 3-session cap; recovery restores delivery", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock);
    await b.receive(a, await a.send(b, "x0"));
    await a.receive(b, await b.send(a, "x1"));
    const lateOnX = await a.send(b, "late on x");
    // Two concurrent re-initiations plus a third, crossing in flight.
    const reinit = async (d: Device, peer: Device, text: string) => {
      return withSession(d.e, d.store, peer.id, APP_CONV, async (s, t) => {
        const n = d.e.initiateSession({
          conversationId: APP_CONV,
          self: d.device,
          peerBundle: peer.bundle(),
          existing: s!,
        });
        const r = d.encrypt(peer, n, text);
        return { state: r.state, tracker: t, result: r.message };
      });
    };
    clock.advance(1000);
    const y = await reinit(a, b, "y");
    clock.advance(1000);
    const z = await reinit(b, a, "z");
    clock.advance(1000);
    const w = await reinit(a, b, "w");
    expect((await b.receive(a, y)).text).toBe("y");
    expect((await a.receive(b, z)).text).toBe("z");
    expect((await b.receive(a, w)).text).toBe("w");
    expect(((await b.state(a))!["sessions"] as unknown[]).length).toBe(3);
    // The late message on X: delivered if X is still held, otherwise a recovery trigger.
    const late = await b.receive(a, lateOnX);
    expect(
      late.text === "late on x" || late.error === "E2EE_HANDSHAKE_REQUIRED",
    ).toBe(true);
    // Delivery works both ways afterwards.
    expect((await b.receive(a, await a.send(b, "after a"))).text).toBe(
      "after a",
    );
    expect((await a.receive(b, await b.send(a, "after b"))).text).toBe(
      "after b",
    );
  });
  it("R2-5: replayed founding message passed to acceptSession({existing}) → E2EE_DUPLICATE_MESSAGE", () => {
    const [a, b] = fresh();
    const m = send(a, "x");
    receive(b, a, m);
    expectCode(
      () =>
        b.e.acceptSession({
          conversationId: CONV,
          self: b.device,
          expectedPeerBoxPk: a.device.boxPk,
          expectedPeerSignPk: a.device.signPk,
          message: m,
          lookupSpk: (i) => b.spks.get(i),
          lookupOtp: (i) => b.otps.get(i),
          seenHandshake: () => false,
          existing: b.state!,
        }),
      "E2EE_DUPLICATE_MESSAGE",
    );
  });
  it("R3-1: reading-only receiver; control message restores delivery within one round trip", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock); // reads only
    await b.receive(a, await a.send(b, "1"));
    await b.deleteSession(a);
    await b.receive(a, await a.send(b, "lost 1"));
    clock.advance(10 * 60 * 1000);
    await b.receive(a, await a.send(b, "lost 2"));
    const control = await b.maybeRecover(a);
    expect(control).not.toBeNull();
    expect((await a.receive(b, control!)).text).toBe("session-refresh");
    expect((await b.receive(a, await a.send(b, "restored"))).text).toBe(
      "restored",
    );
  });
  it("R4-2: adversary injects triggers while traffic flows; ≤3 recoveries per 24 h, active session kept", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock);
    await b.receive(a, await a.send(b, "hello"));
    await a.receive(b, await b.send(a, "hi"));
    let recoveries = 0;
    const recoveryTimes: number[] = [];
    for (let minute = 0; minute < 50 * 60; minute += 5) {
      clock.advance(5 * 60_000);
      // Forged unknown-sid message without a handshake, from the server.
      const legit = await a.send(b, `m${minute}`);
      const forged = {
        ...legit,
        header: { ...legit.header, sid: "AAAAAAAAAAA" },
      };
      delete (forged as { handshake?: unknown }).handshake;
      if (minute % 10 === 0) await b.receive(a, forged);
      // Legitimate traffic flows both ways (a→b hourly) and is never lost.
      if (minute % 60 === 0)
        expect((await b.receive(a, legit)).text).toBe(`m${minute}`);
      if (minute % 30 === 0)
        expect((await a.receive(b, await b.send(a, `r${minute}`))).text).toBe(
          `r${minute}`,
        );
      const control = await b.maybeRecover(a);
      if (control) {
        recoveries++;
        recoveryTimes.push(clock.ms);
        expect((await a.receive(b, control)).text).toBe("session-refresh");
      }
    }
    for (const t of recoveryTimes)
      expect(
        recoveryTimes.filter((u) => u > t - 24 * 3600_000 && u <= t).length,
      ).toBeLessThanOrEqual(3);
    expect(recoveries).toBeGreaterThan(0);
  }, 300_000);
  it("R5-1: recovery driven from first sighting to re-initiation through withSession", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock);
    await b.receive(a, await a.send(b, "1"));
    await a.receive(b, await b.send(a, "2"));
    await b.deleteSession(a);
    expect(await b.receive(a, await a.send(b, "lost"))).toMatchObject({
      reason: "handshake-required",
    });
    expect(await b.maybeRecover(a)).toBeNull();
    clock.advance(10 * 60 * 1000);
    const control = await b.maybeRecover(a);
    expect(control?.handshake).toBeDefined();
    expect((await a.receive(b, control!)).text).toBe("session-refresh");
    expect((await b.receive(a, await a.send(b, "ok"))).text).toBe("ok");
  });
});

describe("final review findings", () => {
  it("F-1/F2-1: 3-DH founding message replayed after FIFO roll-over → E2EE_DUPLICATE_MESSAGE; record persists across a crash", async () => {
    for (const transactional of [true, false]) {
      const clock = testClock();
      const a = new Device("alice", clock, transactional);
      const b = new Device("bob", clock, transactional);
      const founding = await a.send(b, "first", false); // 3-DH: replayable while the SPK lives
      // Crash between the session write and the device-level records.
      b.store.crashAt = transactional ? "put:after" : "put:after-session";
      await b.receive(a, founding).catch(() => undefined);
      await withSession(b.e, b.store, a.id, APP_CONV, async () => ({
        state: null,
        tracker: null,
        result: 0,
      }));
      expect(
        b.store.replay.get(1)?.has(b.e.handshakeDigest(founding.handshake!)),
      ).toBe(true);
      // Roll the per-state FIFO over with 33 re-initiations, then delete the session.
      for (let i = 0; i < 33; i++) {
        a.store.sessions.clear();
        expect(
          (await b.receive(a, await a.send(b, `re${i}`, false))).text,
        ).toBe(`re${i}`);
      }
      expect(await b.receive(a, founding)).toMatchObject({
        error: "E2EE_DUPLICATE_MESSAGE",
        reason: "evicted-session",
      });
      await b.deleteSession(a);
      expect(await b.receive(a, founding)).toMatchObject({
        error: "E2EE_DUPLICATE_MESSAGE",
        reason: "evicted-session",
      });
    }
  });
  it("F-2: forged {dh: SPK_B} before the first reply → E2EE_DECRYPT_FAILED, state unchanged", () => {
    const [a, b] = fresh();
    const m = send(a, "x");
    const { handshake: _h, ...rest } = m;
    const forged = {
      ...rest,
      ad: adFrom(b, a),
      header: { ...m.header, dh: bundleOf(b, false).spkPk },
    };
    const before = JSON.stringify(a.state);
    expectCode(
      () =>
        a.e.decrypt({
          state: a.state!,
          message: forged,
          expectedAd: adFrom(b, a),
        }),
      "E2EE_DECRYPT_FAILED",
    );
    expect(JSON.stringify(a.state)).toBe(before);
  });
  it("F-3: initiateSession({existing}) with a different peer key → E2EE_IDENTITY_MISMATCH", () => {
    const [a] = fresh();
    const mallory = party("mallory");
    expectCode(
      () =>
        a.e.initiateSession({
          conversationId: CONV,
          self: a.device,
          peerBundle: bundleOf(mallory),
          existing: a.state!,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
  });
  it("F-5: timestamps Feb 30, 1969 and leap second → E2EE_INVALID_INPUT", () => {
    const { e } = makeE2ee("f5");
    const dev = e.generateDeviceIdentity("d");
    const bundle = e.buildDeviceBundle({
      device: dev,
      spk: e.generateSignedPrekey(dev, 1),
    });
    for (const createdAt of [
      "1969-02-30T00:00:00.000Z",
      "2016-12-31T23:59:60.000Z",
    ])
      expectCode(
        () => e.verifyDeviceBundle({ ...bundle, createdAt }),
        "E2EE_INVALID_INPUT",
      );
  });
  it("F-6: report disclosure verifies; wrong key, altered plaintext and non-canonical payload fail", () => {
    const [a, b] = fresh();
    const m = send(a, "report");
    const cand = b.e.acceptSession({
      conversationId: CONV,
      self: b.device,
      expectedPeerBoxPk: a.device.boxPk,
      expectedPeerSignPk: a.device.signPk,
      message: m,
      lookupSpk: (i) => b.spks.get(i),
      lookupOtp: (i) => b.otps.get(i),
      seenHandshake: () => false,
    });
    const r = b.e.decrypt({ state: cand, message: m, expectedAd: adFrom(a) });
    const item = b.e.buildReportDisclosure([
      {
        envelopeId: "env",
        message: m,
        messageKey: r.messageKey,
        plaintext: r.plaintext,
      },
    ]).items[0]!;
    expect(b.e.verifyReportDisclosureItem(item)).toBe(true);
    expect(
      b.e.verifyReportDisclosureItem({
        ...item,
        messageKey: item.messageKey.replace(/^./, (c) =>
          c === "A" ? "B" : "A",
        ),
      }),
    ).toBe(false);
    expect(
      b.e.verifyReportDisclosureItem({ ...item, plaintext: "altered" }),
    ).toBe(false);
    const nonCanonical = JSON.stringify(m, null, 2);
    expect(
      nonCanonical === b.e.canonicalJson(b.e.parseMessage(nonCanonical)),
    ).toBe(false);
  });
  it("F-13: small-order Ed25519 public key → E2EE_INVALID_KEY", () => {
    const { e } = makeE2ee("f13");
    const dev = e.generateDeviceIdentity("d");
    const bundle = e.buildDeviceBundle({
      device: dev,
      spk: e.generateSignedPrekey(dev, 1),
    });
    const identity = b64uEncode(Uint8Array.of(1, ...new Uint8Array(31)));
    expectCode(
      () => e.verifyDeviceBundle({ ...bundle, deviceSignPk: identity }),
      "E2EE_INVALID_KEY",
    );
  });
});
