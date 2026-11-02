// Edge cases found by mutation testing: each test pins a behaviour a surviving mutant changed.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createE2ee,
  LIMITS,
  SUITES,
  withSession,
  type MessageV2,
} from "../src/index.js";
import {
  b64uDecode,
  b64uEncode,
  isStableId,
  parseTimestamp,
  utf8DecodeStrict,
  utf8Encode,
} from "../src/codec.js";
import { canonicalJson } from "../src/jcs.js";
import { HmacDrbg, tapeRng } from "../src/testing.js";
import { sidOf as sidOfReal } from "../src/x3dh.js";
import { CONV as APP_CONV, Device } from "./app.js";
import { expectCode, hex, makeE2ee, T0, testClock } from "./helpers.js";
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

const DAY = 24 * 3600_000;
type J = Record<string, unknown> & {
  sessions: Array<Record<string, unknown>>;
  skipped: Array<{
    sid: string;
    dh: string;
    keys: Array<[number, string, string]>;
  }>;
  activeSid: string;
};
const json = (p: Party): J => JSON.parse(p.e.serializeState(p.state!)) as J;
const two = (): [Party, Party, ReturnType<typeof testClock>] => {
  const clock = testClock();
  return [party("alice", clock), party("bob", clock), clock];
};
const accept = (
  to: Party,
  from: Party,
  m: MessageV2,
  over: Record<string, unknown> = {},
) =>
  to.e.acceptSession({
    conversationId: CONV,
    self: to.device,
    expectedPeerBoxPk: from.device.boxPk,
    expectedPeerSignPk: from.device.signPk,
    message: m,
    lookupSpk: (id: number) => to.spks.get(id),
    lookupOtp: (id: number) => to.otps.get(id),
    seenHandshake: () => false,
    ...(to.state ? { existing: to.state } : {}),
    ...over,
  } as never);

describe("codec edges", () => {
  it("UTF-8 encoding matches Node at every length boundary", () => {
    for (const cp of [
      0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff,
    ]) {
      const s = String.fromCodePoint(cp);
      expect(
        Buffer.from(utf8Encode(s)!).equals(Buffer.from(s, "utf8")),
        cp.toString(16),
      ).toBe(true);
      expect(utf8DecodeStrict(utf8Encode(s)!)).toBe(s);
    }
    expect(utf8Encode(String.fromCharCode(0xdbff, 0xdfff))).toEqual(
      Uint8Array.from(Buffer.from("\u{10ffff}")),
    );
    for (const bad of [
      [0xdc00, 0xdc00],
      [0xd800, 0xd800],
      [0xd800],
      [0x61, 0xdc00],
      [0xdbff, 0x61],
      [0xdfff],
    ])
      expect(
        utf8Encode(String.fromCharCode(...bad)),
        bad.map((x) => x.toString(16)).join(","),
      ).toBeNull();
  });

  it("strict UTF-8 decoding: valid boundaries and every invalid class", () => {
    for (const h of [
      "7f",
      "c280",
      "dfbf",
      "e0a080",
      "efbfbf",
      "f0908080",
      "f48fbfbf",
    ])
      expect(utf8DecodeStrict(hex(h)), h).toBe(
        Buffer.from(h, "hex").toString("utf8"),
      );
    for (const h of [
      "80",
      "bf",
      "c080",
      "c1bf",
      "c341",
      "c3",
      "e08080",
      "e0a0",
      "e0a041",
      "eda080",
      "edbfbf",
      "f08f8080",
      "f4908080",
      "f5808080",
      "f8888080",
      "fc80808080",
      "ff",
      "f090804180",
    ])
      expect(utf8DecodeStrict(hex(h)), h).toBeNull();
  });

  it("base64url rejects bad characters and impossible lengths; stable ids and stamps need real strings", () => {
    for (const s of ["Zm9v!A", "Zm9vY", "Zm9vYm*y"])
      expect(b64uDecode(s), s).toBeNull();
    expect(isStableId(["x"])).toBe(false);
    const fake = { toString: () => "2026-10-22T12:00:00.000Z" };
    expect(parseTimestamp(fake)).toBeNull();
    expect(parseTimestamp(1)).toBeNull();
    expect(parseTimestamp("+010000-01-01T00:00:00.000Z")).toBeNull();
    expect(parseTimestamp("9999-12-31T23:59:59.999Z")).not.toBeNull();
  });
});

describe("jcs and schema edges", () => {
  it("object nesting is capped at 32 too", () => {
    let ok: unknown = "x";
    for (let i = 0; i < 32; i++) ok = { a: ok };
    expect(canonicalJson(ok)).toContain("x");
    expectCode(() => canonicalJson({ a: ok }), "E2EE_INVALID_INPUT");
  });

  it("an absent suite fails rule 4, not rule 3; state errors carry no details", () => {
    const [a] = two();
    initiate(a, party("bob"));
    const m = send(a, "x");
    const { suite: _s, ...noSuite } = m;
    expect(
      expectCode(() => a.e.parseMessage(noSuite), "E2EE_INVALID_INPUT").details,
    ).toEqual({ path: "suite" });
    const err = expectCode(
      () => a.e.parseState(JSON.stringify({ ...json(a), x: 1 })),
      "E2EE_INVALID_STATE",
    );
    expect(err.details).toBeUndefined();
    expectCode(
      () => a.e.parseState(Buffer.from(a.e.serializeState(a.state!)) as never),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () =>
        a.e.parseTracker(
          Buffer.from(
            '{"v":1,"sightings":[],"attempts":0,"window":[]}',
          ) as never,
        ),
      "E2EE_INVALID_STATE",
    );
    expectCode(
      () => a.e.handshakeDigest({ ...m.handshake!, extra: 1 } as never),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => a.e.handshakeDigest({ ...m.handshake!, v: 1 } as never),
      "E2EE_UNSUPPORTED_VERSION",
    );
  });
});

describe("context and keys edges", () => {
  afterEach(() => vi.unstubAllGlobals());
  it("crypto without getRandomValues → E2EE_RNG_UNAVAILABLE; account keys are point-checked", () => {
    vi.stubGlobal("crypto", {});
    expectCode(() => createE2ee(), "E2EE_RNG_UNAVAILABLE");
    vi.unstubAllGlobals();
    const { e } = makeE2ee("acct");
    const account = {
      ...e.generateAccountIdentity(),
      signPk: b64uEncode(Uint8Array.of(1, ...new Uint8Array(31))),
    };
    const d = e.generateDeviceIdentity("d");
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account,
          accountId: "a",
          epoch: 1,
          devices: [
            {
              deviceId: "d",
              deviceSignPk: d.signPk,
              deviceBoxPk: d.boxPk,
              addedAt: "2026-01-01T00:00:00.000Z",
            },
          ],
        }),
      "E2EE_INVALID_KEY",
    );
  });

  it("DRBG: non-multiple-of-32 output and tape exhaustion", () => {
    const seed = new Uint8Array(32).fill(3);
    const a = new HmacDrbg(seed, new Uint8Array(0), new Uint8Array(0)).generate(
      100,
    );
    const b = new HmacDrbg(seed, new Uint8Array(0), new Uint8Array(0)).generate(
      128,
    );
    expect(a).toEqual(b.slice(0, 100));
    const r = tapeRng([{ purpose: "seed", bytes: new Uint8Array(32) }]);
    expect(() => r(31, "seed")).toThrow(/tape mismatch/);
    const r2 = tapeRng([]);
    expect(() => r2(32, "seed")).toThrow(/tape mismatch/);
  });
});

describe("device list edges", () => {
  const setup = () => {
    const { e } = makeE2ee("dle");
    const account = e.generateAccountIdentity();
    const d = e.generateDeviceIdentity("d1");
    const entry = {
      deviceId: "d1",
      deviceSignPk: d.signPk,
      deviceBoxPk: d.boxPk,
      addedAt: "2026-01-01T00:00:00.000Z",
    };
    const list = e.buildSignedDeviceList({
      account,
      accountId: "a",
      epoch: 2,
      devices: [entry],
    });
    return { e, d, entry, list };
  };
  it("parseDeviceList enforces the entry cap and unique ids itself", () => {
    const { e, entry, list } = setup();
    expectCode(
      () => e.parseDeviceList({ ...list, devices: [] }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expectCode(
      () => e.parseDeviceList({ ...list, devices: [entry, entry] }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    expectCode(
      () =>
        e.parseDeviceList({
          ...list,
          devices: Array.from({ length: 65 }, (_, i) => ({
            ...entry,
            deviceId: `d${i}`,
          })),
        }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    e.verifySignedDeviceList(list, { minEpoch: 2 });
  });
  it("bundleMatchesDeviceList compares id, signing key and box key separately", () => {
    const { e, d, list } = setup();
    const other = e.generateDeviceIdentity("d1");
    const b = e.buildDeviceBundle({
      device: d,
      spk: e.generateSignedPrekey(d, 1),
    });
    expect(e.bundleMatchesDeviceList(b, list)).toBe(true);
    const renamed = { ...d, deviceId: "d2" };
    expect(
      e.bundleMatchesDeviceList(
        e.buildDeviceBundle({
          device: renamed,
          spk: e.generateSignedPrekey(renamed, 1),
        }),
        list,
      ),
    ).toBe(false);
    const otherSign = { ...d, signPk: other.signPk, signSk: other.signSk };
    expect(
      e.bundleMatchesDeviceList(
        e.buildDeviceBundle({
          device: otherSign,
          spk: e.generateSignedPrekey(otherSign, 1),
        }),
        list,
      ),
    ).toBe(false);
  });
});

describe("fingerprint and link edges", () => {
  it("QR verification rejects non-byte and wrong-length payloads on either side", () => {
    const { e } = makeE2ee("qr");
    const l = {
      accountSignPk: e.generateAccountIdentity().signPk,
      stableId: "l",
    };
    const r = {
      accountSignPk: e.generateAccountIdentity().signPk,
      stableId: "r",
    };
    const sl = e.computeSafetyNumber({ local: l, remote: r });
    const sr = e.computeSafetyNumber({ local: r, remote: l });
    expect(e.verifySafetyNumberPayload(sl, sr.qrPayload)).toBe(true);
    expect(
      e.verifySafetyNumberPayload(
        { ...sl, qrPayload: Array.from(sl.qrPayload) as never },
        sr.qrPayload,
      ),
    ).toBe(false);
    expect(
      e.verifySafetyNumberPayload(sl, Array.from(sr.qrPayload) as never),
    ).toBe(false);
    expect(
      e.verifySafetyNumberPayload(sl, Uint8Array.from([...sr.qrPayload, 0])),
    ).toBe(false);
    expect(
      e.verifySafetyNumberPayload(
        { ...sl, qrPayload: Uint8Array.from([...sl.qrPayload, 0]) },
        sr.qrPayload,
      ),
    ).toBe(false);
  });

  it("sealed account key: 39 bytes is malformed, 40 bytes reaches the AEAD; a trapped ephSelf is INVALID_STATE", () => {
    const { e } = makeE2ee("lk");
    const eph = e.generateLinkEphemeral();
    const peer = e.generateLinkEphemeral();
    const t = b64uEncode(new Uint8Array(32).fill(1));
    expectCode(
      () =>
        e.openAccountKey({
          sealed: b64uEncode(new Uint8Array(39)),
          transcript: t,
          ephSelf: eph,
          ephPeerPk: peer.pk,
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.openAccountKey({
          sealed: b64uEncode(new Uint8Array(40)),
          transcript: t,
          ephSelf: eph,
          ephPeerPk: peer.pk,
        }),
      "E2EE_DECRYPT_FAILED",
    );
    const trapped = new Proxy(eph, {
      ownKeys: () => {
        throw new Error("trap");
      },
    });
    expectCode(
      () =>
        e.sealAccountKey({
          account: e.generateAccountIdentity(),
          transcript: t,
          ephSelf: trapped,
          ephPeerPk: peer.pk,
        }),
      "E2EE_INVALID_STATE",
    );
  });
});

describe("recovery edges", () => {
  it("onDecrypt(null) is INVALID_STATE; a not-due refresh changes nothing; zero attempts means no backoff", () => {
    const clock = testClock();
    const { e } = makeE2ee("rec2", clock);
    expectCode(
      () =>
        e.onDecrypt(null as never, {
          advancedReceiveChain: true,
          sessionCreatedAt: new Date(T0).toISOString(),
        }),
      "E2EE_INVALID_STATE",
    );
    const r1 = e.refreshDecision(null);
    clock.advance(1000);
    expect(e.refreshDecision(r1.tracker)).toEqual({
      due: false,
      tracker: { ...r1.tracker, seenAt: new Date(clock.ms).toISOString() },
    });
    const t = {
      v: 1 as const,
      sightings: [new Date(clock.ms - 10 * 60_000).toISOString()],
      attempts: 0,
      lastAt: new Date(clock.ms - 60_000).toISOString(),
      window: [],
    };
    expect(e.recoveryDecision(t).due).toBe(true);
  });
});

describe("state edges", () => {
  it("eviction uses re-stamped lastUsedAt (discriminating case)", () => {
    const [a, b, clock] = two();
    for (let i = 0; i < 3; i++) {
      initiate(a, b);
      clock.advance(1000);
    }
    const j = json(a);
    const nonActive = j.sessions.filter((s) => s["sid"] !== j.activeSid);
    nonActive[0]!["lastUsedAt"] = new Date(clock.ms + 10 * DAY).toISOString(); // re-stamped to now
    nonActive[1]!["lastUsedAt"] = new Date(
      clock.ms + 23 * 3600_000,
    ).toISOString(); // kept, newer than now
    a.state = a.e.parseState(JSON.stringify(j));
    initiate(a, b);
    const sids = json(a).sessions.map((s) => s["sid"]);
    expect(sids).not.toContain(nonActive[0]!["sid"]);
    expect(sids).toContain(nonActive[1]!["sid"]);
  });

  it("evicting a session removes its skipped keys", () => {
    const [a, b, clock] = two();
    initiate(a, b);
    send(a, "dropped");
    receive(b, a, send(a, "x")); // one skipped key on session 1
    for (let i = 0; i < 3; i++) {
      clock.advance(1000);
      initiate(a, b);
      receive(b, a, send(a, `r${i}`));
    }
    const j = json(b);
    expect(j.sessions).toHaveLength(3);
    for (const g of j.skipped)
      expect(j.sessions.map((s) => s["sid"])).toContain(g.sid);
  });

  it("over the cap, the oldest keys go first and equal stamps drop the lowest n", () => {
    const [a, b, clock] = two();
    initiate(a, b);
    for (let i = 0; i < 1000; i++) send(a, "d");
    receive(b, a, send(a, "x"));
    clock.advance(1000);
    receive(a, b, send(b, "r"));
    for (let i = 0; i < 1000; i++) send(a, "d");
    receive(b, a, send(a, "y"));
    clock.advance(1000);
    receive(a, b, send(b, "r2"));
    for (let i = 0; i < 10; i++) send(a, "d");
    receive(b, a, send(a, "z"));
    const first = json(b).skipped.find((g) =>
      g.keys.some((k) => k[2] === new Date(T0).toISOString()),
    )!;
    expect(first.keys[0]![0]).toBe(10);
  });

  it("an idle session exactly at the TTL is kept, one ms later dropped; inspect leaves past stamps alone", () => {
    const [a, b, clock] = two();
    initiate(a, b);
    clock.advance(1000);
    initiate(a, b);
    clock.advance(LIMITS.SKIPPED_KEY_TTL_MS - 1000);
    send(a, "x");
    expect(json(a).sessions).toHaveLength(2);
    clock.advance(1);
    send(a, "y");
    expect(json(a).sessions).toHaveLength(1);
    const info = a.e.inspectSession(a.state!);
    expect(info.sessions[0]!.createdAt).toBe(new Date(T0 + 1000).toISOString());
    expect("otpId" in info.sessions[0]!.pending!).toBe(true);
    initiate(a, b, false);
    expect("otpId" in a.e.inspectSession(a.state!).sessions[1]!.pending!).toBe(
      false,
    );
  });

  it("decrypt: two candidates, or a responder missing only ckr, are INVALID_STATE", () => {
    const [a, b] = two();
    initiate(a, b);
    receive(b, a, send(a, "x"));
    receive(a, b, send(b, "y"));
    a.state = null;
    initiate(a, b);
    const m1 = send(a, "c1");
    const c1 = accept(b, a, m1);
    a.state = null;
    initiate(a, b);
    const c2 = accept(b, a, send(a, "c2"));
    const j = JSON.parse(JSON.stringify(c1)) as J;
    j.sessions.push((JSON.parse(JSON.stringify(c2)) as J).sessions.at(-1)!);
    expectCode(
      () =>
        b.e.decrypt({ state: j as never, message: m1, expectedAd: adFrom(a) }),
      "E2EE_INVALID_STATE",
    );
    const k = json(b);
    delete k.sessions[0]!["ckr"];
    expectCode(
      () =>
        b.e.decrypt({ state: k as never, message: m1, expectedAd: adFrom(a) }),
      "E2EE_INVALID_STATE",
    );
  });
});

describe("session edges", () => {
  it("initiateSession: an explicit supported suite works; each existing mismatch is caught on its own", () => {
    const [a, b] = two();
    const st = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle: bundleOf(b),
      suite: SUITES[0]!,
    });
    expect(st).toBeDefined();
    initiate(a, b);
    const otherKeys = a.e.generateDeviceIdentity("bob-dev"); // same id, different keys
    const spoof = {
      ...b.device,
      boxPk: otherKeys.boxPk,
      boxSk: otherKeys.boxSk,
    };
    const spoofBundle = b.e.buildDeviceBundle({
      device: spoof,
      spk: b.e.generateSignedPrekey(spoof, 9),
    });
    expectCode(
      () =>
        a.e.initiateSession({
          conversationId: CONV,
          self: a.device,
          peerBundle: spoofBundle,
          existing: a.state!,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
    const selfOther = {
      ...a.device,
      boxPk: otherKeys.boxPk,
      boxSk: otherKeys.boxSk,
    };
    expectCode(
      () =>
        a.e.initiateSession({
          conversationId: CONV,
          self: selfOther,
          peerBundle: bundleOf(b),
          existing: a.state!,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
    const renamed = { ...b.device, deviceId: "bob-dev-2" };
    const renamedBundle = b.e.buildDeviceBundle({
      device: renamed,
      spk: b.e.generateSignedPrekey(renamed, 9),
    });
    expectCode(
      () =>
        a.e.initiateSession({
          conversationId: CONV,
          self: a.device,
          peerBundle: renamedBundle,
          existing: a.state!,
        }),
      "E2EE_IDENTITY_MISMATCH",
    );
  });

  it("acceptSession: callbacks checked one by one; each existing mismatch alone; held sid vs FIFO", () => {
    const [a, b] = two();
    initiate(a, b);
    const m = send(a, "x");
    expectCode(() => accept(b, a, m, { lookupOtp: 1 }), "E2EE_INVALID_INPUT");
    expectCode(
      () => accept(b, a, m, { seenHandshake: 1 }),
      "E2EE_INVALID_INPUT",
    );
    receive(b, a, m);
    // Existing from a different key under the same device id.
    const mallory = party("mallory");
    const mDev = mallory.e.generateDeviceIdentity("alice-dev");
    const mParty: Party = { ...mallory, device: mDev };
    initiate(mParty, b);
    const mm = send(mParty, "m");
    expectCode(() => accept(b, mParty, mm), "E2EE_IDENTITY_MISMATCH");
    initiate(a, b);
    const m2 = send(a, "y");
    const otherSelf = b.e.generateDeviceIdentity("bob-dev");
    expectCode(
      () => accept(b, a, m2, { self: otherSelf }),
      "E2EE_IDENTITY_MISMATCH",
    );
    expectCode(
      () => accept(b, a, m2, { self: { ...b.device, deviceId: "bob-dev-2" } }),
      "E2EE_IDENTITY_MISMATCH",
    );
    // Held sid with its digest gone from the FIFO → DUPLICATE without a reason.
    const j = json(b);
    j["acceptedHandshakes"] = [];
    const noFifo = b.e.parseState(JSON.stringify(j));
    expect(
      expectCode(
        () => accept(b, a, m, { existing: noFifo }),
        "E2EE_DUPLICATE_MESSAGE",
      ).details,
    ).toBeUndefined();
  });

  it("encrypt checks plaintext size before AD; decrypt checks AD against the state's conversation", () => {
    const [a, b] = two();
    initiate(a, b);
    expectCode(
      () =>
        a.e.encrypt({
          state: a.state!,
          plaintext: new Uint8Array(8193),
          ad: adFrom(b),
        }),
      "E2EE_PLAINTEXT_TOO_LARGE",
    );
    const m = send(a, "x");
    const ad = { ...m.ad, conversationId: "conv-x" };
    const cand = accept(b, a, m);
    expectCode(
      () => b.e.decrypt({ state: cand, message: { ...m, ad }, expectedAd: ad }),
      "E2EE_AD_MISMATCH",
    );
  });

  it("decrypt: reflection is caught before routing; the right skipped group is used; skipped groups don't block new ratchets", () => {
    const [a, b] = two();
    initiate(a, b);
    const m = send(a, "x");
    receive(b, a, m);
    const h = { ...m.handshake!, initiatorBoxPk: b.device.boxPk };
    expectCode(
      () =>
        b.e.decrypt({
          state: b.state!,
          message: {
            ...m,
            handshake: h,
            header: { ...m.header, sid: sidOfReal(h) },
          },
          expectedAd: adFrom(a),
        }),
      "E2EE_INVALID_INPUT",
    );
    // Two skipped groups: chain 1 and chain 2, delivered late in reverse order.
    receive(a, b, send(b, "r"));
    const c1 = send(a, "c1");
    receive(b, a, send(a, "c1b"));
    receive(a, b, send(b, "r2"));
    const c2 = send(a, "c2");
    receive(b, a, send(a, "c2b")); // b has skipped keys on two chains now? (c1 and c2 were sent before the delivered ones)
    expect(json(b).skipped).toHaveLength(2);
    expect(receive(b, a, c2)).toBe("c2");
    expect(receive(b, a, c1)).toBe("c1");
    // A pending skipped group does not block the peer's next ratchet key.
    send(a, "lost");
    receive(b, a, send(a, "after lost"));
    receive(a, b, send(b, "turn"));
    expect(receive(b, a, send(a, "new chain"))).toBe("new chain");
  });
});

describe("withSession edges", () => {
  it("flushes a lone pending OTP delete; rejects non-object results and foreign conversations; unchanged tracker is not written", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock);
    const m = await a.send(b, "x");
    await b.receive(a, m);
    expect(b.store.writes.at(-1)!.opts.deleteOtpIds).toEqual([1]);
    // A stored state with only a pending OTP delete.
    const cur = b.store.sessions.get(`${a.id}|${APP_CONV}`)!;
    const st = JSON.parse(cur.serialized!) as Record<string, unknown>;
    st["pendingOtpDeletes"] = [7];
    st["pendingReplayRecords"] = [];
    b.store.sessions.set(`${a.id}|${APP_CONV}`, {
      ...cur,
      serialized: JSON.stringify(st),
    });
    b.store.otps.set(7, b.e.generateOneTimePrekeys(7, 1)[0]!);
    b.store.ignoreDeleteOtpIds = true;
    await withSession(b.e, b.store, a.id, APP_CONV, async () => ({
      state: null,
      tracker: null,
      result: 0,
    }));
    expect(b.store.otps.has(7)).toBe(false);
    await expect(
      withSession(b.e, b.store, a.id, APP_CONV, (async () => 5) as never),
    ).rejects.toMatchObject({ code: "E2EE_INVALID_INPUT" });
    const state = b.e.parseState(
      b.store.sessions.get(`${a.id}|${APP_CONV}`)!.serialized!,
    );
    await expect(
      withSession(b.e, b.store, a.id, "other-conv", async () => ({
        state,
        tracker: null,
        result: 0,
      })),
    ).rejects.toMatchObject({ code: "E2EE_INVALID_INPUT" });
    await withSession(b.e, b.store, a.id, APP_CONV, async (_s, t) => ({
      state: null,
      tracker: b.e.recordRecoverySignal(t, "evicted-session"),
      result: 0,
    }));
    const n = b.store.writes.length;
    await withSession(b.e, b.store, a.id, APP_CONV, async (_s, t) => ({
      state: null,
      tracker: t,
      result: 0,
    }));
    expect(b.store.writes.length).toBe(n);
  });
});

describe("edges from mutation round 3", () => {
  it("UTF-8: a high surrogate followed by U+E000 is lone; 0xf8 lead bytes are invalid", () => {
    expect(utf8Encode(String.fromCharCode(0xd800, 0xe000))).toBeNull();
    expect(utf8DecodeStrict(hex("f8a08080"))).toBeNull();
    expect(utf8DecodeStrict(hex("f0a08080"))).toBe(
      String.fromCodePoint(0x20000),
    );
  });

  it("Ed25519: a non-canonical encoding (y = p + 3) of a large-order point is rejected", async () => {
    const { ed25519PublicKeyValid } = await import("../src/primitives.js");
    expect(
      ed25519PublicKeyValid(
        hex("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
      ),
    ).toBe(false);
    expect(
      ed25519PublicKeyValid(
        hex("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      ),
    ).toBe(false);
  });

  it("sealAccountKey point-checks the account key", () => {
    const { e } = makeE2ee("seal");
    const account = {
      ...e.generateAccountIdentity(),
      signPk: b64uEncode(Uint8Array.of(1, ...new Uint8Array(31))),
    };
    const eph = e.generateLinkEphemeral();
    expectCode(
      () =>
        e.sealAccountKey({
          account,
          transcript: b64uEncode(new Uint8Array(32)),
          ephSelf: eph,
          ephPeerPk: e.generateLinkEphemeral().pk,
        }),
      "E2EE_INVALID_KEY",
    );
  });

  it("parseState rejects a repeated n in a skipped group; decrypt rejects a session missing only ckr", () => {
    const [a, b] = two();
    initiate(a, b);
    send(a, "lost");
    receive(b, a, send(a, "x"));
    const j = json(b);
    j.skipped[0]!.keys.push([...j.skipped[0]!.keys[0]!]);
    expectCode(() => b.e.parseState(JSON.stringify(j)), "E2EE_INVALID_STATE");
    receive(a, b, send(b, "y"));
    const m = send(a, "z");
    const k = json(b);
    const target = k.sessions.find((s) => s["sid"] === m.header.sid)!;
    delete target["ckr"];
    expectCode(
      () =>
        b.e.decrypt({ state: k as never, message: m, expectedAd: adFrom(a) }),
      "E2EE_INVALID_STATE",
    );
  });

  it("acceptSession({existing}): FIFO-only replay is evicted-session; a held sid among several sessions is a plain duplicate", () => {
    const [a, b, clock] = two();
    initiate(a, b);
    const first = send(a, "first");
    receive(b, a, first);
    for (let i = 0; i < 3; i++) {
      clock.advance(1000);
      initiate(a, b);
      receive(b, a, send(a, `r${i}`));
    }
    expect(json(b).sessions.map((s) => s["sid"])).not.toContain(
      first.header.sid,
    );
    expect(
      expectCode(() => accept(b, a, first), "E2EE_DUPLICATE_MESSAGE").details,
    ).toEqual({ reason: "evicted-session" });
    // Several sessions, the founding one held, its digest dropped from the FIFO.
    const [c, d, clock2] = two();
    initiate(c, d);
    const f2 = send(c, "f2");
    receive(d, c, f2);
    clock2.advance(1000);
    initiate(c, d);
    receive(d, c, send(c, "second session"));
    const j = json(d);
    j["acceptedHandshakes"] = [];
    expect(
      expectCode(
        () => accept(d, c, f2, { existing: d.e.parseState(JSON.stringify(j)) }),
        "E2EE_DUPLICATE_MESSAGE",
      ).details,
    ).toBeUndefined();
  });

  it("decrypt: AD whose sender differs from the state's peer is AD_MISMATCH even when expectedAd agrees", () => {
    const [a, b] = two();
    initiate(a, b);
    receive(b, a, send(a, "x"));
    const m = send(a, "y");
    const ad = { ...m.ad, senderDeviceId: "someone-else" };
    expectCode(
      () =>
        b.e.decrypt({ state: b.state!, message: { ...m, ad }, expectedAd: ad }),
      "E2EE_AD_MISMATCH",
    );
  });

  it("withSession rejects a null result", async () => {
    const [a, b] = [
      new Device("alice", testClock()),
      new Device("bob", testClock()),
    ];
    await expect(
      withSession(b.e, b.store, a.id, APP_CONV, (async () => null) as never),
    ).rejects.toMatchObject({ code: "E2EE_INVALID_INPUT" });
  });
});

describe("review round 3 regressions", () => {
  it("M1: onDecrypt with a non-string sessionCreatedAt is E2EE_INVALID_INPUT and never runs caller toString", () => {
    const { e } = makeE2ee("r3");
    const t = e.recordRecoverySignal(null, "evicted-session");
    let called = false;
    const sneaky = {
      toString: () => ((called = true), "2026-10-22T12:00:00.000Z"),
    };
    for (const sessionCreatedAt of [Symbol("x"), 5, sneaky, null])
      expectCode(
        () =>
          e.onDecrypt(t, {
            advancedReceiveChain: true,
            sessionCreatedAt,
          } as never),
        "E2EE_INVALID_INPUT",
      );
    expect(called).toBe(false);
    expect(parseTimestamp(Symbol("x"))).toBeNull();
  });

  it("L1: Proxy arrays that throw while read give typed errors", () => {
    const { e } = makeE2ee("r3b");
    const dev = e.generateDeviceIdentity("d");
    const bad = new Proxy([SUITES[0]], {
      get: (o, k) =>
        k === "length"
          ? (() => {
              throw new Error("trap");
            })()
          : Reflect.get(o, k),
    });
    expectCode(
      () => e.generateSignedPrekey(dev, 1, bad as never),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.linkTranscript({
          requestId: "r",
          accountId: "a",
          newDeviceId: "n",
          newDeviceSignPk: dev.signPk,
          newDeviceBoxPk: dev.boxPk,
          suites: bad as never,
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account: e.generateAccountIdentity(),
          accountId: "a",
          epoch: 1,
          devices: bad as never,
        }),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => e.buildReportDisclosure(bad as never),
      "E2EE_INVALID_INPUT",
    );
  });

  it("L2-L4, N6: createE2ee(null), throwing option getters, fake Dates, a late crypto swap and a trapped RNG result", () => {
    expect(() => createE2ee(null as never)).not.toThrow();
    const trapped = Object.defineProperty({}, "rng", {
      get: () => {
        throw new Error("trap");
      },
      enumerable: true,
    });
    expectCode(() => createE2ee(trapped as never), "E2EE_INVALID_INPUT");
    const clock = (now: () => Date) =>
      makeE2ee("r3c", { now, set() {}, advance() {}, ms: 0 } as never).e;
    const dev = createE2ee().generateDeviceIdentity("d");
    expectCode(
      () =>
        clock(() => Object.create(Date.prototype) as Date).generateSignedPrekey(
          dev,
          1,
        ),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () => clock(() => new Proxy(new Date(), {})).generateSignedPrekey(dev, 1),
      "E2EE_INVALID_INPUT",
    );
    // The library's own draws stay on the crypto captured at createE2ee. (noble also calls
    // crypto.getRandomValues internally for blinding, so the swap only checks our seed.)
    const e = createE2ee();
    const real = globalThis.crypto;
    vi.stubGlobal("crypto", {
      getRandomValues: (a: Uint8Array) => real.getRandomValues(a).fill(7),
    });
    let sk: string;
    try {
      sk = e.generateAccountIdentity().signSk;
    } finally {
      vi.unstubAllGlobals();
    }
    expect(sk).not.toBe(b64uEncode(new Uint8Array(32).fill(7)));
    let i = 0;
    const proxied = createE2ee({
      rng: (n) =>
        i++ < 2
          ? new Uint8Array(n).fill(i)
          : new Proxy(new Uint8Array(n), {
              get: (o, k) =>
                k === Symbol.iterator
                  ? (() => {
                      throw new Error("trap");
                    })()
                  : Reflect.get(o, k),
            }),
    });
    expectCode(() => proxied.generateAccountIdentity(), "E2EE_RNG_UNAVAILABLE");
  });

  it("L6: withSession accepts only plain objects from fn", async () => {
    const [a, b] = [
      new Device("alice", testClock()),
      new Device("bob", testClock()),
    ];
    for (const out of [
      new Map(),
      new Date(),
      new (class X {
        y = 1;
      })(),
    ])
      await expect(
        withSession(b.e, b.store, a.id, APP_CONV, (async () => out) as never),
      ).rejects.toMatchObject({ code: "E2EE_INVALID_INPUT" });
    expect(
      await withSession(b.e, b.store, a.id, APP_CONV, async () =>
        Object.assign(Object.create(null), {
          state: null,
          tracker: null,
          result: 7,
        }),
      ),
    ).toBe(7);
  });
});

describe("review round 4 regressions", () => {
  it("L-A: proxied or lying byte arrays give typed errors or are copied safely", () => {
    const [a, b] = two();
    initiate(a, b);
    expectCode(
      () =>
        a.e.encrypt({
          state: a.state!,
          plaintext: new Proxy(new Uint8Array(3), {}),
          ad: adFrom(a),
        }),
      "E2EE_INVALID_INPUT",
    );
    const trap = new Proxy(new Uint8Array(3), {
      getPrototypeOf: () => {
        throw new Error("trap");
      },
    });
    expectCode(
      () => a.e.encrypt({ state: a.state!, plaintext: trap, ad: adFrom(a) }),
      "E2EE_INVALID_INPUT",
    );
    class Liar extends Uint8Array {
      override get length() {
        return 1;
      }
    }
    expectCode(
      () =>
        a.e.encrypt({
          state: a.state!,
          plaintext: new Liar(8193),
          ad: adFrom(a),
        }),
      "E2EE_PLAINTEXT_TOO_LARGE",
    );
    const m = send(a, "r");
    const r = b.e.decrypt({
      state: accept(b, a, m),
      message: m,
      expectedAd: adFrom(a),
    });
    expectCode(
      () =>
        b.e.buildReportDisclosure([
          {
            envelopeId: "e",
            message: m,
            messageKey: new Proxy(r.messageKey, {}),
            plaintext: r.plaintext,
          },
        ]),
      "E2EE_INVALID_INPUT",
    );
    expectCode(
      () =>
        b.e.buildReportDisclosure([
          {
            envelopeId: "e",
            message: m,
            messageKey: r.messageKey,
            plaintext: new Proxy(r.plaintext, {}),
          },
        ]),
      "E2EE_INVALID_INPUT",
    );
  });

  it("L-B: withSession persists and deletes from the validated copy, not the caller's object", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock);
    const m = await a.send(b, "x");
    await b.receive(a, m);
    await withSession(b.e, b.store, a.id, APP_CONV, async () => ({
      state: null,
      tracker: null,
      result: 0,
    }));
    const st = b.e.parseState(
      b.store.sessions.get(`${a.id}|${APP_CONV}`)!.serialized!,
    );
    let reads = 0;
    const shifty = new Proxy(st as object, {
      get: (o, k) =>
        k === "conversationId" && ++reads > 1 ? "elsewhere" : Reflect.get(o, k),
    });
    await withSession(b.e, b.store, a.id, APP_CONV, async () => ({
      state: shifty as never,
      tracker: null,
      result: 0,
    }));
    expect(
      JSON.parse(b.store.sessions.get(`${a.id}|${APP_CONV}`)!.serialized!)
        .conversationId,
    ).toBe(APP_CONV);
  });
});

describe("pre-release decisions (SPEC §20 item 16)", () => {
  it("null rng/now mean absent; non-object options are rejected", () => {
    expect(() =>
      createE2ee({ rng: null, now: null } as never).generateAccountIdentity(),
    ).not.toThrow();
    for (const opts of [5, "x", true])
      expectCode(() => createE2ee(opts as never), "E2EE_INVALID_INPUT");
  });

  it("a throw while reading fn's result propagates unchanged (caller code)", async () => {
    const [a, b] = [
      new Device("alice", testClock()),
      new Device("bob", testClock()),
    ];
    const boom = new Error("caller getter");
    const out = Object.defineProperty({ tracker: null, result: 0 }, "state", {
      get: () => {
        throw boom;
      },
      enumerable: true,
    });
    await expect(
      withSession(b.e, b.store, a.id, APP_CONV, async () => out as never),
    ).rejects.toBe(boom);
  });

  it("QR verification also checks the local payload's version", () => {
    const { e } = makeE2ee("qr2");
    const l = {
      accountSignPk: e.generateAccountIdentity().signPk,
      stableId: "l",
    };
    const r = {
      accountSignPk: e.generateAccountIdentity().signPk,
      stableId: "r",
    };
    const sl = e.computeSafetyNumber({ local: l, remote: r });
    const sr = e.computeSafetyNumber({ local: r, remote: l });
    const badLocal = sl.qrPayload.slice();
    badLocal[1] = 2;
    expect(e.verifySafetyNumberPayload(sl, sr.qrPayload)).toBe(true);
    expect(
      e.verifySafetyNumberPayload({ ...sl, qrPayload: badLocal }, sr.qrPayload),
    ).toBe(false);
  });
});

describe("final mutation gaps", () => {
  it("UTF-8: lone continuation-byte pairs are invalid", () => {
    for (const h of ["bfbf", "8080", "80bf"])
      expect(utf8DecodeStrict(hex(h)), h).toBeNull();
  });

  it("malformed account and OTP key-pair structs are E2EE_INVALID_STATE", () => {
    const [a, b] = two();
    initiate(a, b);
    const m = send(a, "x");
    expectCode(
      () =>
        accept(b, a, m, {
          lookupOtp: (id: number) => ({ ...b.otps.get(id)!, extra: 1 }),
        }),
      "E2EE_INVALID_STATE",
    );
    const { e } = makeE2ee("acct2");
    const eph = e.generateLinkEphemeral();
    expectCode(
      () =>
        e.sealAccountKey({
          account: { ...e.generateAccountIdentity(), signSk: "x" },
          transcript: b64uEncode(new Uint8Array(32)),
          ephSelf: eph,
          ephPeerPk: eph.pk,
        }),
      "E2EE_INVALID_STATE",
    );
  });

  it("wire errors carry details.path for a bad ciphertext and from handshakeDigest", () => {
    const [a, b] = two();
    initiate(a, b);
    const m = send(a, "x");
    expect(
      expectCode(
        () => a.e.parseMessage({ ...m, ciphertext: "!!" }),
        "E2EE_INVALID_INPUT",
      ).details,
    ).toEqual({ path: "ciphertext" });
    expect(
      expectCode(
        () => a.e.handshakeDigest({ ...m.handshake!, spkId: 0 }),
        "E2EE_INVALID_INPUT",
      ).details,
    ).toEqual({ path: "spkId" });
  });
});
