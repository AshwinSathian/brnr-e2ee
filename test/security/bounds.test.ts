// F1-F3: size caps run before any per-element or per-character work (SPEC §4.1, §4.7, §9.1).
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { LIMITS } from "../../src/index.js";
import { b64uDecode } from "../../src/codec.js";
import { expectCode, makeE2ee } from "../helpers.js";
import { initiate, party, receive, send } from "../parties.js";

const root = fileURLToPath(new URL("../../", import.meta.url));

describe("F1: device list entry cap", () => {
  it("a ~900 KB list of 300,000 entries gives DEVICE_LIST_INVALID inside a 256 MB heap", () => {
    const dir = mkdtempSync(join(tmpdir(), "brnr-f1-"));
    const evil = `{"v":1,"accountId":"a","accountSignPk":"x","epoch":1,"devices":[${Array(300_000).fill("{}").join(",")}],"sig":"x"}`;
    expect(evil.length).toBeLessThan(1_000_000);
    const evilPath = join(dir, "evil.json");
    writeFileSync(evilPath, evil);
    const script = join(dir, "run.mjs");
    writeFileSync(
      script,
      `import { readFileSync } from "node:fs";
       import { createE2ee, E2eeError } from ${JSON.stringify(join(root, "src/index.ts"))};
       const text = readFileSync(${JSON.stringify(evilPath)}, "utf8");
       try { createE2ee().parseDeviceList(text); } catch (err) {
         console.log("CAUGHT", err instanceof E2eeError, err.code);
       }`,
    );
    const r = spawnSync(
      process.execPath,
      [
        "--max-old-space-size=256",
        "--import",
        join(root, "scripts/ts-hooks.mjs"),
        script,
      ],
      { encoding: "utf8", timeout: 60_000 },
    );
    expect(r.stderr).not.toMatch(/heap out of memory/i);
    expect(r.stdout.trim()).toBe("CAUGHT true E2EE_DEVICE_LIST_INVALID");
  }, 120_000);

  it("the cap runs after the version rule and in buildSignedDeviceList", () => {
    const { e } = makeE2ee("f1");
    const devices = Array(LIMITS.MAX_DEVICES + 1).fill({});
    const list = {
      v: 1,
      accountId: "a",
      accountSignPk: "x",
      epoch: 1,
      devices,
      sig: "x",
    };
    expectCode(() => e.parseDeviceList(list), "E2EE_DEVICE_LIST_INVALID");
    expectCode(
      () => e.parseDeviceList({ ...list, v: 2 }),
      "E2EE_UNSUPPORTED_VERSION",
    );
    // At the cap, entries are checked by the schema as before.
    expectCode(
      () => e.parseDeviceList({ ...list, devices: devices.slice(1) }),
      "E2EE_INVALID_INPUT",
    );
    // A non-array with a large length is left to the schema.
    expectCode(
      () => e.parseDeviceList({ ...list, devices: { length: 1000 } }),
      "E2EE_INVALID_INPUT",
    );
    const account = e.generateAccountIdentity();
    expectCode(
      () =>
        e.buildSignedDeviceList({ account, accountId: "a", epoch: 1, devices }),
      "E2EE_DEVICE_LIST_INVALID",
    );
    const trapped = new Proxy([], {
      get: () => {
        throw new Error("trap");
      },
    });
    expectCode(
      () =>
        e.buildSignedDeviceList({
          account,
          accountId: "a",
          epoch: 1,
          devices: trapped,
        }),
      "E2EE_INVALID_INPUT",
    );
  });
});

describe("F2: base64url length checked on the string", () => {
  it("a fixed-length field of the wrong string length is rejected before decoding", () => {
    expect(b64uDecode("A".repeat(43), 32)).not.toBeNull();
    expect(b64uDecode("A".repeat(44), 32)).toBeNull();
    expect(b64uDecode("A".repeat(42), 32)).toBeNull();
    expect(b64uDecode("A".repeat(11), 8)).not.toBeNull();
    expect(b64uDecode("A".repeat(86), 64)).not.toBeNull();
  });

  it("a 16 MB ciphertext is rejected by the length rule for less than the JSON.parse cost", () => {
    const { e } = makeE2ee("f2");
    const big = "A".repeat(16 * 1024 * 1024);
    const text = `{"v":2,"suite":"x25519-xchacha20poly1305-sha256-v1","header":{"sid":"AAAAAAAAAAA","dh":"${"A".repeat(43)}","pn":0,"n":0},"nonce":"${"A".repeat(32)}","ciphertext":"${big}","ad":{"conversationId":"c","senderDeviceId":"d","suite":"x25519-xchacha20poly1305-sha256-v1","v":2}}`;
    const obj: unknown = JSON.parse(text);
    let t = performance.now();
    JSON.parse(text);
    const base = performance.now() - t;
    t = performance.now();
    const err = expectCode(() => e.parseMessage(obj), "E2EE_INVALID_INPUT");
    const cost = performance.now() - t;
    expect(err.details).toEqual({ path: "ciphertext" });
    if (!process.env["BENCH_SKIP_WALLCLOCK"]) expect(cost).toBeLessThan(base);
  }, 60_000);
});

describe("F3: state arrays are bounded", () => {
  it("pendingOtpDeletes and pendingReplayRecords hold at most MAX_PENDING_RECORDS", () => {
    const a = party("alice");
    const b = party("bob");
    initiate(a, b);
    receive(b, a, send(a, "x"));
    const j = JSON.parse(b.e.serializeState(b.state!)) as Record<
      string,
      unknown
    >;
    const n = LIMITS.MAX_PENDING_RECORDS;
    const rec = { spkId: 1, hsDigest: "A".repeat(43) };
    const ok = {
      ...j,
      pendingOtpDeletes: Array(n).fill(1),
      pendingReplayRecords: Array(n).fill(rec),
    };
    expect(() => b.e.parseState(JSON.stringify(ok))).not.toThrow();
    for (const bad of [
      { ...ok, pendingOtpDeletes: Array(n + 1).fill(1) },
      { ...ok, pendingReplayRecords: Array(n + 1).fill(rec) },
      { ...j, skipped: Array(LIMITS.MAX_SKIPPED_KEYS + 1).fill({}) },
    ])
      expectCode(
        () => b.e.parseState(JSON.stringify(bad)),
        "E2EE_INVALID_STATE",
      );
  });
});
