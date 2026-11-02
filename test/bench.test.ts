// SPEC §17 counted-operation budget and a wall-clock gate.
// BENCH_RECORD=1 npx vitest run test/bench.test.ts   re-records the wall-clock baseline (owner's laptop).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { SessionState } from "../src/index.js";
import { ops } from "../src/testing.js";
import { adFrom, CONV, initiate, party, receive, send } from "./parties.js";

const BASELINE = new URL("./data/bench-baseline.json", import.meta.url);
const snapshot = () => ({ ...ops });
const diff = (a: typeof ops, b: typeof ops) => ({
  kdfCk: b.kdfCk - a.kdfCk,
  hkdf: b.hkdf - a.hkdf,
  x25519: b.x25519 - a.x25519,
  aeadOpen: b.aeadOpen - a.aeadOpen,
});
/** Minimum of five runs, to damp noise from parallel test workers. */
const time = (f: () => unknown): number => {
  let best = Infinity;
  for (let i = 0; i < 5; i++) {
    const t = performance.now();
    f();
    best = Math.min(best, performance.now() - t);
  }
  return best;
};

function worstCase() {
  const a = party("bench-a");
  const b = party("bench-b");
  initiate(a, b);
  receive(b, a, send(a, "m0"));
  for (let i = 0; i < 1000; i++) send(a, "dropped on X");
  receive(a, b, send(b, "reply"));
  for (let i = 0; i < 1000; i++) send(a, "dropped on Y");
  const worst = send(a, "n = 1000, pn = 1001");
  // A conflict-flow accept with 4-DH: a fresh session from a third device's view of b.
  initiate(a, b, true);
  const founding = send(a, "founding");
  return { a, b, worst, founding };
}

describe("SPEC §17 budget", () => {
  it("conflict accept (4-DH) + worst-case decrypt stay within 2,008 KDF_CK, 8 HKDF, 9 X25519, 1 AEAD", () => {
    const { a, b, worst, founding } = worstCase();
    expect(worst.header).toMatchObject({ n: 1000, pn: 1001 });
    const s0 = snapshot();
    const cand = b.e.acceptSession({
      conversationId: CONV,
      self: b.device,
      expectedPeerBoxPk: a.device.boxPk,
      expectedPeerSignPk: a.device.signPk,
      message: founding,
      lookupSpk: (id) => b.spks.get(id),
      lookupOtp: (id) => b.otps.get(id),
      seenHandshake: () => false,
      existing: b.state!,
    });
    const s1 = snapshot();
    const r = b.e.decrypt({
      state: b.state!,
      message: worst,
      expectedAd: adFrom(a),
    });
    const s2 = snapshot();
    const accept = diff(s0, s1);
    const decrypt = diff(s1, s2);
    expect(accept).toEqual({ kdfCk: 0, hkdf: 1, x25519: 6, aeadOpen: 0 });
    expect(decrypt).toEqual({ kdfCk: 2001, hkdf: 3, x25519: 3, aeadOpen: 1 });
    const total = {
      kdfCk: accept.kdfCk + decrypt.kdfCk,
      hkdf: accept.hkdf + decrypt.hkdf,
      x25519: accept.x25519 + decrypt.x25519,
      aeadOpen: accept.aeadOpen + decrypt.aeadOpen,
    };
    expect(total.kdfCk).toBeLessThanOrEqual(2008);
    expect(total.hkdf).toBeLessThanOrEqual(8);
    expect(total.x25519).toBeLessThanOrEqual(9);
    expect(total.aeadOpen).toBe(1);
    expect(new TextDecoder().decode(r.plaintext)).toBe("n = 1000, pn = 1001");
    expect(cand).toBeDefined();
  });
});

describe("wall clock (fails above 3× the recorded baseline)", () => {
  it("worst-case decrypt and 2,000-key state parse/serialise", () => {
    const { a, b, worst } = worstCase();
    const tDecrypt = time(() =>
      b.e.decrypt({ state: b.state!, message: worst, expectedAd: adFrom(a) }),
    );
    const big = b.e.decrypt({
      state: b.state!,
      message: worst,
      expectedAd: adFrom(a),
    }).state;
    let st = big;
    const text = b.e.serializeState(st);
    const j = JSON.parse(text) as {
      skipped: { keys: unknown[] }[];
      sessions: unknown[];
    };
    expect(j.skipped.reduce((n, g) => n + g.keys.length, 0)).toBe(2000);
    const tParse = time(() => (st = b.e.parseState(text)));
    const tSerialize = time(() => b.e.serializeState(st as SessionState));
    const now = {
      decrypt: tDecrypt,
      parseState: tParse,
      serializeState: tSerialize,
    };
    if (process.env["BENCH_RECORD"]) {
      writeFileSync(
        BASELINE,
        JSON.stringify(
          {
            recorded: new Date().toISOString(),
            node: process.version,
            ms: now,
          },
          null,
          1,
        ) + "\n",
      );
      return;
    }
    // Skipped under mutation testing, where instrumentation slows everything down.
    if (!existsSync(BASELINE) || process.env["BENCH_SKIP_WALLCLOCK"]) return;
    const base = (
      JSON.parse(readFileSync(BASELINE, "utf8")) as { ms: typeof now }
    ).ms;
    for (const k of Object.keys(now) as Array<keyof typeof now>)
      expect(now[k], k).toBeLessThanOrEqual(3 * base[k]);
  });
});
