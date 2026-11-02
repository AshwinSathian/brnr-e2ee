// fast-check command model: two parties, three devices, pairwise sessions through withSession.
// Invariants:
//   I1 every successful decrypt yields a message that pair actually sent and has not delivered before;
//   I2 every forgery that changes AAD-bound bytes fails;
//   I3 failures are typed (E2eeError results) or injected crashes, nothing else;
//   I4 after a heal phase (recovery, pings) every pair delivers in both directions.
// Suites: a1 and b1 offer [v2, v1]; a2 starts as a 1.0 peer (v1 only) and may upgrade mid-run, so
// schedules mix v1 and v2 sessions and move states from v1 to v2 (SPEC §9.1).
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { MessageV2 } from "../../src/index.js";
import { b64uEncode } from "../../src/codec.js";
import { sidOf } from "../../src/x3dh.js";
import { Device } from "../app.js";
import { testClock } from "../helpers.js";
import { Crash, type CrashPoint } from "../store.js";

export const STATS: Record<string, number> = {};
const RUNS = Number(process.env["FC_NUM_RUNS"] ?? 1000);
const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const DEVICES = ["a1", "a2", "b1"] as const;
type Dev = (typeof DEVICES)[number];
/** Pairwise sessions only between the two parties' devices. */
const PAIRS: Array<[Dev, Dev]> = [
  ["a1", "b1"],
  ["b1", "a1"],
  ["a2", "b1"],
  ["b1", "a2"],
];

interface Flight {
  id: string;
  m: MessageV2;
}

class World {
  readonly clock = testClock();
  readonly d: Record<Dev, Device>;
  readonly inflight = new Map<string, Flight[]>();
  readonly sent = new Map<string, Set<string>>();
  readonly delivered = new Map<string, Set<string>>();
  readonly history = new Map<string, MessageV2[]>();
  private n = 0;

  constructor() {
    this.d = {
      a1: new Device("a1", this.clock, true),
      a2: new Device("a2", this.clock, false, true, [
        "x25519-xchacha20poly1305-sha256-v1",
      ]),
      b1: new Device("b1", this.clock, true),
    };
    for (const [f, t] of PAIRS) {
      const k = `${f}>${t}`;
      this.inflight.set(k, []);
      this.sent.set(k, new Set());
      this.delivered.set(k, new Set());
      this.history.set(k, []);
    }
  }

  async send(f: Dev, t: Dev, control?: MessageV2): Promise<void> {
    const k = `${f}>${t}`;
    let m = control;
    const id = control ? "session-refresh" : `${k}#${this.n++}`;
    if (!m) {
      try {
        m = await this.d[f].send(this.d[t], id);
      } catch (e) {
        if (e instanceof Crash) return; // crash before persist: nothing was sent
        throw e;
      }
    }
    this.sent.get(k)!.add(id);
    this.inflight.get(k)!.push({ id, m });
    this.history.get(k)!.push(m);
  }

  /** Delivers and checks I1/I3. Returns true on decrypt. */
  async deliver(f: Dev, t: Dev, m: MessageV2): Promise<boolean> {
    const k = `${f}>${t}`;
    let r;
    try {
      r = await this.d[t].receive(this.d[f], m);
    } catch (e) {
      if (e instanceof Crash) return false; // not persisted; may be redelivered
      throw e; // I3
    }
    const key = r.text === undefined ? `fail:${r.error}` : "ok";
    STATS[key] = (STATS[key] ?? 0) + 1;
    if (r.text === undefined) return false;
    if (r.text === "session-refresh") return true;
    expect(
      this.sent.get(k)!.has(r.text),
      `I1: ${r.text} was sent on ${k}`,
    ).toBe(true);
    expect(
      this.delivered.get(k)!.has(r.text),
      `I1: ${r.text} delivered once on ${k}`,
    ).toBe(false);
    this.delivered.get(k)!.add(r.text);
    return true;
  }

  /** I4: recovery and pings converge every pair. */
  async heal(): Promise<void> {
    for (const d of Object.values(this.d)) d.store.crashAt = null;
    for (const [f, t] of PAIRS)
      for (const x of this.inflight.get(`${f}>${t}`)!.splice(0))
        await this.deliver(f, t, x.m);
    const ok = new Map<string, boolean>();
    for (let round = 0; round < 6; round++) {
      this.clock.advance(DAY + MIN);
      for (const [f, t] of PAIRS) {
        const c = await this.d[f].maybeRecover(this.d[t]);
        if (c) await this.deliver(f, t, c);
      }
      for (const [f, t] of PAIRS) {
        const ping = await this.d[f].send(this.d[t], `${f}>${t}#ping${round}`);
        this.sent.get(`${f}>${t}`)!.add(`${f}>${t}#ping${round}`);
        ok.set(`${f}>${t}`, await this.deliver(f, t, ping));
      }
      if ([...ok.values()].every(Boolean)) return;
    }
    expect(Object.fromEntries(ok), "I4: every pair converges").toEqual(
      Object.fromEntries(PAIRS.map(([f, t]) => [`${f}>${t}`, true])),
    );
  }
}

type Cmd = fc.AsyncCommand<object, World>;
const pair = fc.constantFrom(...PAIRS);
const idx = fc.nat({ max: 9 });

class Send implements Cmd {
  constructor(readonly p: [Dev, Dev]) {}
  check = () => true;
  run = async (_: object, w: World) => w.send(...this.p);
  toString = () => `send(${this.p.join(">")})`;
}
class Deliver implements Cmd {
  constructor(
    readonly p: [Dev, Dev],
    readonly i: number,
    readonly keep: boolean,
  ) {}
  check = () => true;
  async run(_: object, w: World) {
    const q = w.inflight.get(this.p.join(">"))!;
    if (q.length === 0) return;
    const at = this.i % q.length;
    const x = q[at]!;
    if (!this.keep) q.splice(at, 1);
    await w.deliver(this.p[0], this.p[1], x.m);
  }
  toString = () =>
    `${this.keep ? "duplicate" : "deliver"}(${this.p.join(">")}, ${this.i})`;
}
class Drop implements Cmd {
  constructor(
    readonly p: [Dev, Dev],
    readonly i: number,
  ) {}
  check = () => true;
  async run(_: object, w: World) {
    const q = w.inflight.get(this.p.join(">"))!;
    if (q.length) q.splice(this.i % q.length, 1);
  }
  toString = () => `drop(${this.p.join(">")}, ${this.i})`;
}
class CrashNext implements Cmd {
  constructor(
    readonly d: Dev,
    readonly point: CrashPoint,
  ) {}
  check = () => true;
  async run(_: object, w: World) {
    w.d[this.d].store.crashAt = this.point;
  }
  toString = () => `crash(${this.d}, ${this.point})`;
}
class Reset implements Cmd {
  constructor(readonly p: [Dev, Dev]) {}
  check = () => true;
  async run(_: object, w: World) {
    try {
      await w.d[this.p[0]].deleteSession(w.d[this.p[1]]);
    } catch (e) {
      if (!(e instanceof Crash)) throw e;
    }
  }
  toString = () => `reset(${this.p.join(">")})`;
}
class Recover implements Cmd {
  constructor(readonly p: [Dev, Dev]) {}
  check = () => true;
  async run(_: object, w: World) {
    let c: MessageV2 | null = null;
    try {
      c = await w.d[this.p[0]].maybeRecover(w.d[this.p[1]]);
    } catch (e) {
      if (!(e instanceof Crash)) throw e;
    }
    if (c) await w.send(this.p[0], this.p[1], c);
  }
  toString = () => `recover(${this.p.join(">")})`;
}
class Upgrade implements Cmd {
  check = () => true;
  async run(_: object, w: World) {
    const d = w.d.a2;
    if (d.suites.length > 1) return;
    d.upgrade();
    STATS["upgrade"] = (STATS["upgrade"] ?? 0) + 1;
  }
  toString = () => "upgrade(a2)";
}
class Advance implements Cmd {
  constructor(readonly ms: number) {}
  check = () => true;
  async run(_: object, w: World) {
    w.clock.advance(this.ms);
  }
  toString = () => `advance(${this.ms})`;
}

const FORGERIES = [
  "n",
  "pn",
  "dh",
  "sid",
  "ad",
  "reattach",
  "nonce",
  "recipient",
  "identity",
] as const;
const IDENTITY_FIELDS = [
  "initiatorSignPk",
  "responderSignPk",
  "responderDeviceId",
] as const;
class Forge implements Cmd {
  constructor(
    readonly p: [Dev, Dev],
    readonly i: number,
    readonly kind: (typeof FORGERIES)[number],
  ) {}
  check = () => true;
  async run(_: object, w: World) {
    const k = this.p.join(">");
    const h = w.history.get(k)!;
    if (h.length === 0) return;
    const m = structuredClone(h[this.i % h.length]!);
    const other = h.find((x) => x.header.sid !== m.header.sid);
    let f: MessageV2;
    switch (this.kind) {
      case "n":
        f = { ...m, header: { ...m.header, n: m.header.n + 1 } };
        break;
      case "pn":
        f = { ...m, header: { ...m.header, pn: m.header.pn + 3 } };
        break;
      case "dh": // a known ratchet key from another message of the pair
        f = {
          ...m,
          header: {
            ...m.header,
            dh: (h.find((x) => x.header.dh !== m.header.dh) ?? m).header.dh,
          },
        };
        if (f.header.dh === m.header.dh)
          f.header.dh = b64uEncode(new Uint8Array(32).fill(9));
        break;
      case "sid": // swapped into another session of the pair
        if (!other) return;
        f = { ...m, header: { ...m.header, sid: other.header.sid } };
        break;
      case "ad":
        f = { ...m, ad: { ...m.ad, conversationId: "conv-other" } };
        break;
      case "reattach": {
        const hs = h.find(
          (x) => x.handshake && x.header.sid === m.header.sid,
        )?.handshake;
        if (m.handshake || !hs) return;
        f = { ...m, handshake: hs };
        break;
      }
      case "nonce":
        f = { ...m, nonce: b64uEncode(new Uint8Array(24).fill(1)) };
        break;
      case "recipient": {
        // v2: another recipient; v1: a field its AD does not have.
        const to = (m.ad as { recipientDeviceId?: string }).recipientDeviceId;
        f = {
          ...m,
          ad: {
            ...m.ad,
            recipientDeviceId: to === "a1-dev" ? "a2-dev" : "a1-dev",
          } as MessageV2["ad"],
        };
        break;
      }
      case "identity": {
        // A v2 handshake naming another identity, re-labelled with its own sid (SPEC §6.5).
        if (m.handshake?.initiatorSignPk === undefined) return;
        const field = IDENTITY_FIELDS[this.i % IDENTITY_FIELDS.length]!;
        const handshake = {
          ...m.handshake,
          [field]:
            field === "responderDeviceId"
              ? "mallory-dev"
              : b64uEncode(new Uint8Array(32).fill(5)),
        };
        f = {
          ...m,
          handshake,
          header: { ...m.header, sid: sidOf(handshake) },
        };
        break;
      }
    }
    let r;
    try {
      r = await w.d[this.p[1]].receive(w.d[this.p[0]], f);
    } catch (e) {
      if (e instanceof Crash) return;
      throw e;
    }
    STATS[`forge:${this.kind}:${r.error}`] =
      (STATS[`forge:${this.kind}:${r.error}`] ?? 0) + 1;
    expect(r.text, `I2: forgery ${this.kind} must not decrypt`).toBeUndefined();
  }
  toString = () => `forge(${this.p.join(">")}, ${this.i}, ${this.kind})`;
}

const commands = [
  pair.map((p) => new Send(p)),
  pair.map((p) => new Send(p)),
  pair.map((p) => new Send(p)),
  fc.tuple(pair, idx).map(([p, i]) => new Deliver(p, i, false)),
  fc.tuple(pair, idx).map(([p, i]) => new Deliver(p, i, false)),
  fc.tuple(pair, idx).map(([p, i]) => new Deliver(p, i, false)),
  fc.tuple(pair, idx).map(([p, i]) => new Deliver(p, i, true)),
  fc.tuple(pair, idx).map(([p, i]) => new Drop(p, i)),
  fc
    .tuple(
      fc.constantFrom(...DEVICES),
      fc.constantFrom<CrashPoint>(
        "put:before",
        "put:after-session",
        "put:mid-device",
        "put:after",
        "deleteOtp:before",
      ),
    )
    .map(([d, c]) => new CrashNext(d, c)),
  pair.map((p) => new Reset(p)),
  pair.map((p) => new Recover(p)),
  fc
    .constantFrom(MIN, 11 * MIN, 2 * 3600_000, DAY + 1, 31 * DAY)
    .map((ms) => new Advance(ms)),
  fc
    .tuple(pair, idx, fc.constantFrom(...FORGERIES))
    .map(([p, i, k]) => new Forge(p, i, k)),
  fc.constant(new Upgrade()),
];

describe("conversation model", () => {
  it(`random schedules keep I1-I4 (${RUNS} runs)`, async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.commands(commands, { maxCommands: 40, size: "max" }),
        async (cmds) => {
          const w = new World();
          await fc.asyncModelRun(() => ({ model: {}, real: w }), cmds);
          await w.heal();
        },
      ),
      { numRuns: RUNS },
    );
    if (process.env["MODEL_STATS"])
      (await import("node:fs")).writeFileSync(
        process.env["MODEL_STATS"],
        JSON.stringify(STATS, null, 1),
      );
  }, 3_600_000);
});
