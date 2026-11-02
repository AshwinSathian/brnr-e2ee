// S-1: superseded sessions are retired, so a stale copy of the state cannot re-activate one (SPEC §8.1).
import { describe, expect, it } from "vitest";
import type { MessageV2, SessionState, SuiteId } from "../../src/index.js";
import { b64uDecode, b64uEncode } from "../../src/codec.js";
import {
  aeadOpen,
  aeadSeal,
  x25519Dh,
  x25519PublicKey,
} from "../../src/primitives.js";
import { aadOf, kdfCk, kdfRk, messageKey, pad } from "../../src/ratchet.js";
import { expectCode, testClock } from "../helpers.js";
import {
  adFrom,
  commit,
  initiate,
  party,
  receive,
  send,
  type Party,
} from "../parties.js";

const H = 3600_000;
const raw = (s: string) => b64uDecode(s) as Uint8Array;
interface Sess {
  sid: string;
  role: string;
  rk: string;
  dhs: { pk: string; sk: string };
  dhr?: string;
  cks?: string;
  ckr?: string;
  nr: number;
  lastUsedAt: string;
  retiredAt?: string;
}
interface St {
  suite: SuiteId;
  activeSid: string;
  selfBoxPk: string;
  peerBoxPk: string;
  selfSignPk?: string;
  peerSignPk?: string;
  sessions: Sess[];
}
const snap = (s: SessionState | null): St =>
  JSON.parse(JSON.stringify(s)) as St;
/** The keys bound into the message key (SPEC §7.4); every session here has the state's suite. */
function ik(s: St, x: Sess): string[] {
  const self = [s.selfBoxPk, s.selfSignPk!];
  const peer = [s.peerBoxPk, s.peerSignPk!];
  const [a, b] = x.role === "initiator" ? [self, peer] : [peer, self];
  return s.suite === "x25519-xchacha20poly1305-sha256-v2"
    ? [a[0]!, b[0]!, a[1]!, b[1]!]
    : [a[0]!, b[0]!];
}

/** The attacker forges `from → victim` on `sid` from a stolen copy of the victim's state. */
function forge(stolen: St, sid: string, from: Party, text: string): MessageV2 {
  const x = stolen.sessions.find((y) => y.sid === sid)!;
  const [, mk] = kdfCk(raw(x.ckr!));
  const ad = adFrom(from);
  const header = { sid, dh: x.dhr!, pn: 0, n: x.nr };
  const nonce = new Uint8Array(24).fill(7);
  const fields = { v: 2 as const, suite: stolen.suite, ad, header };
  const ct = aeadSeal(
    messageKey(mk, ad, ik(stolen, x)),
    nonce,
    pad(new TextEncoder().encode(text)),
    aadOf(fields),
  );
  return { ...fields, nonce: b64uEncode(nonce), ciphertext: b64uEncode(ct) };
}

/** As forge, but with a fresh attacker ratchet key: a confirmed decrypt on the victim's side. */
function forgeStep(
  stolen: St,
  sid: string,
  from: Party,
  text: string,
): MessageV2 {
  const x = stolen.sessions.find((y) => y.sid === sid)!;
  const esk = new Uint8Array(32).fill(9);
  const epk = x25519PublicKey(esk);
  const [, ckr] = kdfRk(raw(x.rk), x25519Dh(esk, raw(x.dhs.pk)), stolen.suite);
  const [, mk] = kdfCk(ckr);
  const ad = adFrom(from);
  const header = { sid, dh: b64uEncode(epk), pn: 0, n: 0 };
  const nonce = new Uint8Array(24).fill(8);
  const fields = { v: 2 as const, suite: stolen.suite, ad, header };
  const ct = aeadSeal(
    messageKey(mk, ad, ik(stolen, x)),
    nonce,
    pad(new TextEncoder().encode(text)),
    aadOf(fields),
  );
  return { ...fields, nonce: b64uEncode(nonce), ciphertext: b64uEncode(ct) };
}

/** True if the stolen sending chain of `sid` opens `m`. */
function stolenChainOpens(stolen: St, sid: string, m: MessageV2): boolean {
  const x = stolen.sessions.find((y) => y.sid === sid)!;
  const [, mk] = kdfCk(raw(x.cks!));
  return (
    aeadOpen(
      messageKey(mk, m.ad, ik(stolen, x)),
      raw(m.nonce),
      raw(m.ciphertext),
      aadOf(m),
    ) !== null
  );
}

/** S1 established both ways, then Alice refreshes to S2 and Bob accepts it. */
function twoSessions(clock = testClock()) {
  const a = party("alice", clock);
  const b = party("bob", clock);
  initiate(a, b);
  receive(b, a, send(a, "s1-hello"));
  receive(a, b, send(b, "s1-reply"));
  const s1 = snap(a.state).activeSid;
  initiate(a, b);
  receive(b, a, send(a, "s2-hello"));
  return { a, b, s1, s2: snap(a.state).activeSid, clock };
}

const heal = (a: Party, b: Party) => {
  for (let i = 0; i < 3; i++) {
    receive(a, b, send(b, `heal-b-${i}`));
    receive(b, a, send(a, `heal-a-${i}`));
  }
};

describe("S-1: a stale state cannot re-activate a superseded session", () => {
  it("after healing, a forged message on the old session does not flip activeSid or expose the next send", () => {
    const { a, b, s1, s2 } = twoSessions();
    const stolen = snap(b.state);
    expect(stolen.activeSid).toBe(s2);
    heal(a, b);
    expect(
      snap(b.state).sessions.find((x) => x.sid === s1)!.retiredAt,
    ).toBeDefined();
    // Within the 48 h window the forged message still authenticates, but s1 stays retired.
    const r = b.e.decrypt({
      state: b.state!,
      message: forge(stolen, s1, a, "forged"),
      expectedAd: adFrom(a),
    });
    expect(r.advancedReceiveChain).toBe(true);
    commit(b, r.state);
    expect(snap(b.state).activeSid).toBe(s2);
    const out = send(b, "secret after healing");
    expect(out.header.sid).toBe(s2);
    expect(stolenChainOpens(stolen, s1, out)).toBe(false);
  });

  it("10 days after healing the old session is gone: the forgery is a routing error and the next send stays on s2", () => {
    const clock = testClock();
    const { a, b, s1, s2 } = twoSessions(clock);
    receive(a, b, send(b, "ack")); // Alice decrypts on active s2 with a DH step: s1 retired
    const stolen = snap(a.state);
    heal(a, b);
    clock.advance(10 * 24 * H);
    expectCode(
      () =>
        a.e.decrypt({
          state: a.state!,
          message: forge(stolen, s1, b, "x"),
          expectedAd: adFrom(b),
        }),
      "E2EE_HANDSHAKE_REQUIRED",
    );
    const m = send(a, "the launch code is 0000");
    expect(m.header.sid).toBe(s2);
    expect(snap(a.state).sessions.map((x) => x.sid)).toEqual([s2]);
  });

  it("a retired session decrypts in-flight messages for 48 h, then routes as deleted and is removed at the next commit", () => {
    const clock = testClock();
    const a = party("alice", clock);
    const b = party("bob", clock);
    initiate(a, b);
    receive(b, a, send(a, "s1-hello"));
    receive(a, b, send(b, "s1-reply"));
    const s1 = snap(a.state).activeSid;
    const late = [send(b, "late-1"), send(b, "late-2"), send(b, "late-3")];
    initiate(a, b);
    receive(b, a, send(a, "s2-hello"));
    receive(a, b, send(b, "s2-reply"));
    const s2 = snap(a.state).activeSid;
    const retiredAt = snap(a.state).sessions.find(
      (x) => x.sid === s1,
    )!.retiredAt!;
    expect(retiredAt).toBe(new Date(clock.ms).toISOString());
    expect(
      a.e.inspectSession(a.state!).sessions.map((x) => x.retiredAt),
    ).toEqual([retiredAt, null]);
    clock.advance(48 * H);
    expect(receive(a, b, late[0]!)).toBe("late-1");
    expect(snap(a.state).activeSid).toBe(s2);
    // A later confirmed decrypt on s2 keeps the first retiredAt.
    receive(b, a, send(a, "more"));
    receive(a, b, send(b, "more-reply"));
    expect(snap(a.state).sessions.find((x) => x.sid === s1)!.retiredAt).toBe(
      retiredAt,
    );
    clock.advance(1);
    expectCode(
      () =>
        a.e.decrypt({
          state: a.state!,
          message: late[1]!,
          expectedAd: adFrom(b),
        }),
      "E2EE_HANDSHAKE_REQUIRED",
    );
    send(a, "commit");
    expect(snap(a.state).sessions.map((x) => x.sid)).toEqual([s2]);
  });

  it("a retiredAt more than 24 h ahead of the clock has expired (a clock stepped back cannot extend the window)", () => {
    const clock = testClock();
    const { a, b, s1 } = twoSessions(clock);
    receive(a, b, send(b, "ack"));
    clock.advance(-(24 * H + 1));
    const st = snap(a.state);
    expect(st.sessions.find((x) => x.sid === s1)!.retiredAt).toBeDefined();
    send(a, "commit");
    expect(snap(a.state).sessions.some((x) => x.sid === s1)).toBe(false);
  });

  it("at the 24 h tolerance a future retiredAt is kept", () => {
    const clock = testClock();
    const { a, b, s1 } = twoSessions(clock);
    receive(a, b, send(b, "ack"));
    clock.advance(-24 * H);
    send(a, "commit");
    expect(snap(a.state).sessions.some((x) => x.sid === s1)).toBe(true);
  });

  it("eviction prefers a retired session over an older live one", () => {
    const clock = testClock();
    const { a, b, s1, s2 } = twoSessions(clock);
    receive(a, b, send(b, "ack")); // s1 retired on Alice, lastUsedAt T0
    // A third, live session from Bob, used after s1.
    clock.advance(H);
    initiate(b, a);
    receive(a, b, send(b, "s3"));
    const s3 = snap(a.state).activeSid;
    // Make s1 (retired) the most recently used non-active session.
    const j = snap(a.state);
    j.sessions.find((x) => x.sid === s1)!.lastUsedAt = new Date(
      clock.ms,
    ).toISOString();
    j.sessions.find((x) => x.sid === s2)!.lastUsedAt = new Date(
      clock.ms - H,
    ).toISOString();
    a.state = j as unknown as SessionState;
    initiate(a, b);
    const left = snap(a.state).sessions.map((x) => x.sid);
    expect(left).not.toContain(s1);
    expect(left).toContain(s2);
    expect(left).toContain(s3);
  });

  it("parseState rejects a retired active session and a malformed retiredAt", () => {
    const { a, b, s1 } = twoSessions();
    receive(a, b, send(b, "ack"));
    const j = snap(a.state);
    const bad1 = { ...j, activeSid: s1 };
    expectCode(
      () => a.e.parseState(JSON.stringify(bad1)),
      "E2EE_INVALID_STATE",
    );
    const bad2 = structuredClone(j);
    bad2.sessions.find((x) => x.sid === s1)!.retiredAt = "yesterday";
    expectCode(
      () => a.e.parseState(JSON.stringify(bad2)),
      "E2EE_INVALID_STATE",
    );
    expect(a.e.parseState(JSON.stringify(j))).toEqual(j);
  });

  it("simultaneous initiation still converges (retirement needs a DH step over an existing dhr)", () => {
    const clock = testClock();
    const a = party("alice", clock);
    const b = party("bob", clock);
    initiate(a, b);
    initiate(b, a);
    const as = [send(a, "a1"), send(a, "a2")];
    const bs = [send(b, "b1"), send(b, "b2")];
    receive(b, a, as[0]!);
    receive(a, b, bs[0]!);
    receive(b, a, as[1]!);
    receive(a, b, bs[1]!);
    // No side has retired anything yet: neither has seen a reply on its active session.
    expect(snap(a.state).sessions.every((x) => x.retiredAt === undefined)).toBe(
      true,
    );
    receive(b, a, send(a, "a3"));
    receive(a, b, send(b, "b3"));
    expect(snap(a.state).activeSid).toBe(snap(b.state).activeSid);
    receive(b, a, send(a, "a4"));
    expect(snap(a.state).activeSid).toBe(snap(b.state).activeSid);
    // Each side retires exactly the sessions it created before the winner. The side that
    // created the winner first keeps the other until it expires (THREATMODEL item 18).
    const shape = (p: Party) => {
      const st = snap(p.state);
      return st.sessions.map((x) => x.retiredAt !== undefined);
    };
    const winnerFirst = (p: Party) =>
      snap(p.state).sessions[0]!.sid === snap(p.state).activeSid;
    for (const p of [a, b])
      expect(shape(p)).toEqual(winnerFirst(p) ? [false, false] : [true, false]);
    expect([winnerFirst(a), winnerFirst(b)].sort()).toEqual([false, true]);
  });

  it("forging on an old session that is not yet retired cannot retire the newer active session, which recovers", () => {
    const clock = testClock();
    const a = party("alice", clock);
    const b = party("bob", clock);
    initiate(a, b);
    receive(b, a, send(a, "s1-hello"));
    receive(a, b, send(b, "s1-reply"));
    const s1 = snap(a.state).activeSid;
    clock.advance(H);
    initiate(a, b);
    receive(b, a, send(a, "s2-hello")); // Bob switches to s2; nothing retired yet
    const s2 = snap(b.state).activeSid;
    const stolen = snap(b.state);
    expect(stolen.sessions.every((x) => x.retiredAt === undefined)).toBe(true);
    // 1. Same-chain forgery: s1 becomes active again (pre-heal, nothing proves otherwise)...
    receive(b, a, forge(stolen, s1, a, "forged-1"));
    expect(snap(b.state).activeSid).toBe(s1);
    // 2. ...and a confirmed forgery on the now-active s1 must not retire the newer s2.
    receive(b, a, forgeStep(stolen, s1, a, "forged-2"));
    const after = snap(b.state);
    expect(after.activeSid).toBe(s1);
    expect(after.sessions.find((x) => x.sid === s2)!.retiredAt).toBeUndefined();
    // Alice's genuine traffic on s2 takes Bob back, and the next confirmed decrypt retires s1.
    receive(b, a, send(a, "s2-again"));
    expect(snap(b.state).activeSid).toBe(s2);
    receive(a, b, send(b, "s2-reply"));
    receive(b, a, send(a, "s2-confirmed"));
    const healed = snap(b.state);
    expect(healed.activeSid).toBe(s2);
    expect(healed.sessions.find((x) => x.sid === s1)!.retiredAt).toBeDefined();
    expect(send(b, "next").header.sid).toBe(s2);
  });

  it("a decrypt that only switches to a session retires nothing, and an older session never retires a newer one", () => {
    const clock = testClock();
    const a = party("alice", clock);
    const b = party("bob", clock);
    initiate(a, b);
    receive(b, a, send(a, "s1-hello"));
    receive(a, b, send(b, "s1-reply"));
    const s1 = snap(a.state).activeSid;
    const bobOnS1 = [send(b, "b-old-1")];
    receive(a, b, bobOnS1[0]!); // same chain, no step
    // Alice refreshes to s2 (newer); Bob has not seen it and replies on s1 with a new ratchet key.
    clock.advance(H);
    receive(b, a, send(a, "on-s1")); // Bob ratchets s1
    initiate(a, b);
    const s2 = snap(a.state).activeSid;
    const reply = send(b, "b-on-s1"); // Bob still on s1, new ratchet key
    receive(a, b, reply); // switches Alice back to s1: not confirmed-on-active, retires nothing
    expect(snap(a.state).activeSid).toBe(s1);
    expect(snap(a.state).sessions.every((x) => x.retiredAt === undefined)).toBe(
      true,
    );
    // A confirmed decrypt on s1, now active, must leave the newer s2 live.
    receive(b, a, send(a, "a-on-s1"));
    receive(a, b, send(b, "b-on-s1-again"));
    const st = snap(a.state);
    expect(st.activeSid).toBe(s1);
    expect(st.sessions.find((x) => x.sid === s2)!.retiredAt).toBeUndefined();
  });
});

describe("S-1 under clock skew: retirement follows creation order, not createdAt", () => {
  it("Bob's clock runs 23 h fast for S1 and is then corrected: healing on S2 still retires S1", () => {
    const ca = testClock();
    const cb = testClock();
    const a = party("alice", ca);
    const b = party("bob", cb);
    cb.set(cb.now().getTime() + 23 * H);
    initiate(a, b);
    receive(b, a, send(a, "s1-hello"));
    receive(a, b, send(b, "s1-reply"));
    const s1 = snap(a.state).activeSid;
    cb.set(cb.now().getTime() - 22 * H); // corrected, and an hour has passed
    ca.set(ca.now().getTime() + H);
    initiate(a, b);
    receive(b, a, send(a, "s2-hello"));
    const s2 = snap(b.state).activeSid;
    const stolen = snap(b.state);
    heal(a, b);
    expect(snap(b.state).activeSid).toBe(s2);
    expect(
      snap(b.state).sessions.find((x) => x.sid === s1)!.retiredAt,
    ).toBeDefined();
    commit(
      b,
      b.e.decrypt({
        state: b.state!,
        message: forgeStep(stolen, s1, a, "forged"),
        expectedAd: adFrom(a),
      }).state,
    );
    expect(snap(b.state).activeSid).toBe(s2);
    expect(
      snap(b.state).sessions.find((x) => x.sid === s2)!.retiredAt,
    ).toBeUndefined();
    const out = send(b, "secret");
    expect(out.header.sid).toBe(s2);
  });
});
