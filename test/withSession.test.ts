// withSession and the KeyStore contract (SPEC §10), incl. crash injection and concurrency (D13).
import { describe, expect, it } from "vitest";
import { E2eeError, withSession, type MessageV2 } from "../src/index.js";
import { CONV, Device } from "./app.js";
import { testClock } from "./helpers.js";
import { Crash, type CrashPoint } from "./store.js";

const pair = (transactional = true) => {
  const clock = testClock();
  return [
    new Device("alice", clock, transactional),
    new Device("bob", clock, transactional),
  ] as const;
};

async function rejectsCode(p: Promise<unknown>, code: string) {
  const err = await p.then(
    () => null,
    (x: unknown) => x,
  );
  expect(err).toBeInstanceOf(E2eeError);
  expect((err as E2eeError).code).toBe(code);
}

describe("withSession basics (SPEC §10.2)", () => {
  it("first contact: accept, persist, then flush OTP delete and replay record", async () => {
    const [a, b] = pair();
    const m = await a.send(b, "hello");
    expect(b.store.otps.has(1)).toBe(true);
    expect(await b.receive(a, m)).toEqual({ text: "hello" });
    expect(b.store.otps.has(1)).toBe(false);
    expect([...b.store.replay.get(1)!]).toEqual([
      b.e.handshakeDigest(m.handshake!),
    ]);
    // The lists stay in the stored state as a backup until the next call persists the emptied copy.
    expect((await b.state(a))!["pendingOtpDeletes"]).toEqual([1]);
    const writes = b.store.writes.length;
    await withSession(b.e, b.store, a.id, CONV, async () => ({
      state: null,
      tracker: null,
      result: 0,
    }));
    expect(b.store.writes.length).toBe(writes + 2); // flush (null) + emptied state
    expect(b.store.writes.at(-2)).toMatchObject({
      serialized: null,
      opts: { deleteOtpIds: [1] },
    });
    expect((await b.state(a))!["pendingOtpDeletes"]).toEqual([]);
    expect((await b.state(a))!["pendingReplayRecords"]).toEqual([]);
  });

  it("writes only when something changed", async () => {
    const [a, b] = pair();
    await b.receive(a, await a.send(b, "x"));
    await withSession(b.e, b.store, a.id, CONV, async () => ({
      state: null,
      tracker: null,
      result: 0,
    }));
    const n = b.store.writes.length;
    await withSession(b.e, b.store, a.id, CONV, async (_s, t) => ({
      state: null,
      tracker: t,
      result: 0,
    }));
    expect(b.store.writes.length).toBe(n);
    // A tracker change alone is persisted without touching the session.
    await withSession(b.e, b.store, a.id, CONV, async (_s, t) => ({
      state: null,
      tracker: b.e.recordRecoverySignal(t, "handshake-required"),
      result: 0,
    }));
    expect(b.store.writes.length).toBe(n + 1);
    expect(b.store.writes.at(-1)!.serialized).toBeNull();
    expect(b.store.writes.at(-1)!.opts.tracker).toBeDefined();
  });

  it("validates ids and fn's return; caller and store errors propagate unchanged", async () => {
    const [a, b] = pair();
    await rejectsCode(
      withSession(b.e, b.store, "bad id", CONV, async () => ({
        state: null,
        tracker: null,
        result: 0,
      })),
      "E2EE_INVALID_INPUT",
    );
    await rejectsCode(
      withSession(b.e, b.store, a.id, "", async () => ({
        state: null,
        tracker: null,
        result: 0,
      })),
      "E2EE_INVALID_INPUT",
    );
    await rejectsCode(
      withSession(b.e, b.store, a.id, CONV, (async () => undefined) as never),
      "E2EE_INVALID_INPUT",
    );
    await rejectsCode(
      withSession(b.e, b.store, a.id, CONV, 5 as never),
      "E2EE_INVALID_INPUT",
    );
    const boom = new Error("app");
    await expect(
      withSession(b.e, b.store, a.id, CONV, async () => Promise.reject(boom)),
    ).rejects.toBe(boom);
    b.store.crashAt = "put:before";
    await expect(
      withSession(b.e, b.store, a.id, CONV, async (_s, t) => ({
        state: null,
        tracker: b.e.recordRecoverySignal(t, "evicted-session"),
        result: 0,
      })),
    ).rejects.toBeInstanceOf(Crash);
    // An unparsable stored state surfaces as a typed error (consumer rule §19.13).
    b.store.sessions.set(`${a.id}|${CONV}`, {
      serialized: "{}",
      version: 9,
      tracker: null,
    });
    await rejectsCode(
      withSession(b.e, b.store, a.id, CONV, async () => ({
        state: null,
        tracker: null,
        result: 0,
      })),
      "E2EE_UNSUPPORTED_VERSION",
    );
  });
});

describe("D13: the lock prevents ratchet forks under concurrent encrypt", () => {
  it("concurrent sends get distinct counters and all decrypt", async () => {
    const [a, b] = pair();
    await b.receive(a, await a.send(b, "first"));
    await a.receive(b, await b.send(a, "reply"));
    const ms = await Promise.all(
      Array.from({ length: 5 }, (_, i) => a.send(b, `c${i}`)),
    );
    expect(new Set(ms.map((m) => m.header.n)).size).toBe(5);
    for (const m of ms) expect((await b.receive(a, m)).text).toMatch(/^c\d$/);
  });

  it("without the lock, the version check rejects the forked write", async () => {
    const clock = testClock();
    const a = new Device("alice", clock, true, false);
    const b = new Device("bob", clock);
    await b.receive(a, await a.send(b, "first"));
    const results = await Promise.allSettled([a.send(b, "x"), a.send(b, "y")]);
    expect(results.map((r) => r.status).sort()).toEqual([
      "fulfilled",
      "rejected",
    ]);
  });
});

describe("crash injection (SPEC §8.5, §8.6, §10.2)", () => {
  const points: CrashPoint[] = [
    "put:before",
    "put:after-session",
    "put:mid-device",
    "put:after",
    "deleteOtp:before",
  ];
  for (const transactional of [true, false])
    for (const point of points) {
      if (
        transactional &&
        (point === "put:after-session" || point === "put:mid-device")
      )
        continue;
      it(`${transactional ? "transactional" : "non-transactional"} store, crash at ${point}`, async () => {
        const [a, b] = pair(transactional);
        const m = await a.send(b, "founding");
        const digest = b.e.handshakeDigest(m.handshake!);
        b.store.crashAt = point;
        const first = await b.receive(a, m).then(
          (r) => r,
          (e: unknown) => e,
        );
        const persisted = (await b.state(a)) !== null;
        // Never delete an OTP before the session that used it is durable.
        if (!persisted) expect(b.store.otps.has(1)).toBe(true);
        if (first instanceof Crash) {
          // Restart: if nothing was persisted, redelivery works; otherwise the next call flushes.
          if (!persisted)
            expect(await b.receive(a, m)).toEqual({ text: "founding" });
        } else expect(first).toEqual({ text: "founding" });
        await withSession(b.e, b.store, a.id, CONV, async () => ({
          state: null,
          tracker: null,
          result: 0,
        }));
        expect(b.store.otps.has(1)).toBe(false);
        expect(b.store.replay.get(1)?.has(digest)).toBe(true);
        const st = (await b.state(a))!;
        expect(st["pendingOtpDeletes"]).toEqual([]);
        expect(st["pendingReplayRecords"]).toEqual([]);
        // The session still works after recovery from the crash.
        expect((await b.receive(a, await a.send(b, "after"))).text).toBe(
          "after",
        );
      });
    }

  it("a crash inside the step 2 flush is repaired by the next call", async () => {
    for (const transactional of [true, false]) {
      const [a, b] = pair(transactional);
      await b.receive(a, await a.send(b, "x"));
      b.store.crashAt = "deleteOtp:before";
      b.store.otps.set(
        1,
        b.store.otps.get(1) ?? (b.e.generateOneTimePrekeys(1, 1)[0] as never),
      );
      await expect(
        withSession(b.e, b.store, a.id, CONV, async () => ({
          state: null,
          tracker: null,
          result: 0,
        })),
      ).rejects.toBeInstanceOf(Crash);
      await withSession(b.e, b.store, a.id, CONV, async () => ({
        state: null,
        tracker: null,
        result: 0,
      }));
      expect(b.store.otps.has(1)).toBe(false);
      expect((await b.state(a))!["pendingOtpDeletes"]).toEqual([]);
    }
  });

  it("a replay record for a deleted SPK is ignored by the store", async () => {
    const [a, b] = pair();
    const m = await a.send(b, "x");
    await b.receive(a, m);
    expect(b.store.replay.get(1)?.size).toBe(1);
    b.store.spks.delete(1);
    b.store.replay.delete(1);
    await withSession(b.e, b.store, a.id, CONV, async () => ({
      state: null,
      tracker: null,
      result: 0,
    }));
    expect(b.store.replay.has(1)).toBe(false);
  });
});

describe("R5-1: recovery driven through withSession", () => {
  it("first sighting → second sighting → re-initiation → control message restores delivery", async () => {
    const [a, b] = pair();
    await b.receive(a, await a.send(b, "1"));
    await a.receive(b, await b.send(a, "2"));
    // Bob loses the session (e.g. evicted, or deleted by a GC path).
    await b.deleteSession(a);
    const lost1 = await a.send(b, "lost 1");
    expect(await b.receive(a, lost1)).toMatchObject({
      error: "E2EE_HANDSHAKE_REQUIRED",
      reason: "handshake-required",
    });
    const tracker1 = b.store.sessions.get(`${a.id}|${CONV}`)!.tracker!;
    expect(JSON.parse(tracker1).sightings).toHaveLength(1);
    expect(await b.maybeRecover(a)).toBeNull();
    b.clock.advance(10 * 60 * 1000);
    expect(await b.receive(a, await a.send(b, "lost 2"))).toMatchObject({
      error: "E2EE_HANDSHAKE_REQUIRED",
    });
    const control = (await b.maybeRecover(a)) as MessageV2;
    expect(control.handshake).toBeDefined();
    const t = JSON.parse(b.store.sessions.get(`${a.id}|${CONV}`)!.tracker!) as {
      attempts: number;
      window: string[];
    };
    expect(t.attempts).toBe(1);
    expect(t.window).toHaveLength(1);
    expect(await a.receive(b, control)).toEqual({ text: "session-refresh" });
    expect((await b.receive(a, await a.send(b, "restored"))).text).toBe(
      "restored",
    );
    const after = JSON.parse(
      b.store.sessions.get(`${a.id}|${CONV}`)!.tracker!,
    ) as { attempts: number; sightings: string[] };
    expect(after.attempts).toBe(0);
    expect(after.sightings).toEqual([]);
  });
});

describe("review round 2 regressions", () => {
  it("withSession itself deletes OTPs (store ignores deleteOtpIds)", async () => {
    const [a, b] = pair();
    b.store.ignoreDeleteOtpIds = true;
    await b.receive(a, await a.send(b, "x"));
    expect(b.store.otps.has(1)).toBe(false);
  });

  it("a crash inside the step 2 flush write is repaired, for every point and order", async () => {
    const points: CrashPoint[] = [
      "put:before",
      "put:after-session",
      "put:mid-device",
      "put:after",
    ];
    for (const transactional of [true, false])
      for (const replayFirst of [false, true])
        for (const point of points) {
          const [a, b] = pair(transactional);
          b.store.replayFirst = replayFirst;
          const m = await a.send(b, "x");
          b.store.otps.set(1, b.store.otps.get(1)!);
          // Persist the state with pending lists but no device records (crash right after).
          b.store.crashAt = transactional ? "put:before" : "put:after-session";
          await b.receive(a, m).catch(() => undefined);
          if ((await b.state(a)) === null)
            await b.receive(a, m).catch(() => undefined);
          b.store.crashAt = point;
          await withSession(b.e, b.store, a.id, CONV, async () => ({
            state: null,
            tracker: null,
            result: 0,
          })).catch(() => undefined);
          await withSession(b.e, b.store, a.id, CONV, async () => ({
            state: null,
            tracker: null,
            result: 0,
          }));
          expect(
            b.store.otps.has(1),
            `${transactional} ${replayFirst} ${point}`,
          ).toBe(false);
          expect(
            b.store.replay.get(1)?.has(b.e.handshakeDigest(m.handshake!)),
          ).toBe(true);
          expect((await b.state(a))!["pendingOtpDeletes"]).toEqual([]);
        }
  });

  it("rejects bad fn results, foreign states, bad trackers and incomplete stores", async () => {
    const [a, b] = pair();
    await b.receive(a, await a.send(b, "x"));
    await rejectsCode(
      withSession(b.e, b.store, a.id, CONV, (async () => []) as never),
      "E2EE_INVALID_INPUT",
    );
    await rejectsCode(
      withSession(b.e, b.store, "someone-else", CONV, async () => ({
        state: b.e.parseState(
          (await b.state(a)) ? JSON.stringify(await b.state(a)) : "",
        ),
        tracker: null,
        result: 0,
      })),
      "E2EE_INVALID_INPUT",
    );
    await rejectsCode(
      withSession(b.e, b.store, a.id, CONV, async () => ({
        state: null,
        tracker: { v: 1, sightings: [], attempts: -1, window: [] },
        result: 0,
      })),
      "E2EE_INVALID_STATE",
    );
    await withSession(b.e, b.store, a.id, CONV, async (_s, t) => ({
      state: null,
      tracker: b.e.recordRecoverySignal(t, "evicted-session"),
      result: 0,
    }));
    await rejectsCode(
      withSession(b.e, b.store, a.id, CONV, async () => ({
        state: null,
        tracker: { v: 1, sightings: [], attempts: -1, window: [] },
        result: 0,
      })),
      "E2EE_INVALID_STATE",
    );
    const n = b.store.writes.length;
    await withSession(b.e, b.store, a.id, CONV, async () => ({
      state: null,
      tracker: undefined as never,
      result: 0,
    }));
    expect(b.store.writes.length).toBe(n);
    const { withLock: _w, ...noLock } = b.store as unknown as Record<
      string,
      unknown
    >;
    void _w;
    await rejectsCode(
      withSession(
        b.e,
        Object.assign(Object.create(null), noLock) as never,
        a.id,
        CONV,
        async () => ({ state: null, tracker: null, result: 0 }),
      ),
      "E2EE_INVALID_INPUT",
    );
    await rejectsCode(
      withSession(b.e, null as never, a.id, CONV, async () => ({
        state: null,
        tracker: null,
        result: 0,
      })),
      "E2EE_INVALID_INPUT",
    );
    // A state-only write (send returns tracker null) passes no tracker, so the stored one is untouched.
    const before = b.store.sessions.get(`${a.id}|${CONV}`)!.tracker;
    await b.send(a, "y");
    expect(b.store.writes.at(-1)!.opts.tracker).toBeUndefined();
    expect(b.store.sessions.get(`${a.id}|${CONV}`)!.tracker).toBe(before);
  });
});
