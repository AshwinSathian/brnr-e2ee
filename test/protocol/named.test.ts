// Named session cases (SPEC §8) not covered elsewhere: three concurrent handshakes; R4-3 burst then silence.
import { describe, expect, it } from "vitest";
import { withSession } from "../../src/index.js";
import { CONV, Device } from "../app.js";
import { testClock } from "../helpers.js";

const MIN = 60_000;

describe("named model cases", () => {
  it("three concurrent handshakes cross in flight; nothing held is lost; converges", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock);
    const x = await a.send(b, "x"); // A initiates X
    const y = await b.send(a, "y"); // B initiates Y
    const z = await withSession(a.e, a.store, b.id, CONV, async (s, t) => {
      const n = a.e.initiateSession({
        conversationId: CONV,
        self: a.device,
        peerBundle: b.bundle(),
        existing: s!,
      });
      const r = a.encrypt(b, n, "z");
      return { state: r.state, tracker: t, result: r.message };
    }); // A re-initiates Z
    expect((await b.receive(a, z)).text).toBe("z");
    expect((await a.receive(b, y)).text).toBe("y");
    expect((await b.receive(a, x)).text).toBe("x");
    for (let i = 0; i < 2; i++) {
      expect((await b.receive(a, await a.send(b, `a${i}`))).text).toBe(`a${i}`);
      expect((await a.receive(b, await b.send(a, `b${i}`))).text).toBe(`b${i}`);
    }
    expect((await a.state(b))!["activeSid"]).toBe(
      (await b.state(a))!["activeSid"],
    );
  });

  it("R4-3: a burst on an evicted session, then silence: recovery fires about 10 minutes after the burst", async () => {
    const clock = testClock();
    const a = new Device("alice", clock);
    const b = new Device("bob", clock);
    await b.receive(a, await a.send(b, "hello"));
    await a.receive(b, await b.send(a, "hi")); // established: a's messages no longer carry the handshake
    await b.deleteSession(a);
    const start = clock.ms;
    for (let i = 0; i < 10; i++) {
      expect(await b.receive(a, await a.send(b, `burst ${i}`))).toMatchObject({
        error: "E2EE_HANDSHAKE_REQUIRED",
      });
      clock.advance(6_000);
    }
    clock.set(start + 10 * MIN);
    expect(await b.maybeRecover(a)).toBeNull(); // newest retained sighting is under 10 minutes old
    clock.set(start + 11 * MIN);
    const control = await b.maybeRecover(a);
    expect(control).not.toBeNull();
    expect((await a.receive(b, control!)).text).toBe("session-refresh");
    expect((await b.receive(a, await a.send(b, "after"))).text).toBe("after");
  });
});
