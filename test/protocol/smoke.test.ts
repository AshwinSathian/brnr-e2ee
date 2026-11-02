import { describe, expect, it } from "vitest";
import { initiate, party, receive, send } from "../parties.js";

describe("smoke", () => {
  it("round trip with 4-DH and 3-DH", () => {
    for (const otp of [true, false]) {
      const a = party("alice");
      const b = party("bob");
      initiate(a, b, otp);
      const m1 = send(a, "hi bob");
      expect(m1.handshake?.otpId !== undefined).toBe(otp);
      expect(receive(b, a, m1)).toBe("hi bob");
      const m2 = send(b, "hi alice");
      expect(m2.handshake).toBeUndefined();
      expect(receive(a, b, m2)).toBe("hi alice");
      const m3 = send(a, "again");
      expect(m3.handshake).toBeUndefined();
      expect(receive(b, a, m3)).toBe("again");
    }
  });
});
