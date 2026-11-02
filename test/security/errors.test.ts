// B2: isE2eeError recognises an E2eeError thrown by the other build (ESM vs CJS) of the package.
import { describe, expect, it } from "vitest";
import { E2eeError, isE2eeError } from "../../src/index.js";

describe("B2: dual-package isE2eeError", () => {
  it("accepts a same-shaped error from another class, and nothing else", () => {
    class Other extends Error {
      constructor(readonly code: string) {
        super(code);
        this.name = "E2eeError";
      }
    }
    expect(isE2eeError(new E2eeError("E2EE_INVALID_INPUT"))).toBe(true);
    expect(isE2eeError(new Other("E2EE_DECRYPT_FAILED"))).toBe(true);
    expect(
      isE2eeError({ name: "E2eeError", code: "E2EE_RNG_UNAVAILABLE" }),
    ).toBe(true);
    expect(isE2eeError(new Other("E2EE_NOPE"))).toBe(false);
    expect(
      isE2eeError(
        Object.assign(new Error("x"), { code: "E2EE_INVALID_INPUT" }),
      ),
    ).toBe(false);
    const fn = Object.assign(function E2eeError() {}, {
      code: "E2EE_INVALID_INPUT",
    });
    expect(fn.name).toBe("E2eeError");
    expect(isE2eeError(fn)).toBe(false);
    for (const v of [null, undefined, "E2eeError", 5])
      expect(isE2eeError(v)).toBe(false);
    const trapped = new Proxy(
      {},
      {
        get: () => {
          throw new Error("trap");
        },
      },
    );
    expect(isE2eeError(trapped)).toBe(false);
  });
});
