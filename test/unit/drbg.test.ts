import { describe, expect, it } from "vitest";
import { drbgRng, HmacDrbg, tapeRng } from "../../src/testing.js";
import { hex, toHex } from "../helpers.js";

describe("HMAC-DRBG (SP 800-90A §10.1.2)", () => {
  it("matches NIST CAVP HMAC_DRBG.rsp [SHA-256] no reseed, PersonalizationStringLen 256, COUNT 0", () => {
    // Source: csrc.nist.gov drbgtestvectors.zip, drbgvectors_no_reseed/HMAC_DRBG.rsp.
    const d = new HmacDrbg(
      hex("5cacc68165a2e2ee20812f35ec73a79dbf30fd475476ac0c44fc6174cdac2b55"),
      hex("6f885496c1e63af620becd9e71ecb824"),
      hex("e72dd8590d4ed5295515c35ed6199e9d211b8f069b3058caa6670b96ef1208d0"),
    );
    d.generate(128);
    expect(toHex(d.generate(128))).toBe(
      "f1012cf543f94533df27fedfbf58e5b79a3dc517a9c402bdbfc9a0c0f721f9d53faf4aafdc4b8f7a1b580fcaa52338d4bd95f58966a243cdcd3f446ed4bc546d9f607b190dd69954450d16cd0e2d6437067d8b44d19a6af7a7cfa8794e5fbd728e8fb2f2e8db5dd4ff1aa275f35886098e80ff844886060da8b1e7137846b23b",
    );
  });

  it("records and replays a tape with purposes", () => {
    const { rng, tape } = drbgRng(new Uint8Array(32));
    const a = rng(32, "seed");
    const b = rng(24, "nonce");
    expect(tape.map((t) => t.purpose)).toEqual(["seed", "nonce"]);
    const r = tapeRng(tape);
    expect(r(32, "seed")).toEqual(a);
    expect(r.remaining()).toBe(1);
    expect(() => r(24, "dhs")).toThrow(/tape mismatch/);
    expect(b).toHaveLength(24);
  });
});
