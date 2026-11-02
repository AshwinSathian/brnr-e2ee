// Regenerates every vector in memory and compares it with vectors/*.json byte for byte.
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { buildVectors } from "../scripts/vectors.js";

it("vectors/*.json reproduce byte for byte", () => {
  const files = buildVectors();
  expect(Object.keys(files)).toHaveLength(22);
  for (const [name, text] of Object.entries(files))
    expect(
      text ===
        readFileSync(new URL(`../vectors/${name}`, import.meta.url), "utf8"),
      name,
    ).toBe(true);
}, 300_000);
