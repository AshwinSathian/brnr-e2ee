// Writes vectors/*.json, or with --check regenerates them in memory and compares byte for byte.
//   node --import ./scripts/ts-hooks.mjs scripts/gen-vectors.ts [--check]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { buildVectors } from "./vectors.js";

const dir = new URL("../vectors/", import.meta.url);
const check = process.argv.includes("--check");
const files = buildVectors();
let bad = 0;
mkdirSync(dir, { recursive: true });
for (const [name, text] of Object.entries(files)) {
  const url = new URL(name, dir);
  if (check) {
    let cur = "";
    try {
      cur = readFileSync(url, "utf8");
    } catch {
      /* missing */
    }
    if (cur !== text) {
      console.error(`vectors: ${name} does not reproduce byte for byte`);
      bad++;
    }
  } else writeFileSync(url, text);
}
if (bad) process.exit(1);
console.log(
  `vectors: ${Object.keys(files).length} files ${check ? "reproduce byte for byte" : "written"}`,
);
