// Prints the CHANGELOG.md section for one version, for the GitHub release body.
//   node scripts/release-notes.mjs 1.0.1
import { readFileSync } from "node:fs";

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  console.error("usage: node scripts/release-notes.mjs X.Y.Z");
  process.exit(2);
}
const lines = readFileSync(
  new URL("../CHANGELOG.md", import.meta.url),
  "utf8",
).split("\n");
const start = lines.findIndex((l) => l.startsWith(`## [${version}]`));
if (start < 0) {
  console.error(`release-notes: no "## [${version}]" section in CHANGELOG.md`);
  process.exit(1);
}
const end = lines.findIndex((l, i) => i > start && l.startsWith("## ["));
console.log(
  lines
    .slice(start + 1, end < 0 ? undefined : end)
    .join("\n")
    .trim(),
);
