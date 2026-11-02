// Per-file mutation gate: every mutated file must score ≥ 85%.
import { readFileSync } from "node:fs";

const report = JSON.parse(
  readFileSync("reports/mutation/mutation.json", "utf8"),
);
const DETECTED = new Set(["Killed", "Timeout"]);
const VALID = new Set(["Killed", "Timeout", "Survived", "NoCoverage"]);
let bad = 0;
let det = 0;
let all = 0;
for (const [file, { mutants }] of Object.entries(report.files)) {
  const v = mutants.filter((m) => VALID.has(m.status));
  const d = v.filter((m) => DETECTED.has(m.status)).length;
  det += d;
  all += v.length;
  const score = v.length ? (100 * d) / v.length : 100;
  const line = `${file.padEnd(24)} ${score.toFixed(2).padStart(6)}%  (${d}/${v.length})`;
  if (score < 85) {
    bad++;
    console.error(`mutation-gate: FAIL ${line}`);
  } else console.log(`mutation-gate: ok   ${line}`);
}
console.log(
  `mutation-gate: overall ${((100 * det) / all).toFixed(2)}% (${det}/${all})`,
);

// Tripwire for the vitest 5 shims in vitest.stryker.config.ts: a mutant that "survived" with no test
// completed means the test filter selected nothing (the bug the name shim fixes), not a real survivor.
const flat = Object.entries(report.files).flatMap(([f, { mutants }]) =>
  mutants.map((m) => ({ f, ...m })),
);
const empty = flat.filter(
  (m) => m.status === "Survived" && m.testsCompleted === 0,
);
for (const m of empty)
  console.error(
    `mutation-gate: FAIL ${m.f}:${m.location.start.line} survived with 0 tests run (test filter broken?)`,
  );
const runtime = flat.filter((m) => m.status === "RuntimeError").length;
console.log(
  `mutation-gate: ${runtime} runtime-error mutants (break module loading; excluded from the score)`,
);
if (bad || empty.length || (100 * det) / all < 90) process.exit(1);
