// D14 + H7: production dependencies are exactly this allowlist, pinned exact,
// and every package in the production tree carries a permissive licence.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

const ALLOWED = ["@noble/ciphers", "@noble/curves", "@noble/hashes", "zod"];
const LICENCES = new Set([
  "MIT",
  "ISC",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
]);

const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const deps = pkg.dependencies ?? {};
const errors = [];

const names = Object.keys(deps).sort();
if (JSON.stringify(names) !== JSON.stringify(ALLOWED)) {
  errors.push(
    `dependencies must be exactly ${ALLOWED.join(", ")}; got ${names.join(", ") || "(none)"}`,
  );
}
for (const [name, range] of Object.entries(deps)) {
  if (!/^\d+\.\d+\.\d+$/.test(range))
    errors.push(`${name} must be pinned exact, got "${range}"`);
}
for (const field of [
  "peerDependencies",
  "optionalDependencies",
  "bundleDependencies",
]) {
  if (pkg[field] && Object.keys(pkg[field]).length)
    errors.push(`${field} is not allowed`);
}

const tree = JSON.parse(
  execFileSync(
    "npx",
    [
      "--no-install",
      "license-checker-rseidelsohn",
      "--production",
      "--json",
      "--excludePrivatePackages",
    ],
    {
      encoding: "utf8",
    },
  ),
);
for (const [id, info] of Object.entries(tree)) {
  const lic = String(info.licenses);
  if (!LICENCES.has(lic))
    errors.push(`${id}: licence "${lic}" not on the allowlist`);
}

if (errors.length) {
  for (const e of errors) console.error(`check-deps: ${e}`);
  process.exit(1);
}
console.log(
  `check-deps: ok (${names.length} runtime deps, ${Object.keys(tree).length} packages in production tree)`,
);
