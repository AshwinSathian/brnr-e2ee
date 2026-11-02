// Mutation testing: every src/*.ts except index.ts. Gate: ≥ 90% overall (break), ≥ 85% per file
// (scripts/mutation-gate.mjs). Property tests run with fewer cases here: FC_NUM_RUNS is set by `npm run mutation`.
export default {
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner", "./stryker-ignore-messages.mjs"],
  ignorers: ["error-messages"],
  vitest: { configFile: "vitest.stryker.config.ts" },
  mutate: ["src/*.ts", "!src/index.ts"],
  coverageAnalysis: "perTest",
  reporters: ["clear-text", "progress", "json", "html"],
  jsonReporter: { fileName: "reports/mutation/mutation.json" },
  htmlReporter: { fileName: "reports/mutation/mutation.html" },
  thresholds: { high: 95, low: 90, break: 90 },
  timeoutMS: 60_000,
  timeoutFactor: 3,
  tempDirName: ".stryker-tmp",
  cleanTempDir: true,
};
