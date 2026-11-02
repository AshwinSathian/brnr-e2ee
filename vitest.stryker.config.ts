// Vitest settings for Stryker only.
//
// Compatibility shim: @stryker-mutator/vitest-runner 10.0.0 filters a mutant's tests with a name pattern
// that joins describe and test names with " ", but vitest 5 matches full names joined with " > ".
// Without the shim every filtered test is skipped and mutants falsely survive. The shim lets each space
// in Stryker's pattern also match " > ", which can only select more tests, never fewer.
//
// Second shim: a mutant that breaks module loading makes test collection fail. Vitest 5 records that on
// the test module, not in the global error set Stryker reads, so Stryker saw "0 tests, no failure" and
// reported the mutant as Survived. The reporter below copies collection errors into that error set,
// so Stryker reports such mutants as runtime errors instead.
import { defineConfig } from "vitest/config";
import type { TestModule, Vitest } from "vitest/node";

let vitestRef: Vitest | undefined;
const collectionErrors = {
  onInit(v: Vitest) {
    vitestRef = v;
  },
  onTestModuleEnd(m: TestModule) {
    for (const e of m.errors())
      vitestRef?.state.catchError(e, "Collection Error");
  },
};

const widen = (v: unknown): unknown =>
  v instanceof RegExp
    ? new RegExp(v.source.replace(/ /g, "(?: | > )"), v.flags)
    : v;

export default defineConfig({
  plugins: [
    {
      name: "stryker-vitest5-test-names",
      configureVitest({ project }) {
        const cfg = project.config as { testNamePattern?: unknown };
        let pattern = widen(cfg.testNamePattern);
        Object.defineProperty(cfg, "testNamePattern", {
          configurable: true,
          enumerable: true,
          get: () => pattern,
          set: (v: unknown) => {
            pattern = widen(v);
          },
        });
      },
    },
  ],
  test: {
    reporters: ["default", collectionErrors],
    include: ["test/**/*.test.ts"],
    environment: "node",
    testTimeout: 120_000,
  },
});
