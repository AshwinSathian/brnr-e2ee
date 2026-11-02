import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/testing.ts"],
  format: ["esm", "cjs"],
  // tsup injects baseUrl into the dts build, which TypeScript 6 deprecates.
  dts: { compilerOptions: { ignoreDeprecations: "6.0" } },
  sourcemap: false,
  clean: true,
  target: "es2022",
  treeshake: true,
  // Runtime deps stay external so consumers' lockfiles pin and audit them.
  external: [/^@noble\//, "zod"],
});
