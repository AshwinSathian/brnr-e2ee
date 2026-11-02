import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/",
      "coverage/",
      "reports/",
      ".stryker-tmp/",
      "docs-site/",
      ".claude/",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["tweetnacl", "tweetnacl-*"],
              message: "tweetnacl is banned (D6). Use src/primitives.ts.",
            },
            {
              group: ["@noble/*"],
              message: "Only src/primitives.ts may import @noble/* (D6).",
            },
          ],
        },
      ],
      "no-console": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { varsIgnorePattern: "^_", argsIgnorePattern: "^_" },
      ],
    },
  },
  {
    files: ["src/primitives.ts", "test/**/*.ts", "scripts/**/*"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["tweetnacl", "tweetnacl-*"],
              message: "tweetnacl is banned (D6).",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["test/**/*.ts", "scripts/**/*"],
    rules: { "@typescript-eslint/no-non-null-assertion": "off" },
  },
  {
    files: ["scripts/**/*"],
    languageOptions: {
      globals: {
        console: "readonly",
        process: "readonly",
        Buffer: "readonly",
        URL: "readonly",
        structuredClone: "readonly",
      },
    },
    rules: { "no-console": "off" },
  },
);
