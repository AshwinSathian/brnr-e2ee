# Contributing

Thanks for taking a look. Bug reports, questions about the spec, test vectors from other implementations and pull requests are all welcome.

For anything security-related, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Before you start

[SPEC.md](SPEC.md) is normative. The code implements the spec, not the other way round, so a change to protocol behaviour starts as a change to SPEC.md. If you want to propose one, open an issue first and say what problem it solves. Anything that changes bytes on the wire needs a new suite id ([SPEC §18](SPEC.md#18-versioning)), which is a big change for every app that uses the library.

Bug fixes, tests, docs and tooling don't need an issue first.

## Setup

You'll need Node 24 (the exact version is in [`.nvmrc`](.nvmrc)).

```sh
git clone https://github.com/AshwinSathian/brnr-e2ee.git
cd brnr-e2ee
npm ci --ignore-scripts
npm run verify
```

`npm run verify` is what CI runs: typecheck, lint, formatting, the dependency allowlist, the tests, the build, the vector check and the reference-implementation check. It should pass before you push.

Other scripts:

| Script                   | What it does                                                                                   |
| ------------------------ | ---------------------------------------------------------------------------------------------- |
| `npm test`               | The test suite (Vitest)                                                                        |
| `npm run test:release`   | The property and fuzz tests with 10,000 cases each                                             |
| `npm run mutation`       | Stryker; fails below 90% overall or 85% for any file. Slow                                     |
| `npm run vectors:gen`    | Regenerates `vectors/*.json`. Only for a deliberate change, and the reference must still agree |
| `npm run docs`           | Builds the API reference into `docs-site/`                                                     |
| `npm run check:security` | gitleaks, zizmor, semgrep and OSV-Scanner, as in CI (needs `gitleaks`, `uv` and `osv-scanner`) |

To run every check before each push, turn on the hook: `git config core.hooksPath .githooks`.

## Pull requests

- Keep each PR to one change, with a test that fails without it.
- Don't add a runtime dependency. The four that exist are an allowlist enforced by `scripts/check-deps.mjs`.
- If you change a vector, regenerate it with `npm run vectors:gen` and say why in the PR. Vectors are a contract with other implementations.
- If you change behaviour that SPEC.md describes, change SPEC.md and, where it applies, `scripts/ref/` in the same PR.
- Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`fix(ratchet): …`, `docs: …`).

## Releases

The maintainer bumps `package.json`, moves the `Unreleased` notes under the new version in CHANGELOG.md, and pushes a `vX.Y.Z` tag from `main`. [`release.yml`](.github/workflows/release.yml) runs CI again, publishes to npm with provenance, creates the GitHub release and updates the API docs.

## Code of conduct

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
