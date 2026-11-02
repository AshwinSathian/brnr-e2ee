#!/usr/bin/env bash
# Local equivalent of the CI security job.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
echo "== gitleaks";    gitleaks git --no-banner --redact .
echo "== zizmor";      uvx zizmor@1.31.1 --min-severity=low .github/workflows
echo "== semgrep";     uvx semgrep@1.182.0 scan --error --quiet --metrics=off --config p/typescript --config p/secrets src scripts
echo "== osv-scanner"; osv-scanner scan source --lockfile=package-lock.json --config=osv-scanner.toml
echo "security-check: ok"
