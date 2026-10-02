#!/usr/bin/env bash
# Interview demo: a developer "simplifies" a route and drops the ownership
# check. Two independent controls catch it before merge:
#   1. the custom Semgrep rule (static, runs on the PR diff in ~seconds)
#   2. the cross-tenant authorization test (dynamic, runs in the unit suite)
set -u
cd "$(dirname "$0")/.."
git apply demo/introduce-idor.patch 2>/dev/null || patch -p1 < demo/introduce-idor.patch
trap 'git apply -R demo/introduce-idor.patch 2>/dev/null || patch -R -p1 < demo/introduce-idor.patch; echo; echo "[demo] patch reverted"' EXIT

echo "== 1. Semgrep (custom rule) =="
semgrep scan --metrics=off --config .semgrep/offerline.yml app/ --error && echo "NOT CAUGHT" || echo "[demo] Semgrep blocked the change"
echo
echo "== 2. Authorization tests =="
python3 -m pytest -q tests/test_authz.py && echo "NOT CAUGHT" || echo "[demo] cross-tenant test failed, as it should"
