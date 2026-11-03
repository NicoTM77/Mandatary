#!/usr/bin/env bash
set -euo pipefail
# Prove the exact ordinary race gate fails on a deliberately incorrect security
# expectation. Compilation/tool failures do not qualify as assertion evidence.
log=$(mktemp "${TMPDIR:-/tmp}/mandatary-negative.XXXXXX")
trap 'rm -f "$log"' EXIT
set +e
MANDATARY_NEGATIVE_FIXTURE=exposed-route go test -race -count=1 ./... > "$log" 2>&1
status=$?
set -e
cat "$log"
[[ $status == 1 ]] || { printf 'Negative control must fail with exit 1, got %s\n' "$status" >&2; exit 1; }
grep -q 'SECURITY_ROUTE_EXPOSURE: unavailable route returned 200' "$log"
grep -q '^FAIL[[:space:]]*github.com/NicoTM77/Mandatary/tests/security' "$log"
if grep -Eq 'build failed|setup failed|DATA RACE' "$log"; then
  printf 'Negative control failed for an unrelated reason\n' >&2
  exit 1
fi
printf 'Negative control observed: ordinary race gate rejected exposed-route fixture (exit 1).\n'
