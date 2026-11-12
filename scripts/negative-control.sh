#!/usr/bin/env bash
set -euo pipefail
# Prove the exact ordinary race gate fails on a deliberately incorrect security
# expectation, and fails ONLY for that reason. The gate is the unchanged ordinary
# full race suite (`go test -race -timeout=20m -count=1 ./...`) with the structured
# `-json` event stream added; scripts/negative-control-verify.mjs accepts the run
# only when the intended exposed-route assertion is the sole failed test and the
# sole failed package, and rejects any unrelated test/package failure (also inside
# the security package), build/setup failure, race report, panic/timeout/abnormal
# termination, clean run or exit status other than 1 (P1.13 owner observation O1).
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/mandatary-negative.XXXXXX")
events=$work/events.jsonl
errors=$work/stderr.log
trap 'rm -f "$events" "$errors"; rmdir "$work"' EXIT
set +e
MANDATARY_NEGATIVE_FIXTURE=exposed-route go test -race -timeout=20m -count=1 -json ./... > "$events" 2> "$errors"
status=$?
set -e
if [[ -s "$errors" ]]; then
  printf '%s\n' '--- go test stderr ---'
  cat "$errors"
fi
node "$here/negative-control-verify.mjs" "$events" "$errors" "$status"
