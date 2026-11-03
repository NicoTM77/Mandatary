#!/usr/bin/env bash
set -euo pipefail
export GOTOOLCHAIN=local
expected_go=${MANDATARY_GO_VERSION:-1.27.3}
case "$expected_go" in
  1.27.3|1.26.10) ;;
  *) printf 'UNAPPROVED_GO_VERSION: %s\n' "$expected_go" >&2; exit 1 ;;
esac
[[ $(go env GOVERSION) == "go$expected_go" ]] || { printf 'Go %s required\n' "$expected_go" >&2; exit 1; }
[[ $(node --version) == v24.22.1 ]] || { printf 'Node 24.22.1 required\n' >&2; exit 1; }
[[ $(npm --version) == 11.19.1 ]] || { printf 'npm 11.19.1 required\n' >&2; exit 1; }
go version
node --version
npm --version
