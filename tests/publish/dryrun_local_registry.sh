#!/usr/bin/env bash
# DRY RUN of scripts/publish_dev_image.py against a THROWAWAY LOCAL registry (127.0.0.1) on an isolated, disposable Docker host (the P1.20 test VM). Never ghcr.io, no credential.
# Task-scoped names only; cleans up what it created (container, volume, images). usage: PUBLISH_SCRIPT=/path/scripts/publish_dev_image.py bash dryrun_local_registry.sh NEW_WORKDIR
set -uo pipefail
umask 022
D="$1"
cd "$D"
REG_NAME="p120-pubdry-registry"
PORT=5055
REPO="localhost:${PORT}/mandatary"
SCRIPT="${PUBLISH_SCRIPT:-$D/scripts/publish_dev_image.py}"
cleanup() {
  docker rm -fv "$REG_NAME" >/dev/null 2>&1 || true
  docker image rm -f mandatary-ci:amd64 mandatary-ci:arm64 >/dev/null 2>&1 || true
  for t in $(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep "^localhost:${PORT}/mandatary:" || true); do docker image rm -f "$t" >/dev/null 2>&1 || true; done
  echo "cleanup done"
}
trap cleanup EXIT

echo "== environment"; docker version --format 'server={{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'; docker buildx version
docker info --format 'storage-driver={{.Driver}} driver-status={{.DriverStatus}}' | head -2

echo "== git history with two commits"
rm -rf repo 2>/dev/null; mkdir repo; cd repo
git init -q . && git config user.email t@example.test && git config user.name t
echo a > f && git add f && git commit -q -m A && A=$(git rev-parse HEAD)
echo b > f && git commit -q -am B && B=$(git rev-parse HEAD)
echo "A=$A B=$B"
cd "$D"

mkdir -p ctx
echo marker > ctx/marker
cat > ctx/Dockerfile <<'EOF'
FROM scratch
ARG VCS_REF
LABEL org.opencontainers.image.source="https://github.com/NicoTM77/Mandatary" org.opencontainers.image.revision="${VCS_REF}"
COPY marker /marker
EOF

build_and_record() { # $1 sha $2 outdir
  for arch in amd64 arm64; do
    docker buildx build --platform linux/$arch --build-arg VCS_REF="$1" --load -t mandatary-ci:$arch ctx >build-$arch.log 2>&1 || { echo "BUILD FAILED $arch"; tail -5 build-$arch.log; return 1; }
    GITHUB_SHA="$1" python3 "$SCRIPT" record --image mandatary-ci:$arch --arch $arch --out "$2/tested-image-$arch" || return 1
  done
}

echo "== registry"
docker run -d --name "$REG_NAME" -p 127.0.0.1:${PORT}:5000 registry:2 >/dev/null
for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:${PORT}/v2/" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "http://127.0.0.1:${PORT}/v2/" && echo " registry up"

NEEDS='{"baseline":{"result":"success"},"negative-control":{"result":"success"},"storage-arm64":{"result":"success"},"image":{"result":"success"},"security":{"result":"success"}}'
pub() { # $1 sha $2 tested dir
  (cd repo && GITHUB_SHA="$1" NEEDS_RESULTS="$NEEDS" python3 "$SCRIPT" publish --tested "$2" --fixture-registry "$REPO"); echo "exit=$?"
}

echo "== record + publish A (first publication)"
build_and_record "$A" "$D/tested-A" || exit 1
pub "$A" "$D/tested-A"
echo "-- raw staged amd64 object"; docker buildx imagetools inspect --raw "$REPO:build-$A-amd64"; echo
echo "-- raw dev index"
docker buildx imagetools inspect --raw "$REPO:dev" > dev-after-A.json; cat dev-after-A.json; echo
echo "-- pretty"; docker buildx imagetools inspect "$REPO:dev"

echo "== publish A again (repeat run: expect SKIPPED, nothing written)"
pub "$A" "$D/tested-A"

echo "== record + publish B (newer commit: expect published, A is an ancestor)"
build_and_record "$B" "$D/tested-B" || exit 1
pub "$B" "$D/tested-B"
docker buildx imagetools inspect --raw "$REPO:dev" > dev-after-B.json; cat dev-after-B.json; echo

echo "== publish A again after B (stale run: expect SKIPPED, dev stays at B)"
pub "$A" "$D/tested-A"
docker buildx imagetools inspect --raw "$REPO:dev" > dev-after-stale.json
cmp dev-after-B.json dev-after-stale.json && echo "dev unchanged by the stale run: identical bytes"

echo "== verdict checks (python)"
python3 - "$A" "$B" <<'EOF'
import json, sys
A, B = sys.argv[1:3]
for name, rev in (("dev-after-A.json", A), ("dev-after-B.json", B)):
    d = json.load(open(name))
    plats = sorted((m["platform"]["os"], m["platform"]["architecture"]) for m in d["manifests"])
    ann = d.get("annotations", {})
    print(name, "mediaType=%s" % d["mediaType"], "platforms=%s" % plats, "revision=%s" % ann.get("org.opencontainers.image.revision"), "source=%s" % ann.get("org.opencontainers.image.source"))
    assert plats == [("linux", "amd64"), ("linux", "arm64")], plats
    assert ann.get("org.opencontainers.image.revision") == rev
print("OK: exactly linux/amd64 + linux/arm64, revision annotation as expected")
EOF
echo "== tags in the throwaway registry"
curl -fsS "http://127.0.0.1:${PORT}/v2/mandatary/tags/list"; echo
