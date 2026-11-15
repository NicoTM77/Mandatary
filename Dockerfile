# Mandatary production image (P1.19).
#
# One static Go binary with the compiled admin SPA embedded, on the approved distroless static
# non-root runtime (technical-decisions.md §5, support-and-deployment-matrix.md §5): no shell, no package
# manager, no second service. Every base image is pinned by the multi-architecture index digest reviewed
# for this change; a tag alone is never trusted. Build (on a Docker host you may build on):
#
#   docker build --build-arg VCS_REF="$(git rev-parse HEAD)" -t mandatary:local .
#
# Both CPU targets cross-compile natively on the build platform (no emulation):
#
#   docker build --platform linux/arm64 --build-arg VCS_REF="$(git rev-parse HEAD)" -t mandatary:local-arm64 .
#
# The host-local setup/recovery helper (security-contracts.md §S3.1b) is the SAME binary. Extract the
# byte-identical file the image runs, without starting a container:
#
#   docker build --target host-binary --build-arg VCS_REF="$(git rev-parse HEAD)" \
#     --output type=local,dest=./out .
#
# VCS_REF is mandatory and must be the exact source commit (40 lowercase hex): it is stamped into the
# binary so a helper built from another revision refuses to reveal a token (a container build has no
# .git, so Go cannot record the revision itself).

ARG NODE_IMAGE=docker.io/library/node:24.22.1-trixie-slim@sha256:89c5244bc22a9bc3287d89ebc7e49b9cb5bb84cd40e6175ac3421d5a9f68b95a
ARG GO_IMAGE=docker.io/library/golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

# ---- frontend: locked install (npm ci), strict typecheck, production bundle -------------------------
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
ENV npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
WORKDIR /src
# The lockfile layer is cached until a dependency changes. The postinstall hook lives in scripts/.
COPY scripts/isolate-node-modules.mjs scripts/isolate-node-modules.mjs
COPY web/package.json web/package-lock.json web/.npmrc web/
RUN cd web && test "$(npm --version)" = "11.19.1" && npm ci
COPY web/ web/
RUN cd web && npm run build

# ---- backend: static binary, embedded assets --------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VCS_REF
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
WORKDIR /src
RUN test "$(go env GOVERSION)" = "go1.27.4" \
 && printf '%s' "${VCS_REF}" | grep -Eq '^[0-9a-f]{40}$' \
 || { echo "build requires Go 1.27.4 and --build-arg VCS_REF=<exact 40-hex commit>" >&2; exit 1; }
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd/ cmd/
COPY internal/ internal/
COPY web/assets.go web/assets.go
COPY --from=web /src/web/dist/ web/dist/
RUN go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.stampedRevision=${VCS_REF}" \
      -o /out/mandatary ./cmd/mandatary \
 && mkdir -m 0700 /out/data

# ---- host-local helper artifact: the exact binary the image runs -----------------------------------
FROM scratch AS host-binary
COPY --from=build /out/mandatary /mandatary

# ---- runtime ----------------------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime
ARG VCS_REF
# io.mandatary.self=true is the membership label of security-contracts.md §S1.1: every container created
# from this image is a protected Mandatary peer, whatever its name. The per-deployment instance binding
# label (io.mandatary.self.instance-uuid) is set by the deployment, never baked into an image.
LABEL org.opencontainers.image.title="Mandatary" \
      org.opencontainers.image.description="Security-first Docker access intermediary (in development; see README)" \
      org.opencontainers.image.source="https://github.com/NicoTM77/Mandatary" \
      org.opencontainers.image.revision="${VCS_REF}" \
      io.mandatary.self="true"
# 65532:65532 is this base image's `nonroot` identity. The data directory is created with that owner so a
# NAMED volume starts correctly owned; a host bind mount must be prepared by the operator
# (docs/deployment.md). Nothing else in the image is writable by the service user.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build /out/mandatary /mandatary
# The listener address is set here (the binary itself defaults to loopback). TLS is terminated by the
# reverse proxy in front of this port; see docs/deployment.md. No Docker socket is configured by default:
# the deployment names it (MANDATARY_DOCKER_SOCKET) or no Docker surface exists.
ENV MANDATARY_ADMIN_LISTEN_ADDR=:8080 \
    MANDATARY_DATA_DIR=/data \
    MANDATARY_LOG_FORMAT=json
USER 65532:65532
EXPOSE 8080
# Liveness only (the process answers). Readiness - the Docker self-protection proof - is
# `/mandatary healthcheck --ready`, deliberately not the container health so a fresh installation
# awaiting setup, or a deployment whose Docker access is intentionally withheld, stays reachable.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["/mandatary", "healthcheck"]
ENTRYPOINT ["/mandatary"]
