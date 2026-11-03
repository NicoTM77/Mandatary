SHELL := /bin/bash
export GOTOOLCHAIN := local
export GOFLAGS := -mod=readonly -p=1
export GOMAXPROCS := 2

.PHONY: versions install build test check security tools negative-control dev frontend-dev
versions:
	bash scripts/check-toolchains.sh

install: versions
	npm --prefix web ci
	npm --prefix web ls --all > /dev/null
	go mod download
	go mod verify

build: versions
	npm --prefix web run build
	CGO_ENABLED=0 go build -trimpath -o bin/mandatary ./cmd/mandatary

test: versions
	node --test scripts/*.test.mjs
	npm --prefix web test
	go test -race -count=1 ./...

check: build
	test -z "$$(gofmt -l cmd web/*.go tests/security)"
	go vet ./...
	npm --prefix web run typecheck
	npm --prefix web run lint
	$(MAKE) test

# Scanners have their own locked module; never dependencies of the app binary.
# Bound compiler parallelism for laptops/small runners. No global installation.
tools:
	go -C tools mod download
	go -C tools mod verify
	mkdir -p bin/tools
	GOMAXPROCS=2 go -C tools build -p=1 -trimpath -o ../bin/tools/govulncheck golang.org/x/vuln/cmd/govulncheck
	GOMAXPROCS=2 go -C tools build -p=1 -trimpath -o ../bin/tools/gosec github.com/securego/gosec/v2/cmd/gosec
	GOMAXPROCS=2 go -C tools build -p=1 -trimpath -o ../bin/tools/golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint

security:
	bin/tools/govulncheck ./...
	bin/tools/gosec ./...
	bin/tools/golangci-lint run ./...
	npm --prefix web audit --audit-level=high

negative-control:
	bash scripts/negative-control.sh

# The Go server is loopback-only and static-only; no socket/DB/mail access.
dev: build
	./bin/mandatary

frontend-dev: versions
	npm --prefix web run dev
