# P1.01 security-test substrate

- `surface_test.go`: static-only routes; API/MCP/raw-Docker paths and the
  setup/login API sub-paths are absent (404), rather than unauthenticated
  placeholder implementations. `/setup` and `/login` themselves left this list in
  P1.16.3: they are exact application-document routes serving the static shell
  (`web/assets_test.go` asserts the exact allowlist); their APIs are mounted, and
  tested, where they are composed (`internal/auth`, `cmd/mandatary`).
- `fixtures/`: deterministic concurrent-safe UTC clock; independently allocated
  active/expired/revoked/quarantined credential **metadata** and cross-endpoint /
  protected-target inputs. No tokens, real mail, database or socket.
- `MANDATARY_NEGATIVE_FIXTURE=exposed-route go test -race -count=1 ./...` must
  fail with `SECURITY_ROUTE_EXPOSURE`: it adds the public static index to the
  routes that must be absent. `make negative-control` verifies this exact
  assertion and fails if it is missing, unexpectedly passes, or fails to build.

These tests do not implement an authorizer, prove AAL2, or satisfy the future
SELF/RESTORE/SETUP/N63B4 registers. Their named owning P1 cards add those real
positive/negative service, persistence, interface, browser and isolated fixture
checks, which then accumulate in the existing CI suite. Never mark a planned
contract as passed because synthetic fixture construction passed.
