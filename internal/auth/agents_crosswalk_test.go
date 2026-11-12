package auth

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// docs/agent-credentials.md is only evidence if every test it cites exists and no
// P1.10 test escapes it. A renamed or deleted test fails here instead of leaving an
// acceptance claim that points at nothing.
func TestAgentCredentialCrosswalkNamesResolve(t *testing.T) {
	t.Parallel() // each test owns its repository, clock and sessions
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "agent-credentials.md"))
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	declared := map[string]bool{}
	own := map[string]bool{} // tests introduced by this card
	for _, dir := range []string{".", filepath.Join("..", "store"), filepath.Join("..", "domain"), filepath.Join("..", "..", "tests", "security")} {
		files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			base := filepath.Base(f)
			isOwn := strings.HasPrefix(base, "agent_token_") || strings.HasPrefix(base, "agents_") || base == "agent_credential_schema_test.go" || base == "uuid_test.go"
			for _, m := range decl.FindAllSubmatch(b, -1) {
				declared[string(m[1])] = true
				if isOwn {
					own[string(m[1])] = true
				}
			}
		}
	}
	cited := map[string]bool{}
	for _, m := range regexp.MustCompile("`(Test[A-Z][A-Za-z0-9_]+)`").FindAllStringSubmatch(string(doc), -1) {
		cited[m[1]] = true
	}
	if len(cited) < 40 || len(own) < 40 {
		t.Fatalf("crosswalk cites %d tests, %d declared by the card", len(cited), len(own))
	}
	for name := range cited {
		if !declared[name] {
			t.Errorf("docs/agent-credentials.md cites %s, which is not a declared test", name)
		}
	}
	for name := range own {
		if !cited[name] {
			t.Errorf("%s is not cited in docs/agent-credentials.md", name)
		}
	}
}

func TestNonExpiringTokensDieWithTheCredentialGenerationAndRevocation(t *testing.T) { // RESTORE-01: "including non-expiring tokens"
	t.Parallel() // each test owns its repository, clock and sessions
	settings := AdminSettings{DefaultTTL: time.Hour, MaxTTL: time.Hour, DefaultOverlap: time.Minute, MaxOverlap: time.Hour, AllowNonExpiring: true}
	for name, retire := range map[string]func(e *adminEnv, agent, credential string){
		"revocation":            func(e *adminEnv, agent, c string) { _ = e.a.RevokeCredential(e.t.Context(), e.secret, agent, c) },
		"credential generation": func(e *adminEnv, _, _ string) { e.exec(`UPDATE installation_control SET credential_generation=2`) },
		"restore quarantine":    func(e *adminEnv, _, _ string) { e.exec(`UPDATE installation_control SET restore_quarantined=1`) },
		"agent disabled":        func(e *adminEnv, agent, _ string) { _ = e.a.DisableAgent(e.t.Context(), e.secret, agent) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newAdminEnvWith(t, settings)
			agent := e.agentOwnedBy("svc", e.person("owner"))
			c, token := e.issue(agent, CredentialRequest{NonExpiring: true})
			e.advance(10 * time.Hour)
			if !e.accepted(token) {
				t.Fatal("an approved non-expiring token must outlive any TTL")
			}
			retire(e, agent, c.Credential.ID)
			if e.accepted(token) {
				t.Fatalf("non-expiring token still accepted after %s", name)
			}
		})
	}
}

func TestAgentTokensNeverAuthenticateTheSetupSurface(t *testing.T) { // N63B4-SCOPE-MACHINE: no bearer reaches bootstrap/recovery routes
	t.Parallel() // each test owns its repository, clock and sessions
	e := newSetupEnv(t)
	e.ensure()
	_ = e.reveal(PurposeInitialSetup, "") // a retrieved generation: the surface exists, so only authentication can refuse
	token := "mdt_" + strings.Repeat("a", 43)
	cookie := SetupCookieName + "=" + base64.RawURLEncoding.EncodeToString([]byte(token)[:32])
	for _, route := range []string{"account", "addresses/proof", "addresses/confirm", "totp", "totp/confirm", "complete"} {
		for name, c := range map[string]setupCall{
			"bearer header":   {extra: map[string]string{"Authorization": "Bearer " + token}},
			"token as cookie": {cookie: cookie},
			"both":            {cookie: cookie, extra: map[string]string{"Authorization": "Bearer " + token}},
		} {
			c.method, c.path, c.body = http.MethodPost, SetupPathPrefix+route, "{}"
			if w := e.call(c); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
				t.Errorf("%s with %s: %d", route, name, w.Code)
			}
		}
	}
}
