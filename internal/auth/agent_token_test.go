package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Independent decoder: the test never reuses the production encoder's loop.
func decodeAgentToken(t *testing.T, token []byte) []byte {
	t.Helper()
	if !bytes.HasPrefix(token, []byte("mdt_")) || len(token) != 47 {
		t.Fatalf("token shape %d bytes", len(token))
	}
	n := new(big.Int)
	for _, c := range token[4:] {
		d := strings.IndexByte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", c)
		if d < 0 {
			t.Fatalf("non-base62 digit %q", c)
		}
		n.Mul(n, big.NewInt(62))
		n.Add(n, big.NewInt(int64(d)))
	}
	return n.FillBytes(make([]byte, 32))
}

func TestAgentTokenCarries256RandomBitsInCanonicalBase62(t *testing.T) { // TD §3.2, N63B4-RANDOM-EVIDENCE
	t.Parallel() // each test owns its repository, clock and sessions
	// Known vectors pin the encoding at both ends of the 256-bit range.
	one := make([]byte, 32)
	one[31] = 1
	got, err := newAgentToken(bytes.NewReader(one))
	if err != nil || string(got) != "mdt_"+strings.Repeat("0", 42)+"1" {
		t.Fatalf("low vector %q %v", got, err)
	}
	max := bytes.Repeat([]byte{0xff}, 32)
	got, err = newAgentToken(bytes.NewReader(max))
	if err != nil || !bytes.Equal(decodeAgentToken(t, got), max) || !ValidAgentTokenFormat(string(got)) {
		t.Fatalf("2^256-1 does not round-trip: %q %v", got, err)
	}
	seen := map[string]bool{}
	for range 300 {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		token, err := newAgentToken(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decodeAgentToken(t, token), raw) {
			t.Fatal("token does not carry exactly the 256 drawn bits")
		}
		if !ValidAgentTokenFormat(string(token)) || seen[string(token)] {
			t.Fatal("malformed or repeated token")
		}
		seen[string(token)] = true
	}
	// Exactly 32 bytes are consumed per token: a longer source is not over-read.
	source := bytes.NewReader(bytes.Repeat([]byte{7}, 64))
	if _, err := newAgentToken(source); err != nil || source.Len() != 32 {
		t.Fatalf("consumed %d bytes", 64-source.Len())
	}
}

func TestAgentTokenRandomnessFailureNeverIssues(t *testing.T) { // RANDOM-EVIDENCE: no fallback generator
	t.Parallel() // each test owns its repository, clock and sessions
	for name, source := range map[string]*bytes.Reader{"empty": bytes.NewReader(nil), "short": bytes.NewReader(make([]byte, 31)), "all zero": bytes.NewReader(make([]byte, 32))} {
		if token, err := newAgentToken(source); err == nil || token != nil {
			t.Fatalf("%s source issued %q", name, token)
		}
	}
	if token, err := newAgentToken(erroringReader{}); err == nil || token != nil || strings.Contains(err.Error(), "boom") {
		t.Fatalf("failing source: %q %v", token, err)
	}
}

type erroringReader struct{}

func (erroringReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestValidAgentTokenFormat(t *testing.T) {
	t.Parallel() // each test owns its repository, clock and sessions
	good := "mdt_" + strings.Repeat("a", 43)
	if !ValidAgentTokenFormat(good) {
		t.Fatal("canonical token rejected")
	}
	for name, bad := range map[string]string{
		"empty":        "",
		"no prefix":    strings.Repeat("a", 47),
		"wrong prefix": "mdx_" + strings.Repeat("a", 43),
		"upper prefix": "MDT_" + strings.Repeat("a", 43),
		"short":        good[:46],
		"long":         good + "a",
		"punctuation":  "mdt_" + strings.Repeat("a", 42) + "-",
		"padding":      "mdt_" + strings.Repeat("a", 42) + "=",
		"space":        "mdt_" + strings.Repeat("a", 42) + " ",
		"newline":      "mdt_" + strings.Repeat("a", 42) + "\n",
		"unicode":      "mdt_" + strings.Repeat("a", 41) + "é",
		"nul":          "mdt_" + strings.Repeat("a", 42) + "\x00",
		"bearer":       "Bearer " + good,
	} {
		if ValidAgentTokenFormat(bad) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestIssuedCredentialRedactsEveryFormattingPath(t *testing.T) { // credential exposure
	t.Parallel() // each test owns its repository, clock and sessions
	secret := "mdt_" + strings.Repeat("Z", 43)
	c := IssuedCredential{Credential: CredentialView{ID: "cid"}, secret: []byte(secret)}
	for _, out := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("[%s]", c), fmt.Sprintf("%v", &c), fmt.Sprintf("%+v", &c), fmt.Sprintf("%#v", &c), fmt.Sprint(c), fmt.Sprintf("%q", c), fmt.Sprintf("%x", c)} {
		if strings.Contains(out, secret) || strings.Contains(out, "ZZZZ") {
			t.Fatalf("formatting leaked the token: %s", out)
		}
	}
	for _, v := range []any{c, &c, []IssuedCredential{c}, map[string]IssuedCredential{"k": c}, struct{ C IssuedCredential }{c}} {
		raw, err := json.Marshal(v)
		if err != nil || bytes.Contains(raw, []byte("ZZZZ")) {
			t.Fatalf("JSON leaked the token: %s %v", raw, err)
		}
	}
	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		for _, format := range []string{"json", "text"} {
			var out bytes.Buffer
			opts := &slog.HandlerOptions{Level: slog.LevelDebug}
			var h slog.Handler = slog.NewJSONHandler(&out, opts)
			if format == "text" {
				h = slog.NewTextHandler(&out, opts)
			}
			slog.New(h).Log(t.Context(), level, "issued", "credential", c, "pointer", &c, slog.Any("any", c))
			if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "ZZZZ") {
				t.Fatalf("%s %s log leaked the token: %s", format, level, out.String())
			}
		}
	}
	// The secret leaves exactly once.
	first := c.ExportOnce()
	if string(first) != secret {
		t.Fatal("first export lost the token")
	}
	if again := c.ExportOnce(); len(again) != 0 {
		t.Fatal("token exported twice")
	}
	if c.secret != nil {
		t.Fatal("secret retained after export")
	}
}

// credentialStatus must mirror the verifier on every state. Both are driven over
// one matrix of stored rows at boundary times: any disagreement would let the
// at-most-two-live-credentials rule count a credential the verifier rejects (or
// the reverse).
func TestCredentialStatusMatchesTheSharedVerifierOverTheStateMatrix(t *testing.T) { // C2 parity
	t.Parallel() // each test owns its repository, clock and sessions
	const issued = int64(2000000000)
	type row struct {
		name   string
		mutate string
		want   CredentialStatus
		at     int64
	}
	rows := []row{
		{"active", ``, CredentialActive, issued + 10},
		{"issue instant", ``, CredentialActive, issued},
		{"before issue", ``, CredentialStale, issued - 1},
		{"last second", ``, CredentialActive, issued + 999},
		{"expiry boundary", ``, CredentialExpired, issued + 1000},
		{"long after expiry", ``, CredentialExpired, issued + 5000},
		{"overlap running", `UPDATE agent_credentials SET rotation_overlap_until=2000000500`, CredentialOverlapping, issued + 499},
		{"overlap boundary", `UPDATE agent_credentials SET rotation_overlap_until=2000000500`, CredentialRotatedOut, issued + 500},
		{"overlap after expiry boundary", `UPDATE agent_credentials SET rotation_overlap_until=2000002000`, CredentialExpired, issued + 1000},
		{"revoked", `UPDATE agent_credentials SET state='revoked',revoked_at=2000000100`, CredentialRevoked, issued + 200},
		{"row ahead of control generation", `UPDATE agent_credentials SET credential_generation=2`, CredentialStale, issued + 200},
		{"control generation advanced", `UPDATE installation_control SET credential_generation=2`, CredentialStale, issued + 200},
		{"non expiring", `PERPETUAL`, CredentialActive, issued + 100000},
		{"non expiring overlap boundary", `PERPETUAL;UPDATE agent_credentials SET rotation_overlap_until=2000000500`, CredentialRotatedOut, issued + 500},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e := newAdminEnv(t)
			perpetual := strings.HasPrefix(r.mutate, "PERPETUAL")
			token := insertCredentialRow(t, e, issued, perpetual)
			if mutation := strings.TrimPrefix(strings.TrimPrefix(r.mutate, "PERPETUAL"), ";"); mutation != "" {
				e.exec(mutation)
			}
			var control store.InstallationControl
			var row store.AgentCredential
			err := e.l.repo.Read(t.Context(), func(q *store.Queries) error {
				var err error
				if control, err = q.GetInstallationControl(t.Context()); err != nil {
					return err
				}
				row, err = q.GetMachineRecord(t.Context(), "cred-fixture")
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			got := credentialStatus(control, row, r.at)
			if got != r.want {
				t.Fatalf("status %s, want %s", got, r.want)
			}
			// The verifier clock is the same instant.
			e.clock.Advance(time.Unix(r.at, 0).Sub(e.clock.Now()))
			if e.accepted(token) != got.Live() {
				t.Fatalf("verifier acceptance %v disagrees with status %s", e.accepted(token), got)
			}
		})
	}
}

// insertCredentialRow stores a credential through plain SQL (fixture only) with
// a known token, so the status/verifier parity table can mutate it.
func insertCredentialRow(t *testing.T, e *adminEnv, issued int64, perpetual bool) []byte {
	t.Helper()
	e.exec(`INSERT INTO agents(id,name,owner_user_id,state,credential_generation,authority_generation) VALUES ('agent-fixture','fixture-agent','u','active',1,1)`)
	token, err := newAgentToken(bytes.NewReader(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if perpetual {
		e.exec(`INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,nonexpiring_approved,credential_generation,state) VALUES ('cred-fixture','agent-fixture',?,'mdt_fixt',?,1,1,'active')`, sha(token), issued)
		return token
	}
	e.exec(`INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,credential_generation,state) VALUES ('cred-fixture','agent-fixture',?,'mdt_fixt',?,?,1,'active')`, sha(token), issued, issued+1000)
	return token
}
