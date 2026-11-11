package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// adminEnv is a real SQLite repository, real password/TOTP/session services and a
// real administrative service. The only synthetic pieces are the clock, the
// origin, the password and the notification hook. The single administrator is
// the fixture account "u"; every admin call below uses a genuine AAL2 session.
type adminEnv struct {
	*sessionEnv
	a      *Admin
	secret []byte // admin AAL2 session secret
	sessID string
	totpID string
	totp   Enrollment

	mu       sync.Mutex
	notified int
	// hook runs inside the notification callback so tests can observe the
	// durable state at the moment of notification.
	hook func(context.Context) error
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	return newAdminEnvWith(t, DefaultAdminSettings())
}

func newAdminEnvWith(t *testing.T, settings AdminSettings) *adminEnv {
	t.Helper()
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	e.exec(`INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('adm','u','super_admin','active',1)`)
	ae := &adminEnv{sessionEnv: e, totpID: id, totp: en}
	a, err := NewAdmin(e.l, settings, ae.notify)
	if err != nil {
		t.Fatal(err)
	}
	ae.a = a
	issued := e.aal2TOTP(id, en)
	ae.secret, ae.sessID = issued.Secret(), issued.Info.ID
	return ae
}

func (e *adminEnv) notify(ctx context.Context) error {
	e.mu.Lock()
	e.notified++
	hook := e.hook
	e.mu.Unlock()
	if hook != nil {
		return hook(ctx)
	}
	return nil
}

func (e *adminEnv) notifications() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.notified
}

// refresh models a successful recent step-up of the existing session by moving
// its re-authentication and activity time to the fixture clock. Tests that prove
// the freshness rule itself never call it; they use real logins instead.
func (e *adminEnv) refresh() {
	e.t.Helper()
	now := e.clock.Now().Unix()
	e.exec(`UPDATE sessions SET reauthenticated_at=?,last_activity_at=? WHERE id=?`, now, now, e.sessID)
}

// advance moves the shared clock and keeps the admin session fresh.
func (e *adminEnv) advance(d time.Duration) {
	e.t.Helper()
	e.clock.Advance(d)
	e.refresh()
}

func (e *adminEnv) count(table string) int64 { return e.scalar(`SELECT count(*) FROM ` + table) }

// snapshot captures every identity/credential table so a denied call can be
// proven to have changed nothing.
func (e *adminEnv) snapshot() map[string]string {
	e.t.Helper()
	out := map[string]string{}
	for table, order := range map[string]string{
		"users": "id", "groups": "id", "agents": "id", "agent_credentials": "id",
		"user_group_memberships": "user_id,group_id", "agent_group_memberships": "agent_id,group_id",
		"administrative_roles": "id", "policies": "id",
	} {
		rows, err := e.db.Query(`SELECT * FROM ` + table + ` ORDER BY ` + order)
		if err != nil {
			e.t.Fatal(err)
		}
		cols, _ := rows.Columns()
		var buf bytes.Buffer
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				e.t.Fatal(err)
			}
			for _, v := range values {
				buf.WriteString(sqlText(v))
				buf.WriteByte('|')
			}
			buf.WriteByte('\n')
		}
		_ = rows.Close()
		out[table] = buf.String()
	}
	return out
}

func sqlText(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

func (e *adminEnv) mustNoChange(name string, before map[string]string) {
	e.t.Helper()
	after := e.snapshot()
	for table, rows := range before {
		if after[table] != rows {
			e.t.Fatalf("%s changed %s", name, table)
		}
	}
}

// verifyAgent runs the shared authorizer verifier over a presented bearer token
// at the fixture clock (the single acceptance rule every adapter reuses).
func (e *adminEnv) verifyAgent(token []byte) (authz.VerifiedPrincipal, error) {
	var vp authz.VerifiedPrincipal
	err := e.l.repo.Read(context.Background(), func(q *store.Queries) error {
		c, err := q.GetInstallationControl(context.Background())
		if err != nil {
			return err
		}
		vp, err = authz.NewStoreCredentialVerifier().VerifyPrincipal(context.Background(), q, c, authz.PrincipalCredentials{AgentToken: string(token)}, e.clock.Now())
		return err
	})
	return vp, err
}

func (e *adminEnv) accepted(token []byte) bool {
	e.t.Helper()
	_, err := e.verifyAgent(token)
	return err == nil
}

// person creates a human account through the service and returns its ID.
func (e *adminEnv) person(name string) string {
	e.t.Helper()
	u, err := e.a.CreateUser(e.t.Context(), e.secret, name)
	if err != nil {
		e.t.Fatal(err)
	}
	return u.ID
}

func (e *adminEnv) group(name string) string {
	e.t.Helper()
	g, err := e.a.CreateGroup(e.t.Context(), e.secret, name)
	if err != nil {
		e.t.Fatal(err)
	}
	return g.ID
}

func (e *adminEnv) agentOwnedBy(name, userID string) string {
	e.t.Helper()
	a, err := e.a.CreateAgent(e.t.Context(), e.secret, AgentRequest{Name: name, OwnerUserID: userID})
	if err != nil {
		e.t.Fatal(err)
	}
	return a.ID
}

func (e *adminEnv) issue(agentID string, req CredentialRequest) (IssuedCredential, []byte) {
	e.t.Helper()
	c, err := e.a.IssueCredential(e.t.Context(), e.secret, agentID, req)
	if err != nil {
		e.t.Fatal(err)
	}
	token := bytes.Clone(c.secret)
	return c, token
}

// rawStore returns the entire byte content of the database, WAL and shm files,
// for plaintext-exposure scans.
func (e *adminEnv) rawStore() []byte {
	e.t.Helper()
	var all []byte
	var path string
	if err := e.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		e.t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(path + suffix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			e.t.Fatal(err)
		}
		all = append(all, b...)
	}
	return all
}

func sha(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func (e *adminEnv) credentialRow(id string) (hash []byte, prefix, state string, gen int64) {
	e.t.Helper()
	if err := e.db.QueryRow(`SELECT token_hash,display_prefix,state,credential_generation FROM agent_credentials WHERE id=?`, id).Scan(&hash, &prefix, &state, &gen); err != nil {
		e.t.Fatal(err)
	}
	return
}

var _ = sql.ErrNoRows
