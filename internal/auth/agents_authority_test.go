package auth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// Privilege-escalation tests: who may administer, and with what authentication
// evidence. The authorization decision is made INSIDE the service, from persisted
// state and the server clock, never from the caller's description of itself.

// adminCalls lists every public mutation and read, so one matrix drives them all.
func (e *adminEnv) adminCalls(secret []byte, agent string) (mutations, reads map[string]func() error) {
	ctx := e.t.Context()
	mutations = map[string]func() error{
		"create user":  func() error { _, err := e.a.CreateUser(ctx, secret, "probe-user"); return err },
		"create group": func() error { _, err := e.a.CreateGroup(ctx, secret, "probe-group"); return err },
		"create agent": func() error {
			_, err := e.a.CreateAgent(ctx, secret, AgentRequest{Name: "probe-agent", OwnerUserID: "u"})
			return err
		},
		"add member":    func() error { return e.a.AddMember(ctx, secret, "grp", MemberAgent, agent) },
		"remove member": func() error { return e.a.RemoveMember(ctx, secret, "grp", MemberAgent, agent) },
		"issue": func() error {
			c, err := e.a.IssueCredential(ctx, secret, agent, CredentialRequest{})
			_ = c.ExportOnce()
			return err
		},
		"rotate": func() error {
			r, err := e.a.RotateCredential(ctx, secret, agent, RotateRequest{})
			_ = r.New.ExportOnce()
			return err
		},
		"revoke":  func() error { return e.a.RevokeCredential(ctx, secret, agent, "any") },
		"disable": func() error { return e.a.DisableAgent(ctx, secret, agent) },
	}
	reads = map[string]func() error{
		"list agents": func() error { _, err := e.a.ListAgents(ctx, secret); return err },
		"list groups": func() error { _, err := e.a.ListGroups(ctx, secret); return err },
		"list users":  func() error { _, err := e.a.ListUsers(ctx, secret); return err },
	}
	return mutations, reads
}

// insertSession stores a session row for the fixture user through plain SQL.
func (e *adminEnv) insertSession(id string, secret []byte, assurance, methods int64, bound ...string) {
	e.t.Helper()
	now := e.clock.Now().Unix()
	sum := sha256.Sum256(secret)
	e.exec(`INSERT INTO sessions(id,user_id,secret_hash,purpose,achieved_assurance,methods,authenticated_at,created_at,expires_at,last_activity_at,credential_generation,session_generation,state) VALUES(?,'u',?,'normal',?,?,?,?,?,?,1,1,'active')`,
		id, sum[:], assurance, methods, now, now, now+3600, now)
	for _, a := range bound {
		e.exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES(?,?,'u')`, id, a)
	}
}

func TestOnlyTheSingleActiveAdministratorMayAdminister(t *testing.T) { // acceptance: privilege escalation
	deny := func(t *testing.T, e *adminEnv, secret []byte, agent string) {
		t.Helper()
		before := e.snapshot()
		notified := e.notifications()
		mutations, reads := e.adminCalls(secret, agent)
		for name, call := range mutations {
			if err := call(); !errors.Is(err, ErrDenied) {
				t.Errorf("%s: want ErrDenied, got %v", name, err)
			}
		}
		for name, call := range reads {
			if err := call(); !errors.Is(err, ErrDenied) {
				t.Errorf("%s: want ErrDenied, got %v", name, err)
			}
		}
		e.mustNoChange("denied administration", before)
		if e.notifications() != notified {
			t.Error("a denied call notified a policy change")
		}
	}
	cases := map[string]func(*adminEnv) []byte{
		// The caller is a fully authenticated AAL2 human, but not the administrator.
		"ordinary user with AAL2": func(e *adminEnv) []byte {
			e.exec(`UPDATE administrative_roles SET state='disabled' WHERE id='adm'`)
			return e.secret
		},
		"quarantined administrative role": func(e *adminEnv) []byte {
			e.exec(`UPDATE administrative_roles SET state='quarantined',authority_generation=0 WHERE id='adm'`)
			return e.secret
		},
		"administrative role from an older authority generation": func(e *adminEnv) []byte {
			e.exec(`UPDATE administrative_roles SET authority_generation=2 WHERE id='adm'`)
			return e.secret
		},
		"role removed": func(e *adminEnv) []byte {
			e.exec(`DELETE FROM administrative_roles`)
			return e.secret
		},
		"endpoint administrator only": func(e *adminEnv) []byte {
			e.exec(`DELETE FROM administrative_roles`)
			e.exec(`INSERT INTO administrative_roles(id,user_id,role,endpoint_id) SELECT 'ep','u','endpoint_admin',id FROM endpoints`)
			return e.secret
		},
		"password-only session": func(e *adminEnv) []byte {
			secret := bytes.Repeat([]byte("p"), 40)
			e.insertSession("aal1", secret, 1, 1, "pwd")
			return secret
		},
		"revoked session": func(e *adminEnv) []byte {
			e.exec(`UPDATE sessions SET state='revoked',revoked_at=created_at WHERE id=?`, e.sessID)
			return e.secret
		},
		"session generation advanced": func(e *adminEnv) []byte {
			e.exec(`UPDATE installation_control SET session_generation=2`)
			return e.secret
		},
		"compromised account": func(e *adminEnv) []byte {
			e.exec(`UPDATE users SET compromised=1`)
			return e.secret
		},
		"disabled account": func(e *adminEnv) []byte {
			e.exec(`UPDATE users SET state='disabled'`)
			return e.secret
		},
		"absolute session expiry": func(e *adminEnv) []byte {
			e.clock.Advance(12*time.Hour + time.Second)
			return e.secret
		},
		"idle session expiry": func(e *adminEnv) []byte {
			e.clock.Advance(30 * time.Minute)
			return e.secret
		},
		"nil secret":             func(*adminEnv) []byte { return nil },
		"empty secret":           func(*adminEnv) []byte { return []byte{} },
		"short secret":           func(*adminEnv) []byte { return []byte("short") },
		"unknown secret":         func(*adminEnv) []byte { return bytes.Repeat([]byte("z"), 32) },
		"oversized secret":       func(*adminEnv) []byte { return bytes.Repeat([]byte("z"), 4096) },
		"truncated real secret":  func(e *adminEnv) []byte { return e.secret[:len(e.secret)-1] },
		"extended real secret":   func(e *adminEnv) []byte { return append(bytes.Clone(e.secret), 0) },
		"agent token as session": func(*adminEnv) []byte { return []byte("mdt_" + string(bytes.Repeat([]byte("a"), 43))) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e := newAdminEnv(t)
			agent := e.agentOwnedBy("bot", e.person("owner"))
			e.group("grp")
			secret := setup(e)
			deny(t, e, secret, agent)
		})
	}
	t.Run("password preauth capability", func(t *testing.T) {
		e := newAdminEnv(t)
		agent := e.agentOwnedBy("bot", e.person("owner"))
		e.group("grp")
		r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
		if err != nil {
			t.Fatal(err)
		}
		deny(t, e, r.Session.Secret(), agent)
	})
}

func TestMutationsNeedFreshAAL2EvidenceButReadsDoNot(t *testing.T) { // TD §4.3: >15 minutes since authentication => re-verify
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	e.group("grp")
	// Exactly fifteen minutes after authentication is still fresh (inclusive)...
	authenticated := e.scalar(`SELECT authenticated_at FROM sessions WHERE id=?`, e.sessID)
	e.clock.Advance(time.Duration(900-(e.clock.Now().Unix()-authenticated)) * time.Second)
	if e.clock.Now().Unix()-authenticated != 900 {
		t.Fatal("fixture clock arithmetic")
	}
	if _, err := e.a.CreateGroup(t.Context(), e.secret, "at-the-boundary"); err != nil {
		t.Fatalf("mutation at exactly 900s: %v", err)
	}
	// ...one second later every mutation is refused while reads still work.
	e.clock.Advance(time.Second)
	before := e.snapshot()
	mutations, reads := e.adminCalls(e.secret, agent)
	for name, call := range mutations {
		if err := call(); !errors.Is(err, ErrDenied) {
			t.Errorf("stale evidence, %s: %v", name, err)
		}
	}
	for name, call := range reads {
		if err := call(); err != nil {
			t.Errorf("stale evidence must not block %s: %v", name, err)
		}
	}
	e.mustNoChange("stale administration", before)
	// A real step-up (password + fresh TOTP) restores mutation rights through a successor session.
	stepped, err := e.stepUpTOTP(e.secret, e.totpID, e.totp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.CreateGroup(t.Context(), stepped.Secret(), "after-step-up"); err != nil {
		t.Fatalf("mutation after step-up: %v", err)
	}
	// The pre-step-up session was rotated out and no longer administers anything.
	if _, err := e.a.ListAgents(t.Context(), e.secret); !errors.Is(err, ErrDenied) {
		t.Fatalf("superseded session still administers: %v", err)
	}
}

func TestIssueRefusesAnAgentOutsideTheCurrentGenerations(t *testing.T) {
	for name, mutation := range map[string]string{
		"credential generation": `UPDATE agents SET credential_generation=2`,
		"authority generation":  `UPDATE agents SET authority_generation=2`,
		"disabled":              `UPDATE agents SET state='disabled'`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newAdminEnv(t)
			agent := e.agentOwnedBy("bot", e.person("owner"))
			e.exec(mutation)
			before := e.snapshot()
			if _, err := e.a.IssueCredential(t.Context(), e.secret, agent, CredentialRequest{}); !errors.Is(err, ErrAdminConflict) {
				t.Fatalf("issue: %v", err)
			}
			e.mustNoChange("stale agent issue", before)
		})
	}
}

func TestMultiplePolicyAdministratorsStayUnavailable(t *testing.T) { // acceptance: multiple policy administrators unavailable
	e := newAdminEnv(t)
	user := e.person("second")
	// No administrative operation creates, grants or moves a role...
	owner := e.agentOwnedBy("bot", user)
	e.issue(owner, CredentialRequest{})
	if err := e.a.AddMember(t.Context(), e.secret, e.group("everyone"), MemberUser, user); err != nil {
		t.Fatal(err)
	}
	if e.count("administrative_roles") != 1 || e.scalar(`SELECT count(*) FROM administrative_roles WHERE user_id=?`, user) != 0 {
		t.Fatal("administration created a role")
	}
	// ...and the schema itself refuses a second active administrator or any
	// endpoint-scoped one, so no adapter can add a path to it by accident.
	for name, statement := range map[string][]any{
		"second super administrator": {`INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('adm2',?,'super_admin','active',1)`, user},
		"endpoint administrator":     {`INSERT INTO administrative_roles(id,user_id,role,endpoint_id,state,authority_generation) SELECT 'ep',?,'endpoint_admin',id,'active',1 FROM endpoints`, user},
	} {
		if _, err := e.db.Exec(statement[0].(string), statement[1:]...); err == nil {
			t.Errorf("%s accepted by the schema", name)
		}
	}
}
