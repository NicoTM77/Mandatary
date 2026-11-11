package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// P1.10 administrative service tests. Every case runs over a real SQLite
// repository and the real session/TOTP services; denial cases prove the stored
// identity/credential tables are byte-identical afterwards.

func TestAdminConstructionRejectsUnsafeSettings(t *testing.T) {
	e := newSessionEnv(t)
	ok := DefaultAdminSettings()
	if _, err := NewAdmin(e.l, ok, nil); err != nil {
		t.Fatalf("default settings refused: %v", err)
	}
	if _, err := NewAdmin(nil, ok, nil); err == nil {
		t.Fatal("nil lifecycle accepted")
	}
	for name, mutate := range map[string]func(*AdminSettings){
		"zero default ttl":       func(s *AdminSettings) { s.DefaultTTL = 0 },
		"zero max ttl":           func(s *AdminSettings) { s.MaxTTL = 0 },
		"negative ttl":           func(s *AdminSettings) { s.DefaultTTL = -time.Second },
		"fractional ttl":         func(s *AdminSettings) { s.DefaultTTL = time.Second + time.Millisecond },
		"default above max":      func(s *AdminSettings) { s.DefaultTTL = s.MaxTTL + time.Second },
		"zero overlap max":       func(s *AdminSettings) { s.MaxOverlap = 0 },
		"zero default overlap":   func(s *AdminSettings) { s.DefaultOverlap = 0 },
		"overlap default high":   func(s *AdminSettings) { s.DefaultOverlap = s.MaxOverlap + time.Second },
		"fractional overlap":     func(s *AdminSettings) { s.MaxOverlap = time.Hour + time.Nanosecond },
		"absurd max ttl":         func(s *AdminSettings) { s.MaxTTL = 20 * 365 * 24 * time.Hour },
		"absurd overlap":         func(s *AdminSettings) { s.MaxOverlap = 100 * 24 * time.Hour },
		"overlap beyond max ttl": func(s *AdminSettings) { s.MaxOverlap = s.MaxTTL + time.Hour; s.DefaultOverlap = time.Hour },
	} {
		s := ok
		mutate(&s)
		if _, err := NewAdmin(e.l, s, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if s := DefaultAdminSettings(); s.DefaultTTL != 90*24*time.Hour || s.MaxTTL != 90*24*time.Hour || s.AllowNonExpiring {
		t.Fatalf("defaults are not the TD §3.2 policy: %+v", s)
	}
}

func TestAgentOwnershipIsExactlyOneUserXORGroup(t *testing.T) { // acceptance: owner constraint, invalid ownership
	e := newAdminEnv(t)
	ctx := t.Context()
	user, group := e.person("owner-user"), e.group("owner-group")
	e.person("quarantined-user")
	e.exec(`UPDATE users SET state='quarantined',credential_generation=0,authority_generation=0 WHERE username='quarantined-user'`)
	e.person("disabled-user")
	e.exec(`UPDATE users SET state='disabled' WHERE username='disabled-user'`)
	e.person("compromised-user")
	e.exec(`UPDATE users SET compromised=1 WHERE username='compromised-user'`)
	e.person("stale-user")
	e.exec(`UPDATE users SET authority_generation=9 WHERE username='stale-user'`)
	e.group("quarantined-group")
	e.exec(`UPDATE groups SET state='quarantined',authority_generation=0 WHERE name='quarantined-group'`)
	e.group("disabled-group")
	e.exec(`UPDATE groups SET state='disabled' WHERE name='disabled-group'`)
	idOf := func(table, col, name string) string {
		var id string
		if err := e.db.QueryRow(`SELECT id FROM `+table+` WHERE `+col+`=?`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	valid := map[string]AgentRequest{
		"user owner":  {Name: "agent-user", OwnerUserID: user},
		"group owner": {Name: "agent-group", OwnerGroupID: group},
	}
	for name, req := range valid {
		got, err := e.a.CreateAgent(ctx, e.secret, req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.State != "active" || (got.OwnerUserID == "") == (got.OwnerGroupID == "") {
			t.Fatalf("%s: view %+v", name, got)
		}
	}
	invalid := map[string]AgentRequest{
		"both owners":             {Name: "a1", OwnerUserID: user, OwnerGroupID: group},
		"no owner":                {Name: "a2"},
		"unknown user":            {Name: "a3", OwnerUserID: "no-such-user"},
		"unknown group":           {Name: "a4", OwnerGroupID: "no-such-group"},
		"group id as user":        {Name: "a5", OwnerUserID: group},
		"user id as group":        {Name: "a6", OwnerGroupID: user},
		"quarantined user":        {Name: "a7", OwnerUserID: idOf("users", "username", "quarantined-user")},
		"disabled user":           {Name: "a8", OwnerUserID: idOf("users", "username", "disabled-user")},
		"compromised user":        {Name: "a9", OwnerUserID: idOf("users", "username", "compromised-user")},
		"stale authority user":    {Name: "a10", OwnerUserID: idOf("users", "username", "stale-user")},
		"quarantined group":       {Name: "a11", OwnerGroupID: idOf("groups", "name", "quarantined-group")},
		"disabled group":          {Name: "a12", OwnerGroupID: idOf("groups", "name", "disabled-group")},
		"empty name":              {Name: "", OwnerUserID: user},
		"blank name":              {Name: "   ", OwnerUserID: user},
		"control char name":       {Name: "bad\nname", OwnerUserID: user},
		"oversized name":          {Name: strings.Repeat("a", 65), OwnerUserID: user},
		"unicode name":            {Name: "agént", OwnerUserID: user},
		"duplicate name":          {Name: "agent-user", OwnerUserID: user},
		"owner id with newline":   {Name: "a13", OwnerUserID: user + "\n"},
		"oversized owner id":      {Name: "a14", OwnerUserID: strings.Repeat("x", 129)},
		"sql metacharacter owner": {Name: "a15", OwnerUserID: "' OR 1=1 --"},
	}
	before := e.snapshot()
	for name, req := range invalid {
		_, err := e.a.CreateAgent(ctx, e.secret, req)
		if !errors.Is(err, ErrAdminInvalid) && !errors.Is(err, ErrAdminConflict) {
			t.Errorf("%s: want invalid/conflict, got %v", name, err)
		}
	}
	e.mustNoChange("invalid ownership", before)
	// Ownership implies neither membership nor any policy.
	if e.count("agent_group_memberships") != 0 || e.count("policies") != 0 {
		t.Fatal("ownership created membership or policy")
	}
	if e.scalar(`SELECT count(*) FROM agents WHERE (owner_user_id IS NOT NULL)+(owner_group_id IS NOT NULL)=1`) != 2 {
		t.Fatal("stored agents do not have exactly one owner")
	}
}

func TestAdministrativeIdentityCreationIsInertUntilExplicitlyGranted(t *testing.T) {
	e := newAdminEnv(t)
	ctx := t.Context()
	u, err := e.a.CreateUser(ctx, e.secret, "bob.builder")
	if err != nil || u.State != "active" || u.Username != "bob.builder" {
		t.Fatalf("user %+v %v", u, err)
	}
	g, err := e.a.CreateGroup(ctx, e.secret, "operators")
	if err != nil || g.State != "active" {
		t.Fatalf("group %+v %v", g, err)
	}
	// No credential, factor, role, membership or policy is minted implicitly.
	for table, want := range map[string]int64{"authenticators": e.count("authenticators"), "administrative_roles": 1, "user_group_memberships": 0, "agent_group_memberships": 0, "policies": 0, "agent_credentials": 0} {
		if e.count(table) != want {
			t.Fatalf("%s count %d", table, e.count(table))
		}
	}
	if e.scalar(`SELECT count(*) FROM authenticators WHERE user_id=?`, u.ID) != 0 {
		t.Fatal("administrative user creation minted an authenticator")
	}
	// The new account has current generations and the compulsory-MFA default.
	var mfa string
	var cg, ag int64
	if err := e.db.QueryRow(`SELECT mfa_requirement,credential_generation,authority_generation FROM users WHERE id=?`, u.ID).Scan(&mfa, &cg, &ag); err != nil || mfa != "required" || cg != 1 || ag != 1 {
		t.Fatalf("stored user %s %d %d %v", mfa, cg, ag, err)
	}
	// Duplicates and unsafe names are refused without changes.
	before := e.snapshot()
	for _, name := range []string{"bob.builder", "", " ", "-leading", "has space", "new\nline", strings.Repeat("a", 65), "tab\tname", "é"} {
		if _, err := e.a.CreateUser(ctx, e.secret, name); err == nil {
			t.Errorf("user name %q accepted", name)
		}
	}
	for _, name := range []string{"operators", "", " ", "new\nline", strings.Repeat("g", 65), "\x00"} {
		if _, err := e.a.CreateGroup(ctx, e.secret, name); err == nil {
			t.Errorf("group name %q accepted", name)
		}
	}
	e.mustNoChange("invalid identities", before)
	if _, err := e.a.CreateUser(ctx, e.secret, "bob.builder"); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("duplicate user: %v", err)
	}
	if _, err := e.a.CreateGroup(ctx, e.secret, "operators"); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("duplicate group: %v", err)
	}
	if e.notifications() != 0 {
		t.Fatal("creating inert identities notified policy change")
	}
}

func TestGroupMembershipIsExplicitIdempotentAndNotified(t *testing.T) {
	e := newAdminEnv(t)
	ctx := t.Context()
	user, group := e.person("member"), e.group("team")
	owned := e.agentOwnedBy("bot", user)
	groupOwned, err := e.a.CreateAgent(ctx, e.secret, AgentRequest{Name: "svc", OwnerGroupID: group})
	if err != nil {
		t.Fatal(err)
	}
	// Owning a group is not membership of it.
	if e.count("agent_group_memberships") != 0 {
		t.Fatal("group ownership implied membership")
	}
	for i := 0; i < 2; i++ { // idempotent
		if err := e.a.AddMember(ctx, e.secret, group, MemberUser, user); err != nil {
			t.Fatal(err)
		}
		if err := e.a.AddMember(ctx, e.secret, group, MemberAgent, owned); err != nil {
			t.Fatal(err)
		}
	}
	if e.count("user_group_memberships") != 1 || e.count("agent_group_memberships") != 1 {
		t.Fatalf("memberships %d/%d", e.count("user_group_memberships"), e.count("agent_group_memberships"))
	}
	if e.scalar(`SELECT count(*) FROM agent_group_memberships WHERE agent_id=?`, groupOwned.ID) != 0 {
		t.Fatal("group-owned agent became a member")
	}
	if e.scalar(`SELECT count(*) FROM user_group_memberships WHERE state='active' AND authority_generation=1`) != 1 {
		t.Fatal("membership not active at the current authority generation")
	}
	notified := e.notifications()
	if notified < 2 {
		t.Fatalf("membership additions notified %d times", notified)
	}
	// Removal is soft, notified and re-addable.
	if err := e.a.RemoveMember(ctx, e.secret, group, MemberAgent, owned); err != nil {
		t.Fatal(err)
	}
	if e.scalar(`SELECT count(*) FROM agent_group_memberships WHERE state='disabled'`) != 1 || e.notifications() != notified+1 {
		t.Fatal("removal not durable/notified")
	}
	if err := e.a.RemoveMember(ctx, e.secret, group, MemberAgent, owned); err != nil {
		t.Fatalf("removing an already removed member must be idempotent: %v", err)
	}
	if err := e.a.AddMember(ctx, e.secret, group, MemberAgent, owned); err != nil {
		t.Fatal(err)
	}
	if e.scalar(`SELECT count(*) FROM agent_group_memberships WHERE state='active' AND authority_generation=1`) != 1 {
		t.Fatal("re-add did not reactivate")
	}
	// Invalid requests change nothing.
	before := e.snapshot()
	e.group("other")
	e.exec(`UPDATE groups SET state='disabled' WHERE name='other'`)
	var disabled string
	if err := e.db.QueryRow(`SELECT id FROM groups WHERE name='other'`).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	before = e.snapshot()
	for name, fn := range map[string]func() error{
		"unknown kind":    func() error { return e.a.AddMember(ctx, e.secret, group, MemberKind("admin"), user) },
		"empty kind":      func() error { return e.a.AddMember(ctx, e.secret, group, "", user) },
		"unknown group":   func() error { return e.a.AddMember(ctx, e.secret, "nope", MemberUser, user) },
		"unknown user":    func() error { return e.a.AddMember(ctx, e.secret, group, MemberUser, "nope") },
		"unknown agent":   func() error { return e.a.AddMember(ctx, e.secret, group, MemberAgent, "nope") },
		"user as agent":   func() error { return e.a.AddMember(ctx, e.secret, group, MemberAgent, user) },
		"agent as user":   func() error { return e.a.AddMember(ctx, e.secret, group, MemberUser, owned) },
		"disabled group":  func() error { return e.a.AddMember(ctx, e.secret, disabled, MemberUser, user) },
		"remove unknown":  func() error { return e.a.RemoveMember(ctx, e.secret, group, MemberUser, "nope") },
		"never a member":  func() error { return e.a.RemoveMember(ctx, e.secret, group, MemberAgent, groupOwned.ID) },
		"remove bad kind": func() error { return e.a.RemoveMember(ctx, e.secret, group, MemberKind("x"), user) },
	} {
		if err := fn(); !errors.Is(err, ErrAdminInvalid) && !errors.Is(err, ErrAdminNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.mustNoChange("invalid membership", before)
	// A quarantined (restored) membership is never silently approved by re-adding.
	e.exec(`UPDATE user_group_memberships SET state='quarantined',authority_generation=0`)
	if err := e.a.AddMember(ctx, e.secret, group, MemberUser, user); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("quarantined membership re-approved: %v", err)
	}
	if e.scalar(`SELECT count(*) FROM user_group_memberships WHERE state='quarantined'`) != 1 {
		t.Fatal("quarantined membership changed")
	}
}

func TestIssuedTokenIsShownOnceAndOnlyItsHashIsPersisted(t *testing.T) { // acceptance: 256-bit tokens shown once, hash-only persistence
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	issued, token := e.issue(agent, CredentialRequest{})
	if !ValidAgentTokenFormat(string(token)) || len(decodeAgentToken(t, token)) != 32 {
		t.Fatalf("token format %q", token)
	}
	hash, prefix, state, gen := e.credentialRow(issued.Credential.ID)
	if !bytes.Equal(hash, sha(token)) || state != "active" || gen != 1 {
		t.Fatalf("stored credential %x %s %d", hash, state, gen)
	}
	// The display identifier is a separate random value, never token characters.
	if prefix != "mdt_"+issued.Credential.ID[:8] || strings.Contains(string(token), prefix[4:]) {
		t.Fatalf("display prefix %q derived from %q", prefix, issued.Credential.ID)
	}
	if issued.Credential.DisplayID != prefix {
		t.Fatal("view display id differs from stored prefix")
	}
	// Plaintext and encodings of it are absent from the whole store (db, WAL, shm).
	raw := e.rawStore()
	for name, needle := range map[string][]byte{
		"plaintext":  token,
		"body":       token[4:],
		"base64":     []byte(base64.StdEncoding.EncodeToString(token)),
		"hex":        []byte(hex.EncodeToString(token)),
		"raw bits":   decodeAgentToken(t, token),
		"first half": token[:30],
	} {
		if bytes.Contains(raw, needle) {
			t.Fatalf("store contains the token (%s)", name)
		}
	}
	if !bytes.Contains(raw, sha(token)) {
		t.Fatal("hash not persisted (scan sanity check)")
	}
	// Views carry neither token nor verifier.
	views, err := e.a.ListAgents(t.Context(), e.secret)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(views)
	for _, needle := range [][]byte{token, token[4:], []byte(hex.EncodeToString(sha(token))), []byte(base64.StdEncoding.EncodeToString(sha(token))), sha(token)} {
		if bytes.Contains(blob, needle) {
			t.Fatal("agent view exposes token material")
		}
	}
	// A stored hash is not a bearer token, in any encoding.
	for _, presented := range [][]byte{[]byte(hex.EncodeToString(sha(token))), []byte("mdt_" + hex.EncodeToString(sha(token))), sha(token), []byte(base64.StdEncoding.EncodeToString(sha(token)))} {
		if e.accepted(presented) {
			t.Fatal("verifier accepted the stored verifier as a bearer token")
		}
	}
	if !e.accepted(token) {
		t.Fatal("freshly issued token rejected")
	}
	// Redaction and single export.
	for _, out := range []string{fmt.Sprint(issued), fmt.Sprintf("%+v", issued), fmt.Sprintf("%#v", &issued)} {
		if strings.Contains(out, string(token[4:20])) {
			t.Fatal("issued credential formatted the token")
		}
	}
	if got := issued.ExportOnce(); !bytes.Equal(got, token) {
		t.Fatal("export differs")
	}
	if len(issued.ExportOnce()) != 0 {
		t.Fatal("token exportable twice")
	}
	// No later read can reveal it: listing again is metadata only and nothing
	// in the repository can recover the plaintext.
	if again, _ := e.a.ListAgents(t.Context(), e.secret); len(again) != 1 || len(again[0].Credentials) != 1 {
		t.Fatalf("listing %+v", again)
	}
}

func TestCredentialExpiryBoundaryIsExact(t *testing.T) { // acceptance: expired token rejected, deterministic boundary
	e := newAdminEnvWith(t, AdminSettings{DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour, DefaultOverlap: 10 * time.Minute, MaxOverlap: time.Hour})
	agent := e.agentOwnedBy("bot", e.person("owner"))
	issued, token := e.issue(agent, CredentialRequest{TTL: 3600 * time.Second})
	t0 := e.clock.Now()
	if issued.Credential.ExpiresAt == nil || *issued.Credential.ExpiresAt != t0.Unix()+3600 {
		t.Fatalf("expiry %v", issued.Credential.ExpiresAt)
	}
	if !e.accepted(token) {
		t.Fatal("rejected at issue")
	}
	e.clock.Advance(3599 * time.Second)
	if !e.accepted(token) {
		t.Fatal("rejected one second before expiry")
	}
	e.clock.Advance(time.Second)
	if e.accepted(token) {
		t.Fatal("accepted at the expiry instant")
	}
	e.clock.Advance(time.Second)
	if e.accepted(token) {
		t.Fatal("accepted after expiry")
	}
}

func TestOverlapWindowBoundaryIsDeterministic(t *testing.T) { // acceptance: overlap rotation, boundary tests
	for _, overlap := range []time.Duration{time.Second, 2 * time.Second, 59 * time.Second, 10 * time.Minute, time.Hour} {
		t.Run(overlap.String(), func(t *testing.T) {
			e := newAdminEnvWith(t, AdminSettings{DefaultTTL: 4 * time.Hour, MaxTTL: 4 * time.Hour, DefaultOverlap: time.Minute, MaxOverlap: 2 * time.Hour})
			agent := e.agentOwnedBy("bot", e.person("owner"))
			_, oldToken := e.issue(agent, CredentialRequest{})
			e.advance(5 * time.Minute)
			rotatedAt := e.clock.Now()
			res, err := e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{Overlap: overlap})
			if err != nil {
				t.Fatal(err)
			}
			newToken := res.New.ExportOnce()
			if len(res.RotatedOut) != 1 || res.RotatedOut[0].OverlapUntil == nil || *res.RotatedOut[0].OverlapUntil != rotatedAt.Unix()+int64(overlap/time.Second) {
				t.Fatalf("rotated-out view %+v", res.RotatedOut)
			}
			// Old and new are both accepted for exactly [rotatedAt, rotatedAt+overlap).
			e.clock.Advance(0)
			if !e.accepted(oldToken) || !e.accepted(newToken) {
				t.Fatal("overlap start: both tokens must be accepted")
			}
			e.clock.Advance(overlap - time.Second)
			if !e.accepted(oldToken) || !e.accepted(newToken) {
				t.Fatalf("one second before the end (%s): both tokens must still be accepted", overlap)
			}
			e.clock.Advance(time.Second)
			if e.accepted(oldToken) {
				t.Fatalf("rotated-out token accepted at the overlap boundary (%s)", overlap)
			}
			if !e.accepted(newToken) {
				t.Fatal("new token rejected when the overlap ended")
			}
			e.clock.Advance(time.Hour)
			if e.accepted(oldToken) {
				t.Fatal("rotated-out token accepted long after the overlap")
			}
		})
	}
}

func TestRotationWithoutOverlapAndDefaultOverlap(t *testing.T) {
	e := newAdminEnvWith(t, AdminSettings{DefaultTTL: time.Hour, MaxTTL: time.Hour, DefaultOverlap: 7 * time.Minute, MaxOverlap: 30 * time.Minute})
	agent := e.agentOwnedBy("bot", e.person("owner"))
	_, first := e.issue(agent, CredentialRequest{})
	res, err := e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{Immediate: true})
	if err != nil {
		t.Fatal(err)
	}
	second := res.New.ExportOnce()
	if e.accepted(first) || !e.accepted(second) {
		t.Fatal("immediate rotation must reject the old token at once and accept the new one")
	}
	if len(res.RotatedOut) != 1 || res.RotatedOut[0].Status != CredentialRevoked {
		t.Fatalf("rotated-out %+v", res.RotatedOut)
	}
	// Omitted overlap uses the configured default exactly.
	at := e.clock.Now().Unix()
	res, err = e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RotatedOut) != 1 || *res.RotatedOut[0].OverlapUntil != at+7*60 {
		t.Fatalf("default overlap %+v", res.RotatedOut)
	}
	before := e.snapshot()
	for name, req := range map[string]RotateRequest{
		"above max":      {Overlap: 30*time.Minute + time.Second},
		"negative":       {Overlap: -time.Second},
		"fractional":     {Overlap: time.Second + time.Millisecond},
		"both":           {Overlap: time.Minute, Immediate: true},
		"huge":           {Overlap: 1 << 62},
		"ttl too large":  {CredentialRequest: CredentialRequest{TTL: time.Hour + time.Second}},
		"ttl negative":   {CredentialRequest: CredentialRequest{TTL: -time.Second}},
		"ttl fractional": {CredentialRequest: CredentialRequest{TTL: 1500 * time.Millisecond}},
		"non-expiring":   {CredentialRequest: CredentialRequest{NonExpiring: true}},
	} {
		if _, err := e.a.RotateCredential(t.Context(), e.secret, agent, req); !errors.Is(err, ErrAdminInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.mustNoChange("invalid rotation", before)
}

func TestRotatingAgainRevokesTheCredentialStillOverlapping(t *testing.T) { // at most two live credentials
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	_, a := e.issue(agent, CredentialRequest{})
	r1, err := e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{Overlap: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	b := r1.New.ExportOnce()
	r2, err := e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{Overlap: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c := r2.New.ExportOnce()
	if e.accepted(a) {
		t.Fatal("the credential that was already rotated out survived a second rotation")
	}
	if !e.accepted(b) || !e.accepted(c) {
		t.Fatal("the previous and the new credential must both be accepted during the new overlap")
	}
	live := e.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`)
	if live != 2 {
		t.Fatalf("live credentials: %d", live)
	}
	e.clock.Advance(30 * time.Minute)
	if e.accepted(b) || !e.accepted(c) {
		t.Fatal("after the second overlap only the newest credential is accepted")
	}
}

func TestRotateAndIssueRulesForLiveCredentials(t *testing.T) {
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	ctx := t.Context()
	if _, err := e.a.RotateCredential(ctx, e.secret, agent, RotateRequest{}); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("rotating with nothing to rotate: %v", err)
	}
	first, _ := e.issue(agent, CredentialRequest{})
	if _, err := e.a.IssueCredential(ctx, e.secret, agent, CredentialRequest{}); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("second concurrent first-issue: %v", err)
	}
	if e.count("agent_credentials") != 1 {
		t.Fatal("conflicting issue stored a credential")
	}
	if err := e.a.RevokeCredential(ctx, e.secret, agent, first.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.RotateCredential(ctx, e.secret, agent, RotateRequest{}); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("rotating a revoked-only agent: %v", err)
	}
	if _, token := e.issue(agent, CredentialRequest{}); !e.accepted(token) {
		t.Fatal("issuing after revocation failed")
	}
	if _, err := e.a.IssueCredential(ctx, e.secret, "no-such-agent", CredentialRequest{}); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
}

func TestRevocationIsImmediateIdempotentAndAgentScoped(t *testing.T) { // acceptance: revoked token rejected
	e := newAdminEnv(t)
	owner := e.person("owner")
	a1, a2 := e.agentOwnedBy("one", owner), e.agentOwnedBy("two", owner)
	c1, t1 := e.issue(a1, CredentialRequest{})
	c2, t2 := e.issue(a2, CredentialRequest{})
	ctx := t.Context()
	// A credential cannot be revoked through another agent's path.
	if err := e.a.RevokeCredential(ctx, e.secret, a1, c2.Credential.ID); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("cross-agent revoke: %v", err)
	}
	if err := e.a.RevokeCredential(ctx, e.secret, a1, "no-such-credential"); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("unknown credential: %v", err)
	}
	if !e.accepted(t2) {
		t.Fatal("failed revoke damaged another credential")
	}
	var observed string
	e.hook = func(ctx context.Context) error { // the revocation must already be durable when observers are told
		return e.db.QueryRow(`SELECT state FROM agent_credentials WHERE id=?`, c1.Credential.ID).Scan(&observed)
	}
	if err := e.a.RevokeCredential(ctx, e.secret, a1, c1.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if observed != "revoked" || e.notifications() != 1 {
		t.Fatalf("notified before durable revocation (%q, %d)", observed, e.notifications())
	}
	e.hook = nil
	if e.accepted(t1) {
		t.Fatal("revoked token still accepted")
	}
	if !e.accepted(t2) {
		t.Fatal("unrelated token revoked")
	}
	revokedAt := e.scalar(`SELECT revoked_at FROM agent_credentials WHERE id=?`, c1.Credential.ID)
	e.advance(time.Minute)
	if err := e.a.RevokeCredential(ctx, e.secret, a1, c1.Credential.ID); err != nil {
		t.Fatalf("repeat revoke must be idempotent: %v", err)
	}
	if e.scalar(`SELECT revoked_at FROM agent_credentials WHERE id=?`, c1.Credential.ID) != revokedAt {
		t.Fatal("repeat revoke rewrote the revocation time")
	}
	if e.notifications() != 2 {
		t.Fatal("idempotent revoke must still notify (retry after a failed notification)")
	}
}

func TestRevokedAndRotatedOutCredentialsCannotBeRevived(t *testing.T) {
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	first, oldToken := e.issue(agent, CredentialRequest{})
	rot, err := e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{Overlap: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	if e.accepted(oldToken) {
		t.Fatal("rotated-out token accepted")
	}
	for name, statement := range map[string]string{
		"extend overlap":   `UPDATE agent_credentials SET rotation_overlap_until=rotation_overlap_until+86400 WHERE id='` + first.Credential.ID + `'`,
		"clear overlap":    `UPDATE agent_credentials SET rotation_overlap_until=NULL WHERE id='` + first.Credential.ID + `'`,
		"extend expiry":    `UPDATE agent_credentials SET expires_at=expires_at+86400 WHERE id='` + first.Credential.ID + `'`,
		"swap verifier":    `UPDATE agent_credentials SET token_hash=zeroblob(32) WHERE id='` + first.Credential.ID + `'`,
		"revoke then undo": `UPDATE agent_credentials SET state='revoked',revoked_at=issued_at WHERE id='` + first.Credential.ID + `'`,
	} {
		_, err := e.db.Exec(statement)
		if name == "revoke then undo" {
			if err != nil {
				t.Fatalf("revoking must stay possible: %v", err)
			}
			if _, err = e.db.Exec(`UPDATE agent_credentials SET state='active',revoked_at=NULL WHERE id='` + first.Credential.ID + `'`); err == nil {
				t.Fatal("a revoked credential was reactivated")
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s succeeded", name)
		}
	}
	if e.accepted(oldToken) {
		t.Fatal("old token revived")
	}
	newToken := rot.New.ExportOnce()
	if !e.accepted(newToken) {
		t.Fatal("rotation target must keep working")
	}
}

func TestDisablingAnAgentRevokesEveryCredentialAndBlocksReissue(t *testing.T) {
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	_, a := e.issue(agent, CredentialRequest{})
	rot, err := e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{Overlap: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	b := rot.New.ExportOnce()
	notified := e.notifications()
	if err := e.a.DisableAgent(t.Context(), e.secret, agent); err != nil {
		t.Fatal(err)
	}
	if e.accepted(a) || e.accepted(b) {
		t.Fatal("a disabled agent's token is still accepted")
	}
	if e.scalar(`SELECT count(*) FROM agent_credentials WHERE state!='revoked'`) != 0 || e.scalar(`SELECT count(*) FROM agents WHERE state='disabled'`) != 1 {
		t.Fatal("agent not fully retired")
	}
	if e.notifications() != notified+1 {
		t.Fatal("disable did not notify")
	}
	if err := e.a.DisableAgent(t.Context(), e.secret, agent); err != nil {
		t.Fatalf("disable must be idempotent: %v", err)
	}
	if _, err := e.a.IssueCredential(t.Context(), e.secret, agent, CredentialRequest{}); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("issuing for a disabled agent: %v", err)
	}
	if _, err := e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{}); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("rotating a disabled agent: %v", err)
	}
	if err := e.a.DisableAgent(t.Context(), e.secret, "no-such-agent"); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
}

func TestOldGenerationAndQuarantineRejectEveryCredentialAndAdministration(t *testing.T) { // acceptance: old generation token rejected
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	_, token := e.issue(agent, CredentialRequest{})
	if !e.accepted(token) {
		t.Fatal("baseline")
	}
	// A new credential generation (for example after a restore) kills every old token...
	e.exec(`UPDATE installation_control SET credential_generation=2`)
	if e.accepted(token) {
		t.Fatal("old-generation token accepted")
	}
	// ...and the service never issues under a stale agent or a stale session.
	if _, err := e.a.IssueCredential(t.Context(), e.secret, agent, CredentialRequest{}); err == nil {
		t.Fatal("issued under a stale credential generation")
	}
	if e.count("agent_credentials") != 1 {
		t.Fatal("stale-generation issue stored a credential")
	}
}

func TestRestoreQuarantineDeniesAdministrationAndAcceptance(t *testing.T) { // RESTORE-01/-11 substrate
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	_, token := e.issue(agent, CredentialRequest{})
	e.exec(`UPDATE installation_control SET restore_quarantined=1`)
	before := e.snapshot()
	if e.accepted(token) {
		t.Fatal("token accepted under restore quarantine")
	}
	ctx := t.Context()
	calls := map[string]func() error{
		"create user":  func() error { _, err := e.a.CreateUser(ctx, e.secret, "late"); return err },
		"create group": func() error { _, err := e.a.CreateGroup(ctx, e.secret, "late"); return err },
		"create agent": func() error {
			_, err := e.a.CreateAgent(ctx, e.secret, AgentRequest{Name: "late", OwnerUserID: "u"})
			return err
		},
		"issue":   func() error { _, err := e.a.IssueCredential(ctx, e.secret, agent, CredentialRequest{}); return err },
		"rotate":  func() error { _, err := e.a.RotateCredential(ctx, e.secret, agent, RotateRequest{}); return err },
		"revoke":  func() error { return e.a.RevokeCredential(ctx, e.secret, agent, "x") },
		"disable": func() error { return e.a.DisableAgent(ctx, e.secret, agent) },
		"add":     func() error { return e.a.AddMember(ctx, e.secret, "g", MemberUser, "u") },
		"remove":  func() error { return e.a.RemoveMember(ctx, e.secret, "g", MemberUser, "u") },
		"agents":  func() error { _, err := e.a.ListAgents(ctx, e.secret); return err },
		"groups":  func() error { _, err := e.a.ListGroups(ctx, e.secret); return err },
		"users":   func() error { _, err := e.a.ListUsers(ctx, e.secret); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrDenied) {
			t.Errorf("%s under quarantine: %v", name, err)
		}
	}
	e.mustNoChange("quarantined administration", before)
}

func TestTokenLifetimePolicy(t *testing.T) { // TD §3.2: expiry by default, max TTL, approved non-expiring
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	ctx := t.Context()
	now := e.clock.Now().Unix()
	c, token := e.issue(agent, CredentialRequest{})
	if *c.Credential.ExpiresAt != now+90*86400 || c.Credential.NonExpiring {
		t.Fatalf("default lifetime %+v", c.Credential)
	}
	if err := e.a.RevokeCredential(ctx, e.secret, agent, c.Credential.ID); err != nil || e.accepted(token) {
		t.Fatal("revoke")
	}
	before := e.snapshot()
	for name, req := range map[string]CredentialRequest{
		"above maximum":      {TTL: 90*24*time.Hour + time.Second},
		"negative":           {TTL: -time.Second},
		"fractional":         {TTL: time.Second + time.Nanosecond},
		"non-expiring":       {NonExpiring: true},
		"non-expiring + ttl": {NonExpiring: true, TTL: time.Hour},
	} {
		if _, err := e.a.IssueCredential(ctx, e.secret, agent, req); !errors.Is(err, ErrAdminInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.mustNoChange("invalid lifetimes", before)
	c, _ = e.issue(agent, CredentialRequest{TTL: 90 * 24 * time.Hour}) // maximum is inclusive
	if *c.Credential.ExpiresAt != now+90*86400 {
		t.Fatal("maximum TTL not honoured")
	}
	if err := e.a.RevokeCredential(ctx, e.secret, agent, c.Credential.ID); err != nil {
		t.Fatal(err)
	}
	// Non-expiring service tokens exist only when the deployment explicitly approves them.
	approved := newAdminEnvWith(t, AdminSettings{DefaultTTL: time.Hour, MaxTTL: time.Hour, DefaultOverlap: time.Minute, MaxOverlap: time.Hour, AllowNonExpiring: true})
	service := approved.agentOwnedBy("svc", approved.person("owner"))
	nc, nt := approved.issue(service, CredentialRequest{NonExpiring: true})
	if nc.Credential.ExpiresAt != nil || !nc.Credential.NonExpiring {
		t.Fatalf("non-expiring view %+v", nc.Credential)
	}
	approved.advance(10 * time.Hour)
	if !approved.accepted(nt) {
		t.Fatal("approved non-expiring token expired")
	}
	if _, err := approved.a.RotateCredential(t.Context(), approved.secret, service, RotateRequest{CredentialRequest: CredentialRequest{NonExpiring: true}, Overlap: time.Minute}); err != nil {
		t.Fatalf("rotating an approved non-expiring token: %v", err)
	}
	approved.advance(time.Minute)
	if approved.accepted(nt) {
		t.Fatal("rotated-out non-expiring token still accepted")
	}
}

func TestRandomnessFailureIssuesNoCredential(t *testing.T) { // N63B4-RANDOM-EVIDENCE
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	e.a.random = erroringReader{}
	before := e.snapshot()
	if _, err := e.a.IssueCredential(t.Context(), e.secret, agent, CredentialRequest{}); err == nil {
		t.Fatal("issued without randomness")
	}
	if _, err := e.a.CreateUser(t.Context(), e.secret, "nobody"); err == nil {
		t.Fatal("created an identifier without randomness")
	}
	e.mustNoChange("randomness failure", before)
	e.a.random = bytes.NewReader(make([]byte, 64))
	if _, err := e.a.IssueCredential(t.Context(), e.secret, agent, CredentialRequest{}); err == nil {
		t.Fatal("issued from an all-zero source")
	}
	e.mustNoChange("zero randomness", before)
	// A first-issue with a working source keeps rotation working afterwards.

	e.a.random = rand.Reader
	if _, token := e.issue(agent, CredentialRequest{}); !e.accepted(token) {
		t.Fatal("recovery after the source returned")
	}
}

func TestStorageFailureNeverReturnsATokenOrChangesState(t *testing.T) {
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	before := e.snapshot()
	e.l.repo.FailClosed()
	issued, err := e.a.IssueCredential(t.Context(), e.secret, agent, CredentialRequest{})
	if !errors.Is(err, ErrAdminUnavailable) || len(issued.ExportOnce()) != 0 {
		t.Fatalf("poisoned store: %v", err)
	}
	if _, err := e.a.ListAgents(t.Context(), e.secret); !errors.Is(err, ErrAdminUnavailable) {
		t.Fatalf("read on a poisoned store: %v", err)
	}
	e.mustNoChange("storage failure", before)
}

func TestNotificationFailureDoesNotUndoARevocationButIsReported(t *testing.T) {
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	c, token := e.issue(agent, CredentialRequest{})
	e.hook = func(context.Context) error { return errors.New("synthetic notifier failure") }
	err := e.a.RevokeCredential(t.Context(), e.secret, agent, c.Credential.ID)
	if !errors.Is(err, ErrAdminUnavailable) {
		t.Fatalf("notification failure must be reported, got %v", err)
	}
	if e.accepted(token) {
		t.Fatal("revocation was undone by a notifier failure")
	}
	if strings.Contains(fmt.Sprint(err), "synthetic") {
		t.Fatal("notifier detail leaked")
	}
}

func TestConcurrentFirstIssueYieldsExactlyOneLiveCredential(t *testing.T) {
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := e.a.IssueCredential(t.Context(), e.secret, agent, CredentialRequest{})
			_ = c.ExportOnce()
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok, conflict := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrAdminConflict):
			conflict++
		default:
			t.Fatalf("unexpected error %v", err)
		}
	}
	if ok != 1 || conflict != 11 || e.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`) != 1 {
		t.Fatalf("ok=%d conflict=%d live=%d", ok, conflict, e.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`))
	}
}

func TestConcurrentRotationsNeverExceedTwoLiveCredentials(t *testing.T) {
	e := newAdminEnv(t)
	agent := e.agentOwnedBy("bot", e.person("owner"))
	e.issue(agent, CredentialRequest{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.a.RotateCredential(t.Context(), e.secret, agent, RotateRequest{Overlap: time.Hour})
			if err != nil {
				t.Error(err)
				return
			}
			_ = res.New.ExportOnce()
		}()
	}
	wg.Wait()
	if live := e.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`); live != 2 {
		t.Fatalf("live credentials after serialized rotations: %d", live)
	}
	if e.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active' AND rotation_overlap_until IS NULL`) != 1 {
		t.Fatal("exactly one primary credential expected")
	}
}

func TestAdministrativeViewsAreSecretFreeAndComplete(t *testing.T) {
	e := newAdminEnv(t)
	ctx := t.Context()
	owner, group := e.person("owner"), e.group("team")
	user := e.agentOwnedBy("user-agent", owner)
	svc, err := e.a.CreateAgent(ctx, e.secret, AgentRequest{Name: "svc", OwnerGroupID: group})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.a.AddMember(ctx, e.secret, group, MemberUser, owner); err != nil {
		t.Fatal(err)
	}
	if err := e.a.AddMember(ctx, e.secret, group, MemberAgent, user); err != nil {
		t.Fatal(err)
	}
	c, token := e.issue(user, CredentialRequest{})
	agents, err := e.a.ListAgents(ctx, e.secret)
	if err != nil || len(agents) != 2 {
		t.Fatalf("agents %+v %v", agents, err)
	}
	byName := map[string]AgentView{}
	for _, a := range agents {
		byName[a.Name] = a
	}
	if byName["user-agent"].OwnerUserID != owner || byName["user-agent"].OwnerGroupID != "" || byName["svc"].OwnerGroupID != group || byName["svc"].ID != svc.ID {
		t.Fatalf("owner rendering %+v", byName)
	}
	cv := byName["user-agent"].Credentials
	if len(cv) != 1 || cv[0].ID != c.Credential.ID || cv[0].Status != CredentialActive || !cv[0].AcceptedNow {
		t.Fatalf("credential view %+v", cv)
	}
	groups, err := e.a.ListGroups(ctx, e.secret)
	if err != nil || len(groups) != 1 || len(groups[0].Users) != 1 || len(groups[0].Agents) != 1 || groups[0].Users[0] != owner {
		t.Fatalf("groups %+v %v", groups, err)
	}
	users, err := e.a.ListUsers(ctx, e.secret)
	if err != nil || len(users) != 2 {
		t.Fatalf("users %+v %v", users, err)
	}
	blob, _ := json.Marshal(map[string]any{"a": agents, "g": groups, "u": users})
	if bytes.Contains(blob, token) || bytes.Contains(blob, []byte(hex.EncodeToString(sha(token)))) || bytes.Contains(blob, []byte("verifier")) || bytes.Contains(blob, []byte("token_hash")) {
		t.Fatal("views expose secret material")
	}
	// A rotated-out credential is labelled as such after its window.
	if _, err := e.a.RotateCredential(ctx, e.secret, user, RotateRequest{Overlap: time.Minute}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	e.refresh()
	agents, _ = e.a.ListAgents(ctx, e.secret)
	statuses := map[CredentialStatus]int{}
	for _, a := range agents {
		for _, c := range a.Credentials {
			statuses[c.Status]++
		}
	}
	if statuses[CredentialRotatedOut] != 1 || statuses[CredentialActive] != 1 {
		t.Fatalf("statuses %v", statuses)
	}
}
