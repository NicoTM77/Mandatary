package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// freshSameKey returns an empty, never-set-up installation holding the same master key.
func freshSameKey(t *testing.T) *env { return newEnv(t, keyHexA) }

// RESTORE-05/06/09 fresh instance, same key: everything in scope arrives, nothing is effective, the
// installation is quarantined, credential material is retained INACTIVE and is readable by the target.
func TestSameKeyRestoreIntoAFreshInstanceImportsOnlyInactiveRecords(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	raw := src.export(ModeFull)

	dst := freshSameKey(t)
	zero := dst.controls()
	if zero.RestoreQuarantined != 1 || zero.RestoreGeneration != 0 {
		t.Fatalf("fresh installation must start quarantined at generation zero: %+v", zero)
	}
	report, err := dst.restore(raw, InitiatorHost, false)
	if err != nil {
		t.Fatal(err)
	}
	c := dst.controls()
	if c.RestoreQuarantined != 1 || c.CredentialGeneration != 1 || c.SessionGeneration != 1 || c.AuthorityGeneration != 1 || c.RestoreGeneration != 1 {
		t.Fatalf("control state after restore: %+v", c)
	}
	if report.State != "restore_quarantine" || report.NextStep != "host_recovery_required" || report.RestoreGeneration != 1 || report.Provenance != ProvenanceAuthenticated || report.Mode != ModeFull {
		t.Fatalf("report %+v", report)
	}
	if got := dst.activeAuthority(); got != 0 {
		t.Fatalf("%d records are effective after a restore", got)
	}
	// Every imported record is quarantined with generation zero (never what the archive claimed).
	for _, q := range []string{
		`SELECT count(*) FROM users WHERE state='quarantined' AND credential_generation=0 AND authority_generation=0`,
		`SELECT count(*) FROM groups WHERE state='quarantined' AND authority_generation=0`,
		`SELECT count(*) FROM agents WHERE state='quarantined' AND credential_generation=0 AND authority_generation=0`,
		`SELECT count(*) FROM policies WHERE state='quarantined' AND authority_generation=0`,
		`SELECT count(*) FROM administrative_roles WHERE state='quarantined' AND authority_generation=0`,
		`SELECT count(*) FROM authenticators WHERE state='quarantined' AND credential_generation=0`,
		`SELECT count(*) FROM agent_credentials WHERE state='quarantined' AND credential_generation=0`,
		`SELECT count(*) FROM notification_addresses WHERE state='quarantined' AND verified_at IS NULL`,
	} {
		if dst.scalar(q) == 0 {
			t.Fatalf("expected imported inactive rows: %s", q)
		}
	}
	if dst.scalar(`SELECT count(*) FROM users`) != 2 || dst.scalar(`SELECT count(*) FROM policies`) != 2 || dst.scalar(`SELECT count(*) FROM sessions`) != 0 {
		t.Fatal("record counts")
	}
	// The fresh installation's own endpoint identity stays; selectors and rules were re-pointed at it.
	if dst.scalar(`SELECT count(*) FROM endpoints`) != 1 || dst.scalar(`SELECT count(*) FROM policies p JOIN endpoints e ON e.id=p.endpoint_id AND e.slug='local'`) != 2 {
		t.Fatal("endpoint mapping")
	}
	if dst.text(`SELECT state FROM endpoints WHERE slug='local'`) != "quarantined" {
		t.Fatal("the local endpoint must need approval")
	}
	// The TOTP seed was re-sealed under the TARGET installation: readable there, retained for provenance only.
	env := []byte(dst.text(`SELECT encrypted_secret FROM authenticators WHERE id='adm-totp'`))
	if plain, err := dst.repo.DecryptSecret("totp", "adm-totp", env); err != nil || !bytes.Equal(plain, seedBytes) {
		t.Fatalf("re-sealed seed: %v", err)
	}
	if src.text(`SELECT encrypted_secret FROM authenticators WHERE id='adm-totp'`) == dst.text(`SELECT encrypted_secret FROM authenticators WHERE id='adm-totp'`) {
		t.Fatal("ciphertext was copied between installations instead of re-sealed")
	}
	// The original timing of a token is kept exactly: no lifetime is extended or restarted.
	if dst.scalar(`SELECT count(*) FROM agent_credentials WHERE id='cred-1' AND issued_at=1999999000 AND expires_at=2000999999 AND revoked_at IS NULL`) != 1 {
		t.Fatal("credential timing")
	}
	if dst.scalar(`SELECT count(*) FROM restore_reports WHERE restore_generation=1 AND backup_id=? AND initiator='host'`, report.BackupID) != 1 || dst.scalar(`SELECT count(*) FROM restore_manifest WHERE decision='pending'`) == 0 {
		t.Fatal("report and manifest rows")
	}
	// RESTORE-10: usage is outside the backup scope: the source's counts never appear in the target.
	if dst.scalar(`SELECT count(*) FROM usage_stats_hourly`) != 0 || src.scalar(`SELECT allowed_count FROM usage_stats_hourly`) != 7 {
		t.Fatal("usage scope")
	}
	if len(report.Excluded) == 0 || !contains([]byte(strings.Join(report.Excluded, ",")), "usage_statistics") {
		t.Fatal("report must name the excluded scope")
	}
}

// RESTORE-01/02/03: restore into the SAME live installation after local changes. Nothing is deleted,
// nothing old is revived, newer restrictions and revocations survive, and sessions are gone.
func TestRestoreOverALiveInstallationRetiresLocalAuthorityAndNeverRevivesAnything(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	raw := e.export(ModeFull)
	ep := e.text(`SELECT id FROM endpoints WHERE slug='local'`)

	// Local changes AFTER the backup: the token is revoked, a new DENY is added, a new user and a new token appear.
	e.exec(`UPDATE agent_credentials SET state='revoked',revoked_at=? WHERE id='cred-1'`, baseTime)
	e.exec(`INSERT INTO container_selectors(id,endpoint_id,container_name) VALUES('sel-new',?,'secret')`, ep)
	e.exec(`INSERT INTO policies(id,user_id,endpoint_id,selector_id,operation,effect,state,authority_generation) VALUES('pol-new-deny','alice',?,'sel-new','container:stop','DENY','active',1)`, ep)
	e.exec(`INSERT INTO users(id,username,state,mfa_requirement,credential_generation,authority_generation) VALUES('carol','carol','active','required',1,1)`)
	e.exec(`INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,nonexpiring_approved,credential_generation,state) VALUES('cred-2','bot',?,'mdt_new1',1999999500,2000999999,0,1,'active')`, bytes.Repeat([]byte{0xEE}, 32))
	usageBefore := e.scalar(`SELECT allowed_count FROM usage_stats_hourly`)
	before := e.controls()

	report := e.mustRestore(raw)

	after := e.controls()
	if after.RestoreQuarantined != 1 || after.CredentialGeneration != before.CredentialGeneration+1 || after.SessionGeneration != before.SessionGeneration+1 ||
		after.AuthorityGeneration != before.AuthorityGeneration+1 || after.RestoreGeneration != before.RestoreGeneration+1 {
		t.Fatalf("controls %+v -> %+v", before, after)
	}
	if e.activeAuthority() != 0 {
		t.Fatalf("%d records effective after a restore", e.activeAuthority())
	}
	// RESTORE-01: the token revoked after the backup stays revoked (final); the one issued after is revoked too.
	if e.text(`SELECT state FROM agent_credentials WHERE id='cred-1'`) != "revoked" || e.text(`SELECT state FROM agent_credentials WHERE id='cred-2'`) != "revoked" {
		t.Fatal("a token was revived or left active")
	}
	// RESTORE-03: the newer DENY is retained (quarantined DENY still blocks in the authorizer), not discarded.
	if e.text(`SELECT effect||'/'||state FROM policies WHERE id='pol-new-deny'`) != "DENY/quarantined" {
		t.Fatal("a newer DENY was discarded or weakened")
	}
	// Nothing was deleted: the local-only user is retained and queued for review, usage survived.
	if e.scalar(`SELECT count(*) FROM users WHERE id='carol' AND state='quarantined'`) != 1 || e.scalar(`SELECT allowed_count FROM usage_stats_hourly`) != usageBefore {
		t.Fatal("local-only record or usage lost")
	}
	if e.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != 0 || e.scalar(`SELECT count(*) FROM sessions WHERE id='sess-1' AND state='revoked'`) != 1 {
		t.Fatal("excluded sessions must be revoked, not carried")
	}
	if report.RetainedLocal["user"] != 1 || report.RetainedLocal["policy"] < 1 {
		t.Fatalf("retained local %+v", report.RetainedLocal)
	}
	if e.scalar(`SELECT count(*) FROM restore_manifest WHERE kind='user' AND item_id='carol' AND origin='local_retained'`) != 1 ||
		e.scalar(`SELECT count(*) FROM restore_manifest WHERE kind='user' AND item_id='alice' AND origin='imported'`) != 1 {
		t.Fatal("manifest origin classification")
	}
}

// RESTORE-03: an imported ALLOW cannot overwrite a local DENY that has the same id.
func TestAnImportedAllowNeverOverwritesALocalDenyForTheSameRule(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	raw := e.export(ModeFull) // pol-allow is an ALLOW here
	e.exec(`UPDATE policies SET effect='DENY' WHERE id='pol-allow'`)
	e.mustRestore(raw)
	if e.text(`SELECT effect||'/'||state FROM policies WHERE id='pol-allow'`) != "DENY/quarantined" {
		t.Fatal("the local DENY was replaced by the imported ALLOW")
	}
	if e.scalar(`SELECT count(*) FROM restore_manifest WHERE kind='policy' AND item_id='pol-allow' AND effective LIKE '%DENY%'`) != 1 {
		t.Fatal("manifest must show the retained DENY")
	}
}

func TestNameCollisionsRetireTheLocalRowInsteadOfFailingOrReusingIt(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	raw := src.export(ModeFull)
	dst := freshSameKey(t)
	dst.exec(`INSERT INTO users(id,username,state,mfa_requirement,credential_generation,authority_generation) VALUES('local-u','admin','active','required',1,1)`)
	dst.exec(`INSERT INTO groups(id,name,state,authority_generation) VALUES('local-g','ops','active',1)`)
	dst.mustRestore(raw)
	if dst.scalar(`SELECT count(*) FROM users WHERE id='adm' AND username='admin'`) != 1 || dst.scalar(`SELECT count(*) FROM users WHERE id='local-u' AND username LIKE 'admin~retired~%' AND state='quarantined'`) != 1 ||
		dst.scalar(`SELECT count(*) FROM groups WHERE id='local-g' AND name LIKE 'ops~retired~%'`) != 1 {
		t.Fatal("collisions")
	}
}

// RESTORE-11: the imported MFA requirement can strengthen but never weaken the accepted floor.
func TestAWeakerImportedSecuritySettingNeverBecomesEffective(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed() // alice is stored as 'optional'
	raw := src.export(ModeFull)
	dst := freshSameKey(t)
	dst.mustRestore(raw)
	if dst.text(`SELECT mfa_requirement FROM users WHERE id='alice'`) != "required" {
		t.Fatal("an imported optional MFA requirement became effective")
	}
	if dst.scalar(`SELECT count(*) FROM restore_manifest WHERE kind='user' AND item_id='alice' AND imported LIKE '%optional%' AND effective LIKE '%required%'`) != 1 {
		t.Fatal("the manifest must show imported-versus-effective")
	}
	// A stronger live setting is kept as well.
	live := newEnv(t, keyHexA)
	live.seed()
	live.exec(`UPDATE users SET mfa_requirement='webauthn' WHERE id='alice'`)
	live.mustRestore(raw)
	if live.text(`SELECT mfa_requirement FROM users WHERE id='alice'`) != "webauthn" {
		t.Fatal("a stronger local requirement was weakened")
	}
}

// RESTORE-04 (Phase 1 analogue: agent tokens carry expiry): historical expiry stays exactly as it was.
func TestHistoricalExpiryIsKeptAndNeverBecomesAFreshLifetime(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	src.exec(`INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,nonexpiring_approved,credential_generation,state) VALUES('cred-old','bot',?,'mdt_old1',1000,2000,0,1,'active')`, bytes.Repeat([]byte{0x01}, 32))
	src.exec(`INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,nonexpiring_approved,credential_generation,state) VALUES('cred-future','bot',?,'mdt_fut1',3000000000,3000100000,0,1,'active')`, bytes.Repeat([]byte{0x02}, 32))
	src.exec(`INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,nonexpiring_approved,credential_generation,state) VALUES('cred-forever','bot',?,'mdt_for1',1999999000,NULL,1,1,'active')`, bytes.Repeat([]byte{0x03}, 32))
	raw := src.export(ModeFull)
	dst := freshSameKey(t)
	dst.mustRestore(raw)
	for id, want := range map[string]string{"cred-old": "1000/2000", "cred-future": "3000000000/3000100000", "cred-forever": "1999999000/null"} {
		got := dst.text(`SELECT issued_at||'/'||coalesce(expires_at,'null') FROM agent_credentials WHERE id=?`, id)
		if got != want {
			t.Fatalf("%s timing %s, want %s", id, got, want)
		}
		if dst.text(`SELECT state FROM agent_credentials WHERE id=?`, id) != "quarantined" {
			t.Fatalf("%s must be inactive", id)
		}
	}
}

// New-key / clean mode: credentials and MFA are stripped; users, groups and rules arrive inactive.
func TestCleanRestoreOntoANewKeyStripsEveryCredentialAndIsAcknowledgedAsUnauthenticated(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	raw := src.export(ModeClean)
	dst := newEnv(t, keyHexB)
	if _, err := dst.restore(raw, InitiatorHost, false); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("no acknowledgement: %v", err)
	}
	report, err := dst.restore(raw, InitiatorHost, true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.CredentialsStripped || report.Provenance != ProvenanceUnauthenticated || report.Mode != ModeClean {
		t.Fatalf("report %+v", report)
	}
	for _, table := range []string{"authenticators", "agent_credentials", "webauthn_users", "webauthn_credentials"} {
		if dst.scalar(`SELECT count(*) FROM `+table) != 0 {
			t.Fatalf("%s must be empty after a clean restore", table)
		}
	}
	if dst.scalar(`SELECT count(*) FROM users`) != 2 || dst.scalar(`SELECT count(*) FROM policies WHERE state='quarantined'`) != 2 || dst.activeAuthority() != 0 {
		t.Fatal("clean restore records")
	}
}

// RESTORE-06: unauthorized initiators cannot trigger quarantine or any change.
func TestAnUnauthorizedInitiatorChangesNothingAndCannotTriggerQuarantine(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	raw := e.export(ModeFull)
	v := e.verify(raw)
	before, beforeControl := e.snapshot(), e.controls()
	if _, err := e.svc.Restore(t.Context(), v, RestoreOptions{Initiator: InitiatorAdmin, Authorize: refuse}); !errors.Is(err, ErrDenied) || Quarantined(err) {
		t.Fatalf("restore = %v", err)
	}
	e.sameExceptControl(before)
	if e.controls() != beforeControl {
		t.Fatal("an unauthorized restore entered quarantine")
	}
	for _, bad := range []RestoreOptions{{Initiator: InitiatorAdmin}, {Initiator: "root", Authorize: allow}, {Authorize: allow}} {
		if _, err := e.svc.Restore(t.Context(), v, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("options %+v: %v", bad, err)
		}
	}
	if e.controls() != beforeControl {
		t.Fatal("invalid options changed controls")
	}
}

// RESTORE-05: a failure or crash at each point after the transition leaves quarantine in place and no
// imported record. (SQLite's atomic commit is what a real process crash exercises; the seam fails the
// transaction at exactly that point.)
func TestAFailureAfterTheTransitionLeavesQuarantineAndNoPartialImport(t *testing.T) {
	for _, point := range []string{"restore:after-quarantine", "restore:after-import", "restore:before-commit"} {
		t.Run(point, func(t *testing.T) {
			src := newEnv(t, keyHexA)
			src.seed()
			raw := src.export(ModeFull)
			dst := freshSameKey(t)
			before := dst.snapshot()
			beforeControl := dst.controls()
			dst.svc.step = func(name string) error {
				if name == point {
					return errors.New("injected crash")
				}
				return nil
			}
			if _, err := dst.restore(raw, InitiatorHost, false); !errors.Is(err, ErrUnavailable) || !Quarantined(err) {
				t.Fatalf("restore = %v (quarantined %v)", err, Quarantined(err))
			}
			dst.sameExceptControl(before) // no archive record, report or manifest row
			c := dst.controls()
			if c.RestoreQuarantined != 1 || c.RestoreGeneration != beforeControl.RestoreGeneration+1 || c.AuthorityGeneration != beforeControl.AuthorityGeneration+1 {
				t.Fatalf("the transition must stay committed: %+v", c)
			}
			if dst.activeAuthority() != 0 {
				t.Fatal("authority is active after a failed restore")
			}
			// Recovery: the same archive restores cleanly afterwards.
			dst.svc.step = nil
			if _, err := dst.restore(raw, InitiatorHost, false); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if dst.scalar(`SELECT count(*) FROM users`) != 2 || dst.activeAuthority() != 0 {
				t.Fatal("retry result")
			}
		})
	}
}

// RESTORE-05/06: a REAL database failure in the middle of the import (a constraint raised by SQLite
// itself) rolls the whole import back: records written before the failure vanish.
func TestADatabaseFailureMidImportRollsEverythingBack(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	raw := src.export(ModeFull)
	dst := freshSameKey(t)
	dst.exec(`CREATE TRIGGER fail_policy_insert BEFORE INSERT ON policies BEGIN SELECT RAISE(ABORT,'synthetic constraint failure'); END`)
	before := dst.snapshot()
	if _, err := dst.restore(raw, InitiatorHost, false); !errors.Is(err, ErrUnavailable) || !Quarantined(err) {
		t.Fatalf("restore = %v", err)
	}
	dst.sameExceptControl(before)
	if dst.scalar(`SELECT count(*) FROM users`) != 0 || dst.scalar(`SELECT count(*) FROM restore_reports`) != 0 {
		t.Fatal("records written before the failure survived")
	}
	if dst.controls().RestoreQuarantined != 1 {
		t.Fatal("quarantine must remain")
	}
}

// The post-import integrity check is a second, independent defence: if an imported record could ever
// be effective, the restore refuses to commit. Here a trigger turns one quarantined row active.
func TestThePostRestoreIntegrityCheckRefusesToCommitAnEffectiveRecord(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	raw := src.export(ModeFull)
	dst := freshSameKey(t)
	dst.exec(`CREATE TRIGGER sneaky AFTER INSERT ON groups BEGIN UPDATE groups SET state='active',authority_generation=1 WHERE id=NEW.id; END`)
	before := dst.snapshot()
	if _, err := dst.restore(raw, InitiatorHost, false); !errors.Is(err, ErrConsistency) || !Quarantined(err) {
		t.Fatalf("restore = %v, want ErrConsistency after quarantine", err)
	}
	dst.sameExceptControl(before)
}

// RESTORE-05: competing and repeated restores never leave a partial or active state.
func TestParallelRestoresLeaveOneConsistentInactiveState(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	raw := src.export(ModeFull)
	dst := freshSameKey(t)
	const n = 6
	var wg sync.WaitGroup
	var ok, superseded, other atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := dst.svc.Verify(raw)
			if err != nil {
				other.Add(1)
				return
			}
			_, err = dst.svc.Restore(context.Background(), v, RestoreOptions{Initiator: InitiatorHost, Authorize: allow})
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrSuperseded):
				superseded.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() < 1 || other.Load() != 0 {
		t.Fatalf("ok=%d superseded=%d other=%d", ok.Load(), superseded.Load(), other.Load())
	}
	c := dst.controls()
	if c.RestoreQuarantined != 1 || c.RestoreGeneration != n || dst.activeAuthority() != 0 {
		t.Fatalf("final controls %+v active=%d", c, dst.activeAuthority())
	}
	// The newest report is the last generation, and the data is exactly one consistent import.
	if dst.scalar(`SELECT max(restore_generation) FROM restore_reports`) != c.RestoreGeneration || dst.scalar(`SELECT count(*) FROM users`) != 2 || dst.scalar(`SELECT count(*) FROM policies`) != 2 {
		t.Fatal("inconsistent final state")
	}
}

// RESTORE-05: a restore whose transition was overtaken by a newer restore applies nothing. Deterministic
// interleaving: restore A commits its transition, restore B runs to completion, then A reaches its import.
func TestARestoreOvertakenByANewerOneAppliesNothing(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	older := src.export(ModeFull)
	src.exec(`INSERT INTO users(id,username,state,mfa_requirement,credential_generation,authority_generation) VALUES('carol','carol','active','required',1,1)`)
	newer := src.export(ModeFull)
	dst := freshSameKey(t)
	done := false
	dst.svc.step = func(name string) error {
		if name == "restore:after-quarantine" && !done {
			done = true
			if _, err := dst.restore(newer, InitiatorHost, false); err != nil { // B: transition and import both commit
				return err
			}
		}
		return nil
	}
	_, err := dst.restore(older, InitiatorHost, false)
	if !errors.Is(err, ErrSuperseded) || !Quarantined(err) {
		t.Fatalf("overtaken restore = %v", err)
	}
	// Only B's import is present: three users (adm, alice, carol), B's generation and report.
	if dst.scalar(`SELECT count(*) FROM users`) != 3 || dst.scalar(`SELECT count(*) FROM restore_reports`) != 1 || dst.scalar(`SELECT max(restore_generation) FROM restore_reports`) != 2 {
		t.Fatal("the overtaken restore changed the data")
	}
	if c := dst.controls(); c.RestoreQuarantined != 1 || c.RestoreGeneration != 2 || dst.activeAuthority() != 0 {
		t.Fatalf("controls %+v", c)
	}
}

// RESTORE-06 / admin path: after the first restore the initiator's session no longer authorizes, so a
// second request from the same administrator is denied by the in-transaction check.
func TestACompetingAdministratorRequestIsDeniedByTheInTransactionCheck(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	raw := e.export(ModeFull)
	var calls atomic.Int32
	authorize := func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		if c.RestoreQuarantined != 0 || calls.Add(1) > 1 {
			return errors.New("session no longer valid")
		}
		return nil
	}
	v := e.verify(raw)
	if _, err := e.svc.Restore(t.Context(), v, RestoreOptions{Initiator: InitiatorAdmin, Authorize: authorize}); err != nil {
		t.Fatal(err)
	}
	g := e.controls().RestoreGeneration
	if _, err := e.svc.Restore(t.Context(), v, RestoreOptions{Initiator: InitiatorAdmin, Authorize: authorize}); !errors.Is(err, ErrDenied) {
		t.Fatalf("second restore = %v", err)
	}
	if e.controls().RestoreGeneration != g {
		t.Fatal("the denied second restore advanced the generation")
	}
}

// Quarantine and the generations are durable: closing and reopening the repository changes nothing.
func TestQuarantinePersistsAcrossReopen(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	e.mustRestore(e.export(ModeFull))
	want := e.controls()
	if err := e.repo.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := store.LoadMasterKey(keyHexA, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := store.Open(t.Context(), store.Options{DataDir: e.dir, MasterKey: key, OwnerUID: osUID(), OwnerGID: osGID(), ExistingOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()
	var got store.InstallationControl
	if err := repo.Read(t.Context(), func(q *store.Queries) error {
		var err error
		got, err = q.GetInstallationControl(t.Context())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got != want || got.RestoreQuarantined != 1 {
		t.Fatalf("after reopen %+v, want %+v", got, want)
	}
	if err := repo.ReadActive(t.Context(), store.Generations{Credential: got.CredentialGeneration, Session: got.SessionGeneration, Authority: got.AuthorityGeneration, Restore: got.RestoreGeneration}, func(*store.Queries) error { return nil }); err == nil {
		t.Fatal("ReadActive must deny while quarantined")
	}
}

// The export surface never reads restore control state: exporting after a restore and an approval
// cannot carry the manifest, report or any generation (RESTORE-11, S2.2.1).
func TestRestoreControlStateIsNotPartOfAnyExportSurface(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	e.mustRestore(e.export(ModeFull))
	e.leaveQuarantine()
	raw := e.export(ModeFull)
	for _, forbidden := range []string{"restore_manifest", "restore_reports", "restore_generation", "local_retained", "decision", "installation_control", "host_recovery_required"} {
		if contains(raw, forbidden) {
			t.Fatalf("export carries %q", forbidden)
		}
	}
	// Archive-claimed state is informational: re-importing an archive whose records said "active"
	// still produces inactive records (source_state is displayed, never applied).
	var a Archive
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	e.mustRestore(raw)
	if e.activeAuthority() != 0 {
		t.Fatal("source_state was applied")
	}
}
