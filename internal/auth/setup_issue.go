package auth

import (
	"bytes"
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// TokenStatus is the redacted view of one generation: never the token or digest.
type TokenStatus struct {
	Generation      int64
	Purpose         SetupPurpose
	State           string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Expired         bool
	TargetUser      string // username of an mfa_reset target; empty otherwise
	ReplacePassword bool
	RevokeReason    string
}

// SetupStatus is what operators and startup logging may learn. Redacted by design.
type SetupStatus struct {
	Eligible       bool
	Completed      bool
	MailConfigured bool
	Tokens         []TokenStatus
	LiveSessions   int
}

// IssueRequest asks for a new generation. Issuing always revokes the previous live
// generation of the same purpose/target (and its enrollment sessions) first.
type IssueRequest struct {
	Purpose SetupPurpose
	// Username/ReplacePassword/RiskAcknowledged apply to mfa_reset only. The
	// acknowledgement records the operator's acceptance of the documented
	// all-factors-lost host-recovery risk (S3.2, NIST D-04).
	Username         string
	ReplacePassword  bool
	RiskAcknowledged bool
}

func revealContent(generation int64, purpose SetupPurpose, token []byte) []byte {
	out := []byte(setupRevealHeader + "\n" + strconv.FormatInt(generation, 10) + "\n" + string(purpose) + "\n")
	out = append(out, token...)
	return append(out, '\n')
}

// parseReveal accepts only the exact four-line format bound to a generation.
func parseReveal(data []byte) (generation int64, purpose SetupPurpose, token []byte, ok bool) {
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != 4 || string(lines[0]) != setupRevealHeader {
		return 0, "", nil, false
	}
	g, err := strconv.ParseInt(string(lines[1]), 10, 64)
	if err != nil || g <= 0 || len(lines[3]) != setupTokenChars {
		return 0, "", nil, false
	}
	p := SetupPurpose(lines[2])
	if !p.valid() {
		return 0, "", nil, false
	}
	canonical, valid := canonicalToken(string(lines[3]))
	if !valid || len(canonical) != setupTokenChars {
		return 0, "", nil, false
	}
	return g, p, canonical, true
}

func sameTarget(tok store.SetupToken, purpose SetupPurpose, target sql.NullString) bool {
	return SetupPurpose(tok.Purpose) == purpose && tok.TargetUserID == target
}

// endSession durably ends a live setup session and removes every inert staged
// record it still owns, in foreign-key-safe order. Nothing staged ever carried
// authority (all rows are quarantined/pending), so removal frees the reserved
// username and addresses without touching any active record.
func endSession(ctx context.Context, q *store.Queries, sess store.SetupSession, now int64, to string) error {
	n, err := q.EndSetupSession(ctx, store.EndSetupSessionParams{ToState: to, Now: nullableInt(now), ID: sess.ID})
	if err != nil {
		return err
	}
	if n != 1 {
		return errSetupLogical
	}
	if to == "completed" {
		return nil
	}
	return purgeStaging(ctx, q, sess)
}

func nullableInt(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }

func purgeStaging(ctx context.Context, q *store.Queries, sess store.SetupSession) error {
	if err := q.ClearSetupStaging(ctx, sess.ID); err != nil {
		return err
	}
	if sess.TotpAuthenticatorID.Valid {
		if err := q.PurgeSetupTOTPAcceptances(ctx, sess.TotpAuthenticatorID.String); err != nil {
			return err
		}
		if err := q.PurgeSetupTOTP(ctx, sess.TotpAuthenticatorID.String); err != nil {
			return err
		}
	}
	if sess.StagedUserID.Valid {
		uid := sess.StagedUserID.String
		for _, purge := range []func(context.Context, string) error{q.PurgeStagedProofs, q.PurgeStagedAddresses} {
			if err := purge(ctx, uid); err != nil {
				return err
			}
		}
		if _, err := q.PurgeStagedUser(ctx, uid); err != nil {
			return err
		}
	}
	return nil
}

// revokeLive revokes every live generation (and session) matching purpose/target.
// It returns the reveal-file names the caller must remove after the commit.
func revokeLive(ctx context.Context, q *store.Queries, purpose SetupPurpose, target sql.NullString, now int64, reason string) ([]string, error) {
	var removals []string
	tokens, err := q.ListLiveSetupGenerations(ctx)
	if err != nil {
		return nil, err
	}
	for _, tok := range tokens {
		if !sameTarget(tok, purpose, target) {
			continue
		}
		n, err := q.RevokeSetupGeneration(ctx, store.RevokeSetupGenerationParams{Now: nullableInt(now), Reason: reason, ID: tok.ID})
		if err != nil {
			return nil, err
		}
		if n != 1 {
			return nil, errSetupLogical
		}
		removals = append(removals, revealFileName(tok.Purpose, tok.ID))
	}
	sessions, err := q.ListLiveSetupSessions(ctx)
	if err != nil {
		return nil, err
	}
	for _, sess := range sessions {
		if SetupPurpose(sess.Purpose) == purpose && sess.TargetUserID == target {
			if err := endSession(ctx, q, sess, now, "revoked"); err != nil {
				return nil, err
			}
		}
	}
	return removals, nil
}

// Issue starts a new explicit generation (host rotation / MFA-reset issuance).
func (s *Setup) Issue(ctx context.Context, req IssueRequest) (TokenStatus, error) {
	return s.issue(ctx, req, false)
}

func (s *Setup) issue(ctx context.Context, req IssueRequest, automatic bool) (TokenStatus, error) {
	if !req.Purpose.valid() {
		return TokenStatus{}, ErrSetupDenied
	}
	token, err := s.newToken()
	if err != nil {
		return TokenStatus{}, err
	}
	defer clear(token)
	digest := setupDigest(req.Purpose, token)
	var (
		generation int64
		expires    int64
		issued     int64
		target     sql.NullString
		removals   []string
	)
	logical := false
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err = s.repo.ControlThen(bounded, func(q *store.Queries) error {
		fail := func(e error) error {
			logical = e == errSetupLogical
			return e
		}
		now := s.now().Unix()
		if e := setupClock(bounded, q, now); e != nil {
			return fail(e)
		}
		c, e := q.GetInstallationControl(bounded)
		if e != nil {
			return e
		}
		switch req.Purpose {
		case PurposeInitialSetup:
			if req.Username != "" || req.ReplacePassword || req.RiskAcknowledged {
				return fail(errSetupLogical)
			}
			if e = setupEligible(bounded, q); e != nil {
				return fail(e)
			}
			if automatic {
				st, e := q.GetSetupState(bounded)
				if e != nil {
					return e
				}
				if st.InitialIssued != 0 {
					return fail(errSetupLogical) // a restart never mints a fresh token
				}
			}
		case PurposeMFAReset:
			if !req.RiskAcknowledged || req.Username == "" || automatic {
				return fail(errSetupLogical)
			}
			user, e := q.GetUserByUsername(bounded, req.Username)
			if isNoRows(e) {
				return fail(errSetupLogical)
			}
			if e != nil {
				return e
			}
			// WebAuthn-only accounts are refused: a TOTP continuation must never
			// erase that policy, and WebAuthn re-enrollment is not part of this
			// ceremony. Compromised accounts must replace the password too.
			if !activeControl(c) || user.State != "active" || user.MfaRequirement == "webauthn" || (user.Compromised != 0 && !req.ReplacePassword) {
				return fail(errSetupLogical)
			}
			if ok, e := isActiveAdministrator(bounded, q, user.ID); e != nil {
				return e
			} else if !ok {
				return fail(errSetupLogical)
			}
			target = nullStr(user.ID)
			// Before issuance (S3.2), in this same transaction: end the account's
			// browser sessions and durably retire every old second factor, saved
			// code and recovery capability. Nothing issued before the ceremony can
			// authenticate or start a recovery during it. An abandoned or expired
			// ceremony is recovered only by explicit host re-issuance.
			if e = q.RevokeUserSessions(bounded, store.RevokeUserSessionsParams{UserID: user.ID, Now: nullableInt(now)}); e != nil {
				return e
			}
			if e = retireUserCredentials(bounded, q, user.ID, "", retireProtective, now); e != nil {
				return e
			}
		default:
			// Restore-quarantine administrator recovery is delivered with the restore
			// service (P1.18). Until then no token of that purpose can be issued.
			return fail(errSetupLogical)
		}
		removals, e = revokeLive(bounded, q, req.Purpose, target, now, "rotated")
		if e != nil {
			return fail(e)
		}
		if e = q.ResetSetupAttempts(bounded, string(req.Purpose)); e != nil {
			return e
		}
		meta, e := q.GetRepositoryMetadata(bounded)
		if e != nil {
			return e
		}
		issued, expires = now, now+int64(SetupTokenLifetime/time.Second)
		generation, e = q.CreateSetupGeneration(bounded, store.CreateSetupGenerationParams{
			Purpose: string(req.Purpose), TargetUserID: target, InstallationID: meta.InstallationID, BuildIdentity: s.settings.Build,
			Digest: digest, IssuedAt: issued, ExpiresAt: expires, ReplacePassword: boolInt(req.ReplacePassword), RiskAcknowledged: boolInt(req.RiskAcknowledged),
		})
		if e != nil {
			return e
		}
		if req.Purpose == PurposeInitialSetup {
			return q.MarkInitialSetupIssued(bounded)
		}
		return nil
	}, func() error {
		// Durable PENDING state exists. Now (still under the shared lock) remove the
		// superseded plaintext and create the new generation-bound file.
		for _, name := range removals {
			if e := s.repo.RevealFileRemove(name); e != nil {
				return e
			}
		}
		if e := s.step("issue:before-file"); e != nil {
			return e
		}
		if e := s.repo.RevealFileWrite(revealFileName(string(req.Purpose), generation), revealContent(generation, req.Purpose, token)); e != nil {
			return e
		}
		return s.step("issue:after-file")
	}, func(q *store.Queries) error {
		n, e := q.MakeSetupGenerationAvailable(bounded, generation)
		if e != nil {
			return e
		}
		if n != 1 {
			return errSetupLogical
		}
		return nil
	})
	if err != nil {
		return TokenStatus{}, classify(err, logical)
	}
	status := TokenStatus{Generation: generation, Purpose: req.Purpose, State: "available", IssuedAt: time.Unix(issued, 0).UTC(), ExpiresAt: time.Unix(expires, 0).UTC(), ReplacePassword: req.ReplacePassword, TargetUser: req.Username}
	return status, nil
}

// retireUserCredentials durably retires every second factor, saved code, code
// batch and restricted recovery capability of one account except keep (the
// factor proven in the current ceremony, "" for none). At MFA-reset issuance it
// runs with the protective provenance, so a retired factor can never lower the
// account's assurance floor; completion settles it. Nothing here is reversed:
// an abandoned ceremony is recovered only by explicit host re-issuance.
func retireUserCredentials(ctx context.Context, q *store.Queries, userID, keep, reason string, now int64) error {
	factors, err := q.ListUserAuthenticators(ctx, userID)
	if err != nil {
		return err
	}
	for _, f := range factors {
		if f.ID == keep || f.RevokedAt.Valid {
			continue
		}
		switch f.Kind {
		case "totp":
			_, err = q.RevokeTOTP(ctx, store.RevokeTOTPParams{ID: f.ID, Now: nullableInt(now), Reason: reason})
		case "webauthn":
			_, err = q.RevokeWebAuthn(ctx, store.RevokeWebAuthnParams{ID: f.ID, Now: nullableInt(now), Reason: reason})
		}
		if err != nil {
			return err
		}
	}
	if err = q.RevokeRecoveryCodes(ctx, store.RevokeRecoveryCodesParams{Now: nullableInt(now), UserID: userID}); err != nil {
		return err
	}
	if err = q.RevokeRecoveryBatches(ctx, userID); err != nil {
		return err
	}
	return q.RevokeRecoveryCapabilities(ctx, userID)
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ReconcileReport counts only; it carries no secret and no identifier.
type ReconcileReport struct {
	TokensRevoked   int
	SessionsEnded   int
	FilesRemoved    int
	FilesInspected  int
	CrashedIssues   int
	UncertainClaims int
}

// Reconcile restores a consistent, conservative state after a crash or expiry
// (S3.1a). It never reveals, issues or extends anything:
//   - PENDING (crashed issue) and CLAIMED (uncertain delivery) generations are
//     revoked; they require explicit host rotation;
//   - generations past their absolute expiry are revoked and their sessions end;
//   - every reveal file that does not belong to a live, unexpired AVAILABLE
//     generation is removed; unexpected directory content fails closed.
func (s *Setup) Reconcile(ctx context.Context) (ReconcileReport, error) {
	var report ReconcileReport
	var removals []string
	err := s.run(ctx, func(ctx context.Context, q *store.Queries, now int64) error {
		report, removals = ReconcileReport{}, nil
		tokens, e := q.ListLiveSetupGenerations(ctx)
		if e != nil {
			return e
		}
		keep := map[string]bool{}
		for _, tok := range tokens {
			reason := ""
			switch tok.State {
			case "pending":
				reason = "crashed_issue"
				report.CrashedIssues++
			case "claimed":
				reason = "uncertain_delivery"
				report.UncertainClaims++
			case "available", "retrieved":
				if now >= tok.ExpiresAt {
					reason = "expired_cleanup"
				}
			}
			if reason != "" {
				n, e := q.RevokeSetupGeneration(ctx, store.RevokeSetupGenerationParams{Now: nullableInt(now), Reason: reason, ID: tok.ID})
				if e != nil {
					return e
				}
				if n != 1 {
					return errSetupLogical
				}
				report.TokensRevoked++
				continue
			}
			if tok.State == "available" {
				keep[revealFileName(tok.Purpose, tok.ID)] = true
			}
		}
		sessions, e := q.ListLiveSetupSessions(ctx)
		if e != nil {
			return e
		}
		for _, sess := range sessions {
			if now >= sess.ExpiresAt {
				if e = endSession(ctx, q, sess, now, "revoked"); e != nil {
					return e
				}
				report.SessionsEnded++
			}
		}
		names, e := s.repo.RevealFileNames()
		if e != nil {
			return e
		}
		report.FilesInspected = len(names)
		for _, name := range names {
			if !keep[name] {
				removals = append(removals, name)
			}
		}
		// Tokens revoked above may still have had files not listed (already gone).
		return nil
	}, func() error {
		for _, name := range removals {
			if e := s.repo.RevealFileRemove(name); e != nil {
				return e
			}
			report.FilesRemoved++
		}
		return nil
	})
	return report, err
}

// EnsureResult describes the first-start decision without any secret.
type EnsureResult struct {
	// Outcome is one of: "issued" (first generation created now), "active" (a live
	// unexpired generation exists), "rotation_required" (setup is open but no live
	// generation exists; explicit host rotation is needed), "ineligible" (not an
	// empty store or already set up: no setup surface exists).
	Outcome string
	Token   TokenStatus
}

// EnsureInitial runs at service start. It reconciles, then issues the FIRST
// initial-setup generation if and only if the store is eligible and no generation
// was ever issued. It never mints a token on restart, after expiry, or on
// missing/corrupt/migration-error state (those fail Reconcile/eligibility).
func (s *Setup) EnsureInitial(ctx context.Context) (EnsureResult, error) {
	if _, err := s.Reconcile(ctx); err != nil {
		return EnsureResult{}, err
	}
	status, err := s.Status(ctx)
	if err != nil {
		return EnsureResult{}, err
	}
	if !status.Eligible {
		return EnsureResult{Outcome: "ineligible"}, nil
	}
	for _, t := range status.Tokens {
		if t.Purpose == PurposeInitialSetup && !t.Expired && (t.State == "available" || t.State == "retrieved") {
			return EnsureResult{Outcome: "active", Token: t}, nil
		}
	}
	var issuedBefore bool
	for _, t := range status.Tokens {
		if t.Purpose == PurposeInitialSetup {
			issuedBefore = true
		}
	}
	if !issuedBefore {
		// Tokens list is bounded to the most recent rows; consult the durable flag.
		if err = s.repo.Read(ctx, func(q *store.Queries) error {
			st, e := q.GetSetupState(ctx)
			issuedBefore = st.InitialIssued != 0
			return e
		}); err != nil {
			return EnsureResult{}, ErrSetupUnavailable
		}
	}
	if issuedBefore {
		return EnsureResult{Outcome: "rotation_required"}, nil
	}
	token, err := s.issue(ctx, IssueRequest{Purpose: PurposeInitialSetup}, true)
	if err != nil {
		return EnsureResult{}, err
	}
	return EnsureResult{Outcome: "issued", Token: token}, nil
}

// Status is read-only and redacted.
func (s *Setup) Status(ctx context.Context) (SetupStatus, error) {
	var out SetupStatus
	err := s.repo.Read(ctx, func(q *store.Queries) error {
		out = SetupStatus{MailConfigured: s.l != nil && s.sendProof != nil}
		now := s.now().Unix()
		if clockReadable(ctx, q, now) == nil && setupEligible(ctx, q) == nil {
			out.Eligible = true
		}
		st, e := q.GetSetupState(ctx)
		if e != nil {
			return e
		}
		out.Completed = st.CompletedAt.Valid
		rows, e := q.ListRecentSetupGenerations(ctx)
		if e != nil {
			return e
		}
		for _, tok := range rows {
			ts := TokenStatus{Generation: tok.ID, Purpose: SetupPurpose(tok.Purpose), State: tok.State, IssuedAt: time.Unix(tok.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(tok.ExpiresAt, 0).UTC(), Expired: now >= tok.ExpiresAt, ReplacePassword: tok.ReplacePassword == 1, RevokeReason: tok.RevokeReason.String}
			if tok.TargetUserID.Valid {
				if u, e := q.GetUser(ctx, tok.TargetUserID.String); e == nil {
					ts.TargetUser = u.Username
				}
			}
			out.Tokens = append(out.Tokens, ts)
		}
		live, e := q.ListLiveSetupSessions(ctx)
		out.LiveSessions = len(live)
		return e
	})
	if err != nil {
		return SetupStatus{}, ErrSetupUnavailable
	}
	return out, nil
}
