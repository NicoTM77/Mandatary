package auth

import (
	"bytes"
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Terminal is the host-side output boundary of the reveal protocol. The secret
// bypasses slog entirely and is written only through WriteSecret.
type Terminal interface {
	// Verify proves stdin, stdout and stderr are the same real controlling
	// terminal (no pipe, file or redirection). It is called BEFORE any claim or
	// plaintext access; a refusal emits nothing and consumes nothing.
	Verify() error
	// WriteSecret performs ONE bounded write. A failed, stalled or partial write
	// is uncertain delivery and leaves the generation permanently non-revealable.
	WriteSecret(ctx context.Context, data []byte) error
}

// RevealResult is the secret-free outcome of a successful reveal.
type RevealResult struct {
	Generation int64
	Purpose    SetupPurpose
	ExpiresAt  time.Time
}

// findLive returns the single live generation of purpose/target, if any.
func findLive(ctx context.Context, q *store.Queries, purpose SetupPurpose, target sql.NullString) (store.SetupToken, bool, error) {
	tokens, err := q.ListLiveSetupTokens(ctx)
	if err != nil {
		return store.SetupToken{}, false, err
	}
	for _, tok := range tokens {
		if sameTarget(tok, purpose, target) {
			return tok, true, nil
		}
	}
	return store.SetupToken{}, false, nil
}

// resolveTarget applies the purpose-specific authorization of an issuance/reveal
// target. Initial setup needs an eligible empty store; an MFA reset needs an
// existing active account and an unlocked installation (never an ordinary login).
func resolveTarget(ctx context.Context, q *store.Queries, purpose SetupPurpose, username string) (sql.NullString, error) {
	switch purpose {
	case PurposeInitialSetup:
		if username != "" {
			return sql.NullString{}, errSetupLogical
		}
		return sql.NullString{}, setupEligible(ctx, q)
	case PurposeMFAReset:
		c, err := q.GetInstallationControl(ctx)
		if err != nil {
			return sql.NullString{}, err
		}
		u, err := q.GetUserByUsername(ctx, username)
		if isNoRows(err) {
			return sql.NullString{}, errSetupLogical
		}
		if err != nil {
			return sql.NullString{}, err
		}
		if !activeControl(c) || u.State != "active" || u.MfaRequirement == "webauthn" {
			return sql.NullString{}, errSetupLogical
		}
		if ok, err := isActiveAdministrator(ctx, q, u.ID); err != nil {
			return sql.NullString{}, err
		} else if !ok {
			return sql.NullString{}, errSetupLogical
		}
		return nullStr(u.ID), nil
	default:
		return sql.NullString{}, errSetupLogical
	}
}

// isActiveAdministrator scopes host-local MFA reset: it exists to recover the
// installation's administrator, not an arbitrary account.
func isActiveAdministrator(ctx context.Context, q *store.Queries, userID string) (bool, error) {
	roles, err := q.ListUserAdministrativeRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Role == "super_admin" && r.State == "active" {
			return true, nil
		}
	}
	return false, nil
}

// Reveal implements the S3.1a host reveal under ONE shared-lock acquisition:
//
//  1. verify the terminal (nothing claimed yet, no plaintext touched);
//  2. under the lock: purpose/target, eligibility, AVAILABLE, unexpired UTC,
//     installation + build identity, and the reveal file's safety metadata;
//  3. durably CLAIM before any output;
//  4. read the file, verify it against the stored digest and generation, recheck
//     expiry, write ONCE to the terminal, unlink, sync the directory;
//  5. durably record RETRIEVED, then release the lock.
//
// Any failure after step 3 leaves the generation CLAIMED: it is never revealable
// again, even if the plaintext file survives, and Reconcile revokes it (explicit
// host rotation is then required). Crash after output but before step 5 is
// uncertain human receipt, not exactly-once delivery.
func (s *Setup) Reveal(ctx context.Context, purpose SetupPurpose, username string, term Terminal) (RevealResult, error) {
	if term == nil || !purpose.valid() {
		return RevealResult{}, ErrSetupDenied
	}
	if err := term.Verify(); err != nil {
		return RevealResult{}, ErrSetupDenied
	}
	var (
		tok       store.SetupToken
		claimedAt int64
		logical   bool
	)
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := s.repo.ControlThen(bounded, func(q *store.Queries) error {
		fail := func(e error) error {
			logical = e == errSetupLogical
			return e
		}
		now := s.now().Unix()
		if e := setupClock(bounded, q, now); e != nil {
			return fail(e)
		}
		target, e := resolveTarget(bounded, q, purpose, username)
		if e != nil {
			return fail(e)
		}
		found, ok, e := findLive(bounded, q, purpose, target)
		if e != nil {
			return e
		}
		if !ok || found.State != "available" || now >= found.ExpiresAt {
			return fail(errSetupLogical)
		}
		meta, e := q.GetRepositoryMetadata(bounded)
		if e != nil {
			return e
		}
		if !bytes.Equal(meta.InstallationID, found.InstallationID) || found.BuildIdentity != s.settings.Build {
			return fail(errSetupLogical)
		}
		// Unsafe layout is refused BEFORE the claim: nothing is consumed.
		if e = s.repo.RevealFileCheck(revealFileName(found.Purpose, found.ID)); e != nil {
			return e
		}
		if e = s.step("reveal:before-claim"); e != nil {
			return e
		}
		n, e := q.ClaimSetupToken(bounded, store.ClaimSetupTokenParams{Now: nullableInt(now), ID: found.ID})
		if e != nil {
			return e
		}
		if n != 1 {
			return fail(errSetupLogical)
		}
		tok, claimedAt = found, now
		return nil
	}, func() error {
		// The CLAIMED state is durable. Plaintext may now be read, once.
		if e := s.step("reveal:after-claim"); e != nil {
			return e
		}
		name := revealFileName(tok.Purpose, tok.ID)
		data, e := s.repo.RevealFileRead(name)
		if e != nil {
			return e
		}
		defer clear(data)
		// Once claimed, the generation can never be shown again, so the plaintext
		// has no remaining legitimate use: on ANY failure from here remove it now
		// (best effort; Reconcile removes anything left) rather than let it linger.
		scrub := func(e error) error {
			_ = s.repo.RevealFileRemove(name)
			return e
		}
		generation, filePurpose, canonical, ok := parseReveal(data)
		if !ok || generation != tok.ID || string(filePurpose) != tok.Purpose || !digestEqual(setupDigest(SetupPurpose(tok.Purpose), canonical), tok.Digest) {
			return scrub(ErrSetupDenied)
		}
		defer clear(canonical)
		// Final expiry/clock recheck under the same lock, immediately before output.
		if now := s.now().Unix(); now >= tok.ExpiresAt || now < claimedAt {
			return scrub(ErrSetupDenied)
		}
		payload := revealPayload(tok, username, canonical)
		defer clear(payload)
		if e = s.step("reveal:before-output"); e != nil {
			return scrub(e)
		}
		if e = term.WriteSecret(bounded, payload); e != nil {
			return scrub(e)
		}
		if e = s.step("reveal:after-output"); e != nil {
			return e
		}
		if e = s.repo.RevealFileRemove(name); e != nil {
			return e
		}
		return s.step("reveal:after-unlink")
	}, func(q *store.Queries) error {
		now := s.now().Unix()
		if now < claimedAt {
			now = claimedAt
		}
		n, e := q.FinishSetupTokenReveal(bounded, store.FinishSetupTokenRevealParams{Now: nullableInt(now), ID: tok.ID})
		if e != nil || n != 1 {
			return ErrSetupDenied
		}
		return nil
	})
	if err != nil {
		return RevealResult{}, classify(err, logical)
	}
	return RevealResult{Generation: tok.ID, Purpose: SetupPurpose(tok.Purpose), ExpiresAt: time.Unix(tok.ExpiresAt, 0).UTC()}, nil
}

func revealPayload(tok store.SetupToken, username string, canonical []byte) []byte {
	label := "initial setup"
	if SetupPurpose(tok.Purpose) == PurposeMFAReset {
		label = "MFA reset for " + username
	}
	out := []byte("Mandatary " + label + " token, generation " + strconv.FormatInt(tok.ID, 10) + "\n")
	out = append(out, []byte("Valid until "+time.Unix(tok.ExpiresAt, 0).UTC().Format(time.RFC3339)+" (absolute; retrieval and restarts never extend it)\n\n")...)
	out = append(out, groupedToken(canonical)...)
	return append(out, []byte("\n\nEnter it manually in the protected setup form. It is shown once and cannot be displayed again.\n")...)
}
