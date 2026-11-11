package auth

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// SetupSessionInfo is the secret-free view of a setup/recovery-only session. It
// has no assurance, methods or authentication time: it is not an authenticated
// session of any strength and is never accepted by the normal session verifier.
type SetupSessionInfo struct {
	ID              string
	Purpose         SetupPurpose
	ExpiresAt       time.Time
	ReplacePassword bool
	TargetUser      string
	AccountStaged   bool
	TOTPBegun       bool
	TOTPProven      bool
	Addresses       []SetupAddress
	MailConfigured  bool
}

// SetupAddress is a staged notification address and whether control was proven.
type SetupAddress struct {
	ID        string
	Address   string
	Confirmed bool
}

// SetupSession carries the opaque cookie secret. Formatting/logging are redacted.
type SetupSession struct {
	SetupSessionInfo
	secret []byte
}

func (SetupSession) String() string   { return "SetupSession{[REDACTED]}" }
func (SetupSession) GoString() string { return "SetupSession{[REDACTED]}" }
func (s SetupSession) LogValue() slog.Value {
	return slog.GroupValue(slog.String("session_id", s.ID), slog.String("secret", "[REDACTED]"))
}

// Secret returns a copy of the cookie secret (the HTTP adapter and tests).
func (s SetupSession) Secret() []byte { return append([]byte(nil), s.secret...) }

// CSRFToken is server-derived per session, exactly like the normal browser layer.
func (s SetupSession) CSRFToken() string { return csrfToken(s.secret, s.ID) }

// revokePurpose revokes every live generation of a purpose, whatever its target,
// and ends the matching sessions. Used when a guessing campaign hits the ceiling.
func revokePurpose(ctx context.Context, q *store.Queries, purpose SetupPurpose, now int64, reason string) ([]string, error) {
	tokens, err := q.ListLiveSetupTokens(ctx)
	if err != nil {
		return nil, err
	}
	var removals []string
	for _, tok := range tokens {
		if SetupPurpose(tok.Purpose) != purpose {
			continue
		}
		n, err := q.RevokeSetupToken(ctx, store.RevokeSetupTokenParams{Now: nullableInt(now), Reason: reason, ID: tok.ID})
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
		if SetupPurpose(sess.Purpose) == purpose {
			if err := endSession(ctx, q, sess, now, "revoked"); err != nil {
				return nil, err
			}
		}
	}
	return removals, nil
}

// Exchange is the one-use token POST (SETUP-05). Inside ONE shared-lock control
// transaction it checks the durable failed-guess backoff, matches the digest
// against the consistent RETRIEVED generation only, checks absolute expiry, and
// atomically commits (a) consumption, (b) exactly one setup-only session and
// (c) counter reset; or the failed-attempt update. token_id UNIQUE makes a second
// session for one token impossible even if the lock protocol were bypassed.
// Residual plaintext is removed before success is reported. A crash after the
// commit neither replays the consumption nor mints a second session; a lost
// session response needs explicit host rotation.
//
// ip is the validated peer address, never a forwarded header. Malformed tokens
// and rate-limited requests are rejected before evaluation and are not guesses.
func (s *Setup) Exchange(ctx context.Context, token, ip string) (SetupSession, error) {
	if !s.gate.allow(ip, s.now()) {
		return SetupSession{}, ErrSetupBusy
	}
	canonical, ok := canonicalToken(token)
	if !ok {
		return SetupSession{}, ErrSetupDenied
	}
	defer clear(canonical)
	digests := map[SetupPurpose][]byte{}
	for _, p := range []SetupPurpose{PurposeInitialSetup, PurposeMFAReset, PurposeRestoreRecovery} {
		digests[p] = setupDigest(p, canonical)
	}
	secret, err := s.randomBytes(sessionSecretBytes)
	if err != nil {
		return SetupSession{}, err
	}
	id, err := s.randomHex()
	if err != nil {
		clear(secret)
		return SetupSession{}, err
	}
	hash := sha256.Sum256(secret)
	const (
		outcomeDenied = iota
		outcomeBusy
		outcomeMatched
	)
	outcome := outcomeDenied
	var (
		removals []string
		matched  store.SetupToken
		session  store.SetupSession
		target   string
	)
	err = s.run(ctx, func(ctx context.Context, q *store.Queries, now int64) error {
		outcome, removals = outcomeDenied, nil
		live, e := q.ListLiveSetupTokens(ctx)
		if e != nil {
			return e
		}
		var consumable []store.SetupToken
		purposes := []SetupPurpose{}
		seen := map[SetupPurpose]bool{}
		for _, tok := range live {
			if tok.State == "retrieved" && now < tok.ExpiresAt {
				consumable = append(consumable, tok)
				p := SetupPurpose(tok.Purpose)
				if !seen[p] {
					seen[p] = true
					purposes = append(purposes, p)
				}
			}
		}
		if len(consumable) == 0 {
			return nil // nothing guessable exists; not a counted guess
		}
		attempts := map[SetupPurpose]store.SetupAttempt{}
		for _, p := range purposes {
			a, e := q.GetSetupAttempts(ctx, string(p))
			if e != nil {
				return e
			}
			attempts[p] = a
			if now < a.NextAttemptAt {
				outcome = outcomeBusy // inside a backoff window: not evaluated, not counted
				return nil
			}
		}
		matchIndex := -1
		for i, tok := range consumable { // every candidate is compared; no early exit
			if digestEqual(digests[SetupPurpose(tok.Purpose)], tok.Digest) {
				matchIndex = i
			}
		}
		if matchIndex < 0 {
			for _, p := range purposes {
				a := attempts[p]
				n, e := q.RecordSetupFailure(ctx, store.RecordSetupFailureParams{NextAttemptAt: now + passwordWait(a.Failed+1), Purpose: string(p)})
				if e != nil {
					return e
				}
				if n != 1 {
					return errSetupLogical
				}
				if a.Failed+1 >= setupFailureCeiling {
					r, e := revokePurpose(ctx, q, p, now, "attempt_ceiling")
					if e != nil {
						return e
					}
					removals = append(removals, r...)
				}
			}
			return nil // commit the durable counter update
		}
		tok := consumable[matchIndex]
		purpose := SetupPurpose(tok.Purpose)
		meta, e := q.GetRepositoryMetadata(ctx)
		if e != nil {
			return e
		}
		if string(meta.InstallationID) != string(tok.InstallationID) {
			return nil
		}
		// Target/eligibility still hold, or the generation is revoked now.
		if _, e = resolveTarget(ctx, q, purpose, targetName(ctx, q, tok)); e != nil {
			if e != errSetupLogical {
				return e
			}
			n, e := q.RevokeSetupToken(ctx, store.RevokeSetupTokenParams{Now: nullableInt(now), Reason: "not_eligible", ID: tok.ID})
			if e != nil || n != 1 {
				return errSetupLogical
			}
			removals = append(removals, revealFileName(tok.Purpose, tok.ID))
			return nil
		}
		n, e := q.ConsumeSetupToken(ctx, store.ConsumeSetupTokenParams{Now: nullableInt(now), ID: tok.ID})
		if e != nil {
			return e
		}
		if n != 1 {
			return errSetupLogical
		}
		if e = q.ResetSetupAttempts(ctx, string(purpose)); e != nil {
			return e
		}
		// The session can never outlive the token's ORIGINAL absolute expiry.
		if e = q.CreateSetupSession(ctx, store.CreateSetupSessionParams{ID: id, TokenID: tok.ID, Purpose: tok.Purpose, TargetUserID: tok.TargetUserID, SecretHash: hash[:], CreatedAt: now, ExpiresAt: tok.ExpiresAt}); e != nil {
			return e
		}
		removals = append(removals, revealFileName(tok.Purpose, tok.ID))
		matched = tok
		if target = targetName(ctx, q, tok); strings.HasPrefix(target, "\x00") {
			return errSetupLogical
		}
		session = store.SetupSession{ID: id, Purpose: tok.Purpose, TargetUserID: tok.TargetUserID, ExpiresAt: tok.ExpiresAt, CreatedAt: now}
		outcome = outcomeMatched
		return nil
	}, func() error {
		if e := s.step("exchange:after-commit"); e != nil {
			return e
		}
		for _, name := range removals {
			if e := s.repo.RevealFileRemove(name); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		clear(secret)
		return SetupSession{}, err
	}
	switch outcome {
	case outcomeMatched:
		info := SetupSessionInfo{ID: session.ID, Purpose: SetupPurpose(session.Purpose), ExpiresAt: time.Unix(session.ExpiresAt, 0).UTC(), ReplacePassword: matched.ReplacePassword == 1, TargetUser: target, MailConfigured: s.l != nil && s.sendProof != nil}
		return SetupSession{SetupSessionInfo: info, secret: secret}, nil
	case outcomeBusy:
		clear(secret)
		return SetupSession{}, ErrSetupBusy
	default:
		clear(secret)
		return SetupSession{}, ErrSetupDenied
	}
}

// targetName resolves a token's mfa_reset target back to a username for
// resolveTarget (which authorizes by name). Initial tokens have no target.
func targetName(ctx context.Context, q *store.Queries, tok store.SetupToken) string {
	if !tok.TargetUserID.Valid {
		return ""
	}
	u, err := q.GetUser(ctx, tok.TargetUserID.String)
	if err != nil {
		return "\x00unresolvable" // never matches an account; resolveTarget denies
	}
	return u.Username
}

// verifySession is the single in-transaction check every setup-session operation
// repeats: opaque secret -> live row bound to its consumed token, unexpired
// against the token's absolute expiry, purpose-specific eligibility still true.
func verifySession(ctx context.Context, q *store.Queries, secret []byte, now int64) (store.SetupSession, store.SetupToken, error) {
	var sess store.SetupSession
	var tok store.SetupToken
	if len(secret) != sessionSecretBytes {
		return sess, tok, errSetupLogical
	}
	hash := sha256.Sum256(secret)
	sess, err := q.GetSetupSessionByHash(ctx, hash[:])
	if isNoRows(err) {
		return sess, tok, errSetupLogical
	}
	if err != nil {
		return sess, tok, err
	}
	tok, err = q.GetSetupToken(ctx, sess.TokenID)
	if err != nil {
		return sess, tok, err
	}
	if sess.State != "active" || now < sess.CreatedAt || now >= sess.ExpiresAt || tok.State != "consumed" || now >= tok.ExpiresAt || sess.ExpiresAt != tok.ExpiresAt || sess.Purpose != tok.Purpose {
		return sess, tok, errSetupLogical
	}
	if _, err = resolveTarget(ctx, q, SetupPurpose(sess.Purpose), targetName(ctx, q, tok)); err != nil {
		return sess, tok, err
	}
	return sess, tok, nil
}

// Authenticate is the read-only check used by the HTTP adapter before routing.
// It carries no assurance: success only means "this is a live setup session".
func (s *Setup) Authenticate(ctx context.Context, secret []byte) (SetupSessionInfo, error) {
	var info SetupSessionInfo
	logical := false
	err := s.repo.Read(ctx, func(q *store.Queries) error {
		now := s.now().Unix()
		if e := clockReadable(ctx, q, now); e != nil {
			logical = e == errSetupLogical
			return e
		}
		sess, tok, e := verifySession(ctx, q, secret, now)
		if e != nil {
			logical = e == errSetupLogical
			return e
		}
		info, e = s.sessionInfo(ctx, q, sess, tok)
		return e
	})
	if err != nil {
		return SetupSessionInfo{}, classify(err, logical)
	}
	return info, nil
}

func (s *Setup) sessionInfo(ctx context.Context, q *store.Queries, sess store.SetupSession, tok store.SetupToken) (SetupSessionInfo, error) {
	info := SetupSessionInfo{ID: sess.ID, Purpose: SetupPurpose(sess.Purpose), ExpiresAt: time.Unix(sess.ExpiresAt, 0).UTC(), ReplacePassword: tok.ReplacePassword == 1, MailConfigured: s.l != nil && s.sendProof != nil}
	info.AccountStaged = sess.StagedVerifier != nil
	info.TOTPBegun = sess.TotpAuthenticatorID.Valid
	info.TOTPProven = sess.TotpProvenAt.Valid
	if sess.TargetUserID.Valid {
		u, err := q.GetUser(ctx, sess.TargetUserID.String)
		if err != nil && !isNoRows(err) {
			return info, err
		}
		info.TargetUser = u.Username
	}
	if sess.StagedUserID.Valid {
		all, err := q.ListNotificationAddresses(ctx, sess.StagedUserID.String)
		if err != nil {
			return info, err
		}
		confirmed, err := q.ListConfirmedStagedAddresses(ctx, sess.StagedUserID.String)
		if err != nil {
			return info, err
		}
		ok := map[string]bool{}
		for _, a := range confirmed {
			ok[a.ID] = true
		}
		for _, a := range all {
			info.Addresses = append(info.Addresses, SetupAddress{ID: a.ID, Address: a.Address, Confirmed: ok[a.ID]})
		}
	}
	return info, nil
}
