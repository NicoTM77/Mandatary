package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"strings"
	"time"
	"unicode"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Enrollment steps of a setup/recovery session. Every method repeats the full
// session verification inside its own control transaction; the HTTP adapter's
// earlier read is only a routing convenience. Nothing here creates a normal
// session, an AAL label, a policy, or any Docker authority.

// AccountRequest stages the first administrator (initial setup) or the optional
// replacement password (MFA reset with ReplacePassword). Password is raw input;
// it is canonicalised, policy-checked (compulsory-MFA minimum, full-password
// blocklist, context values) and hashed. It is never stored in plaintext.
type AccountRequest struct {
	Username  string
	Password  []byte
	Addresses []string
}

func validSetupUsername(name string) bool {
	if name == "" || len(name) > setupUsernameMax {
		return false
	}
	for i, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if i > 0 {
			ok = ok || r == '.' || r == '_' || r == '-' || r == '@' || r == '+'
		}
		if !ok || r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// preflight reads the session and the context a password policy needs, without
// writing. Policy/hash work then happens outside the control lock.
type setupPreflight struct {
	sess    store.SetupSession
	tok     store.SetupToken
	user    store.User // mfa_reset target
	binding store.Authenticator
	values  []string
}

func (s *Setup) preflight(ctx context.Context, secret []byte) (setupPreflight, error) {
	var p setupPreflight
	logical := false
	err := s.repo.Read(ctx, func(q *store.Queries) error {
		now := s.now().Unix()
		if e := clockReadable(ctx, q, now); e != nil {
			logical = e == errSetupLogical
			return e
		}
		var e error
		p.sess, p.tok, e = verifySession(ctx, q, secret, now)
		if e != nil {
			logical = e == errSetupLogical
			return e
		}
		if p.sess.TargetUserID.Valid {
			if p.user, e = q.GetUser(ctx, p.sess.TargetUserID.String); e != nil {
				return e
			}
			if p.binding, e = q.GetLocalBinding(ctx, p.user.ID); e != nil && !isNoRows(e) {
				return e
			}
			c, e := q.GetInstallationControl(ctx)
			if e != nil {
				return e
			}
			addresses, e := q.ListNotificationAddresses(ctx, p.user.ID)
			if e != nil {
				return e
			}
			p.values = []string{p.user.Username}
			for _, a := range addresses {
				if a.State == "active" && a.VerifiedAt.Valid && !a.RevokedAt.Valid && a.AuthorityGeneration == c.AuthorityGeneration {
					p.values = append(p.values, a.Address)
				}
			}
		}
		return nil
	})
	if err != nil {
		return setupPreflight{}, classify(err, logical)
	}
	return p, nil
}

// StageAccount validates and stages the account of this session. It may be done
// once per session; a different choice needs explicit host rotation. For initial
// setup it reserves the (inert, quarantined) username and addresses; for an MFA
// reset with ReplacePassword it stages only the replacement verifier.
func (s *Setup) StageAccount(ctx context.Context, secret []byte, req AccountRequest) ([]SetupAddress, error) {
	defer clear(req.Password)
	if s.l == nil {
		return nil, ErrSetupUnavailable
	}
	p, err := s.preflight(ctx, secret)
	if err != nil {
		return nil, err
	}
	purpose := SetupPurpose(p.sess.Purpose)
	var values []string
	var addresses []string
	switch purpose {
	case PurposeInitialSetup, PurposeRestoreRecovery:
		if !validSetupUsername(req.Username) || len(req.Addresses) < 1 || len(req.Addresses) > setupMaxAddresses {
			return nil, ErrSetupDenied
		}
		seen := map[string]bool{}
		for _, a := range req.Addresses {
			key := strings.ToLower(a)
			if !validMailbox(a) || seen[key] {
				return nil, ErrSetupDenied
			}
			seen[key] = true
			addresses = append(addresses, a)
		}
		values = append([]string{req.Username}, addresses...)
	case PurposeMFAReset:
		if p.tok.ReplacePassword != 1 || req.Username != "" || len(req.Addresses) != 0 {
			return nil, ErrSetupDenied
		}
		values = p.values
	default:
		return nil, ErrSetupDenied
	}
	if p.sess.StagedVerifier != nil {
		return nil, ErrSetupDenied
	}
	// Expensive hashing is bounded to one at a time process-wide (as passwords).
	select {
	case passwordWork <- struct{}{}:
		defer func() { <-passwordWork }()
	default:
		return nil, ErrSetupBusy
	}
	canonical, err := s.l.passwords.policy.Validate(ctx, req.Password, true, append(values, s.l.passwords.hostname))
	if err != nil {
		return nil, err // fixed ErrPassword/ErrBlocked guidance; never an echo
	}
	defer clear(canonical)
	if purpose == PurposeMFAReset && p.binding.VerifierHash != nil && VerifyPassword(canonical, p.binding.VerifierHash, p.binding.PasswordFormat.String) {
		return nil, ErrPassword // a "replacement" identical to the current password
	}
	verifier, err := HashPassword(canonical)
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	codepoints := int64(len([]rune(string(canonical))))
	var staged []SetupAddress
	err = s.run(ctx, func(ctx context.Context, q *store.Queries, now int64) error {
		staged = nil
		sess, tok, e := verifySession(ctx, q, secret, now)
		if e != nil {
			return e
		}
		if sess.StagedVerifier != nil || sess.Purpose != string(purpose) || tok.ReplacePassword != p.tok.ReplacePassword {
			return errSetupLogical
		}
		format := nullStr(PasswordProfile)
		cp := nullableInt(codepoints)
		if purpose == PurposeMFAReset {
			// The verifier the policy compared against must still be current.
			current, e := q.GetLocalBinding(ctx, sess.TargetUserID.String)
			if e != nil || !bytes.Equal(current.VerifierHash, p.binding.VerifierHash) {
				return errSetupLogical
			}
			n, e := q.StageSetupVerifier(ctx, store.StageSetupVerifierParams{Verifier: verifier, Format: format, Codepoints: cp, ID: sess.ID})
			if e != nil {
				return e
			}
			if n != 1 {
				return errSetupLogical
			}
			return nil
		}
		if _, e = q.GetUserByUsername(ctx, req.Username); e == nil {
			return errSetupLogical
		} else if !isNoRows(e) {
			return e
		}
		userID, e := s.randomHex()
		if e != nil {
			return e
		}
		if e = q.CreateStagedUser(ctx, store.CreateStagedUserParams{ID: userID, Username: req.Username}); e != nil {
			return e
		}
		for _, a := range addresses {
			id, e := s.randomHex()
			if e != nil {
				return e
			}
			if e = q.CreateStagedAddress(ctx, store.CreateStagedAddressParams{ID: id, UserID: userID, Address: a, CreatedAt: now}); e != nil {
				return e
			}
			staged = append(staged, SetupAddress{ID: id, Address: a})
		}
		n, e := q.StageSetupUser(ctx, store.StageSetupUserParams{UserID: nullStr(userID), Verifier: verifier, Format: format, Codepoints: cp, ID: sess.ID})
		if e != nil {
			return e
		}
		if n != 1 {
			return errSetupLogical
		}
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	return staged, nil
}

var proofEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func proofDigest(addressID string, proof []byte) []byte {
	h := sha256.New()
	h.Write([]byte("mandatary address proof v1\x00"))
	h.Write([]byte(addressID))
	h.Write([]byte{0})
	h.Write(proof)
	return h.Sum(nil)
}

// canonicalProof accepts the 26-character canonical proof with optional hyphens
// and surrounding whitespace; anything else is rejected before evaluation.
func canonicalProof(input string) ([]byte, bool) {
	if len(input) > 64 {
		return nil, false
	}
	compact := strings.ReplaceAll(strings.Trim(input, " \t\r\n"), "-", "")
	if len(compact) != 26 {
		return nil, false
	}
	for i := 0; i < len(compact); i++ {
		c := compact[i]
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return nil, false
		}
	}
	return []byte(compact), true
}

// SendAddressProof issues a purpose/address/session-bound, one-use, expiring
// address-control proof and delivers it to THAT staged address over the verified
// TLS SMTP path. It is not an authentication or recovery code and carries no
// authority. The proof is durable (digest only) BEFORE delivery is attempted;
// network I/O never holds the control lock. Re-sends are rate-limited.
func (s *Setup) SendAddressProof(ctx context.Context, secret []byte, addressID string) error {
	if s.l == nil || s.sendProof == nil {
		return ErrSetupUnavailable
	}
	raw, err := s.randomBytes(16)
	if err != nil {
		return err
	}
	defer clear(raw)
	proof := make([]byte, proofEncoding.EncodedLen(len(raw)))
	proofEncoding.Encode(proof, raw)
	defer clear(proof)
	proofID, err := s.randomHex()
	if err != nil {
		return err
	}
	var recipient string
	err = s.run(ctx, func(ctx context.Context, q *store.Queries, now int64) error {
		sess, _, e := verifySession(ctx, q, secret, now)
		if e != nil {
			return e
		}
		if !SetupPurpose(sess.Purpose).createsAccount() || !sess.StagedUserID.Valid || now-sess.LastProofSentAt < int64(setupProofResend/time.Second) {
			return errSetupLogical
		}
		count, e := q.CountAddressProofs(ctx, sess.StagedUserID.String)
		if e != nil {
			return e
		}
		if count >= setupMaxProofs {
			return errSetupLogical
		}
		addresses, e := q.ListNotificationAddresses(ctx, sess.StagedUserID.String)
		if e != nil {
			return e
		}
		found := false
		for _, a := range addresses {
			if a.ID == addressID && a.State == "quarantined" {
				found, recipient = true, a.Address
			}
		}
		if !found {
			return errSetupLogical
		}
		expires := now + int64(setupProofLifetime/time.Second)
		if expires > sess.ExpiresAt {
			expires = sess.ExpiresAt
		}
		if expires <= now {
			return errSetupLogical
		}
		if e = q.CreateAddressProof(ctx, store.CreateAddressProofParams{ID: proofID, UserID: sess.StagedUserID.String, AddressID: addressID, ProofHash: proofDigest(addressID, proof), IssuedAt: now, ExpiresAt: expires}); e != nil {
			return e
		}
		return q.NoteSetupProofSent(ctx, store.NoteSetupProofSentParams{Now: now, ID: sess.ID})
	}, nil)
	if err != nil {
		return err
	}
	if failure := s.sendProof(ctx, recipient, string(proof)); failure != "" {
		return ErrSetupUnavailable // delivery failure is visible; nothing is retargeted
	}
	return nil
}

// ConfirmAddress consumes the proof for exactly this session/address. A wrong
// proof is an evaluated failure with the same durable, restart-surviving backoff
// as other proofs (waits from five failures, session ended at the ceiling).
func (s *Setup) ConfirmAddress(ctx context.Context, secret []byte, addressID, proofText, ip string) error {
	if !s.gate.allow(ip, s.now()) {
		return ErrSetupBusy
	}
	proof, ok := canonicalProof(proofText)
	if !ok || addressID == "" || len(addressID) > 64 {
		return ErrSetupDenied
	}
	defer clear(proof)
	digest := proofDigest(addressID, proof)
	confirmed := false
	err := s.run(ctx, func(ctx context.Context, q *store.Queries, now int64) error {
		confirmed = false
		sess, _, e := verifySession(ctx, q, secret, now)
		if e != nil {
			return e
		}
		if !SetupPurpose(sess.Purpose).createsAccount() || !sess.StagedUserID.Valid {
			return errSetupLogical
		}
		if now < sess.ProofNextAttemptAt {
			return errSetupLogical // inside a backoff window: not evaluated, not counted
		}
		row, e := q.GetAddressProofByHash(ctx, digest)
		valid := e == nil && row.UserID == sess.StagedUserID.String && row.AddressID == addressID && row.Purpose == "notification_address_confirmation" && !row.ConsumedAt.Valid && now >= row.IssuedAt && now < row.ExpiresAt
		if e != nil && !isNoRows(e) {
			return e
		}
		if !valid {
			n, e := q.RecordSetupProofFailure(ctx, store.RecordSetupProofFailureParams{NextAttemptAt: now + passwordWait(sess.ProofFailures+1), ID: sess.ID})
			if e != nil {
				return e
			}
			if n != 1 {
				return errSetupLogical
			}
			if sess.ProofFailures+1 >= setupFailureCeiling {
				if e = endSession(ctx, q, sess, now, "revoked"); e != nil {
					return e
				}
			}
			return nil // commit the durable failure
		}
		n, e := q.ConsumeAddressProof(ctx, store.ConsumeAddressProofParams{Now: nullableInt(now), ID: row.ID})
		if e != nil {
			return e
		}
		if n != 1 {
			return errSetupLogical
		}
		confirmed = true
		return nil
	}, nil)
	if err != nil {
		return err
	}
	if !confirmed {
		return ErrSetupDenied
	}
	return nil
}

// SetupTOTPAlgorithms mirror the lifecycle service: SHA1/SHA256 only.
func validTOTPAlgorithm(a string) bool { return a == "SHA1" || a == "SHA256" }

// BeginTOTP provisions the session's single TOTP seed (32 CSPRNG bytes, AEAD
// protected, bound to its authenticator ID). The seed is returned once. The
// authenticator stays PENDING and unusable until its proof and the completion.
func (s *Setup) BeginTOTP(ctx context.Context, secret []byte, algorithm string) (Enrollment, error) {
	if s.l == nil || !validTOTPAlgorithm(algorithm) {
		return Enrollment{}, ErrSetupDenied
	}
	id, err := s.randomHex()
	if err != nil {
		return Enrollment{}, err
	}
	seed, err := s.randomBytes(32)
	if err != nil {
		return Enrollment{}, err
	}
	defer clear(seed)
	encrypted, err := s.repo.EncryptSecret("totp", id, seed)
	if err != nil {
		return Enrollment{}, ErrSetupUnavailable
	}
	err = s.run(ctx, func(ctx context.Context, q *store.Queries, now int64) error {
		sess, _, e := verifySession(ctx, q, secret, now)
		if e != nil {
			return e
		}
		if sess.TotpAuthenticatorID.Valid {
			return errSetupLogical // one enrollment per session; a lost seed needs host rotation
		}
		userID := ""
		switch SetupPurpose(sess.Purpose) {
		case PurposeInitialSetup, PurposeRestoreRecovery:
			if !sess.StagedUserID.Valid || sess.StagedVerifier == nil {
				return errSetupLogical // the account is staged first
			}
			userID = sess.StagedUserID.String
		case PurposeMFAReset:
			tok, e := q.GetSetupGeneration(ctx, sess.TokenID)
			if e != nil {
				return e
			}
			if tok.ReplacePassword == 1 && sess.StagedVerifier == nil {
				return errSetupLogical
			}
			userID = sess.TargetUserID.String
		default:
			return errSetupLogical
		}
		c, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		if e = q.CreatePendingTOTP(ctx, store.CreatePendingTOTPParams{ID: id, UserID: userID, CredentialGeneration: c.CredentialGeneration, CreatedAt: now, EncryptedSecret: encrypted, TotpAlgorithm: nullStr(algorithm)}); e != nil {
			return e
		}
		n, e := q.SetSetupTOTP(ctx, store.SetSetupTOTPParams{AuthenticatorID: nullStr(id), ID: sess.ID})
		if e != nil {
			return e
		}
		if n != 1 {
			return errSetupLogical
		}
		return nil
	}, nil)
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{ID: id, secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)}, nil
}

// ConfirmTOTP proves control of the provisioned authenticator. Replay and retry
// use the durable per-authenticator state of the lifecycle service: one OTP per
// verifier period, five-failure escalating waits, ceiling 100 then disabled. The
// authenticator only becomes ACTIVE in the single completion transaction.
func (s *Setup) ConfirmTOTP(ctx context.Context, secret []byte, code, ip string) error {
	if s.l == nil || len(code) > 64 || !s.gate.allow(ip, s.now()) {
		return ErrSetupDenied
	}
	p, err := s.preflight(ctx, secret)
	if err != nil {
		return err
	}
	if !p.sess.TotpAuthenticatorID.Valid {
		return ErrSetupDenied
	}
	id := p.sess.TotpAuthenticatorID.String
	observed, seed, err := s.l.loadTOTP(ctx, id)
	if err != nil {
		return ErrSetupDenied
	}
	defer clear(seed)
	caller := ctx
	proven := false
	err = s.run(ctx, func(ctx context.Context, q *store.Queries, now int64) error {
		proven = false
		sess, _, e := verifySession(ctx, q, secret, now)
		if e != nil {
			return e
		}
		if !sess.TotpAuthenticatorID.Valid || sess.TotpAuthenticatorID.String != id || sess.TotpProvenAt.Valid {
			return errSetupLogical
		}
		a, e := q.GetAuthenticator(ctx, id)
		if e != nil {
			return e
		}
		if a.Kind != "totp" || a.State != "pending" || a.FailedAttempts >= a.RetryCeiling || (a.NextAttemptAt.Valid && now < a.NextAttemptAt.Int64) || now < a.CreatedAt || caller.Err() != nil {
			return errSetupLogical
		}
		if !bytes.Equal(a.EncryptedSecret, observed.EncryptedSecret) || a.TotpAlgorithm != observed.TotpAlgorithm {
			return errSetupLogical
		}
		step, ok := matchTOTP(seed, a.TotpAlgorithm.String, code, now)
		if !ok {
			n, e := q.RecordTOTPFailure(ctx, store.RecordTOTPFailureParams{ID: a.ID, Now: nullableInt(now), NextAttemptAt: nullableInt(now + passwordWait(a.FailedAttempts+1))})
			if e != nil {
				return e
			}
			if n != 1 {
				return errSetupLogical
			}
			return nil // commit the durable failure
		}
		n, e := q.ProveSetupTOTPStep(ctx, store.ProveSetupTOTPStepParams{Step: nullableInt(step), ID: a.ID})
		if e != nil {
			return e
		}
		if n != 1 {
			return errSetupLogical
		}
		hash := sha256.Sum256([]byte(code))
		if e = q.RecordTOTPAcceptance(ctx, store.RecordTOTPAcceptanceParams{AuthenticatorID: a.ID, Step: step, VerifierPeriod: now / 30, OutputHash: hash[:]}); e != nil {
			return e
		}
		n, e = q.MarkSetupTOTPProven(ctx, store.MarkSetupTOTPProvenParams{Now: nullableInt(now), ID: sess.ID, AuthenticatorID: nullStr(a.ID)})
		if e != nil {
			return e
		}
		if n != 1 {
			return errSetupLogical
		}
		proven = true
		return nil
	}, nil)
	if err != nil {
		return err
	}
	if !proven {
		return ErrSetupDenied
	}
	return nil
}

// CompleteResult is secret-free. There is deliberately NO session or cookie: the
// administrator must now authenticate normally (password + TOTP) to obtain any
// session, and that session's assurance comes from the ordinary P1.08 path.
type CompleteResult struct {
	Purpose  SetupPurpose
	Username string
}

// Complete commits the enrollment atomically (SETUP-06/07/08). It requires the
// proven MFA enrollment, an in-time session, and - for the first administrator -
// a confirmed notification address and a durable security-notice intent in the
// SAME transaction. Any failure rolls everything back and leaves the installation
// locked and consistent; a crash before commit leaves nothing active.
func (s *Setup) Complete(ctx context.Context, secret []byte) (CompleteResult, error) {
	if s.l == nil {
		return CompleteResult{}, ErrSetupUnavailable
	}
	var result CompleteResult
	var removals []string
	err := s.run(ctx, func(ctx context.Context, q *store.Queries, now int64) error {
		removals = nil
		sess, tok, e := verifySession(ctx, q, secret, now)
		if e != nil {
			return e
		}
		if !sess.TotpProvenAt.Valid || !sess.TotpAuthenticatorID.Valid {
			return errSetupLogical // no unlock without proven MFA enrollment
		}
		totp, e := q.GetAuthenticator(ctx, sess.TotpAuthenticatorID.String)
		if e != nil {
			return e
		}
		if totp.Kind != "totp" || totp.State != "pending" || !totp.LastAcceptedTotpStep.Valid || totp.FailedAttempts >= totp.RetryCeiling || len(totp.EncryptedSecret) == 0 {
			return errSetupLogical
		}
		switch SetupPurpose(sess.Purpose) {
		case PurposeInitialSetup:
			result, removals, e = s.completeInitial(ctx, q, sess, totp, now)
		case PurposeMFAReset:
			result, removals, e = s.completeReset(ctx, q, sess, tok, totp, now)
		case PurposeRestoreRecovery:
			result, removals, e = s.completeRestoreRecovery(ctx, q, sess, totp, now)
		default:
			e = errSetupLogical
		}
		return e
	}, func() error {
		if e := s.step("complete:after-commit"); e != nil {
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
		return CompleteResult{}, err
	}
	return result, nil
}

func (s *Setup) completeInitial(ctx context.Context, q *store.Queries, sess store.SetupSession, totp store.Authenticator, now int64) (CompleteResult, []string, error) {
	if !sess.StagedUserID.Valid || sess.StagedVerifier == nil || totp.UserID != sess.StagedUserID.String {
		return CompleteResult{}, nil, errSetupLogical
	}
	user, err := q.GetUser(ctx, sess.StagedUserID.String)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if user.State != "quarantined" || user.MfaRequirement != "required" {
		return CompleteResult{}, nil, errSetupLogical
	}
	confirmed, err := q.ListConfirmedStagedAddresses(ctx, user.ID)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if len(confirmed) == 0 {
		return CompleteResult{}, nil, errSetupLogical // no unlock without a confirmed destination (N1)
	}
	// First, the one-time fresh-install unlock: all local generations 0 -> 1 and the
	// quarantine lifted. It cannot run twice, regress, or run on a populated store.
	n, err := q.UnlockInstallation(ctx)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if n != 1 {
		return CompleteResult{}, nil, errSetupLogical
	}
	if n, err = q.ActivateStagedAdmin(ctx, user.ID); err != nil {
		return CompleteResult{}, nil, err
	} else if n != 1 {
		return CompleteResult{}, nil, errSetupLogical
	}
	passwordID, err := s.randomHex()
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if err = q.CreateAdminVerifier(ctx, store.CreateAdminVerifierParams{ID: passwordID, UserID: user.ID, CreatedAt: now, BoundAt: nullableInt(now), ChangedAt: nullableInt(now), VerifierHash: sess.StagedVerifier, PasswordCodepoints: sess.StagedPasswordCodepoints, PasswordFormat: sess.StagedPasswordFormat}); err != nil {
		return CompleteResult{}, nil, err
	}
	if n, err = q.ActivateProvenTOTP(ctx, store.ActivateProvenTOTPParams{Generation: 1, Now: nullableInt(now), ID: totp.ID}); err != nil {
		return CompleteResult{}, nil, err
	} else if n != 1 {
		return CompleteResult{}, nil, errSetupLogical
	}
	roleID, err := s.randomHex()
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if err = q.CreateInitialAdminRole(ctx, store.CreateInitialAdminRoleParams{ID: roleID, UserID: user.ID}); err != nil {
		return CompleteResult{}, nil, err
	}
	for _, a := range confirmed {
		if n, err = q.ActivateConfirmedAddress(ctx, store.ActivateConfirmedAddressParams{Now: nullableInt(now), Generation: 1, ID: a.ID, UserID: user.ID}); err != nil {
			return CompleteResult{}, nil, err
		} else if n != 1 {
			return CompleteResult{}, nil, errSetupLogical
		}
	}
	if err = q.RevokeUnconfirmedAddresses(ctx, store.RevokeUnconfirmedAddressesParams{Now: nullableInt(now), UserID: user.ID}); err != nil {
		return CompleteResult{}, nil, err
	}
	control, err := q.GetInstallationControl(ctx)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	// Binding notice intent in the SAME transaction: if it cannot be recorded the
	// whole unlock rolls back (NOTIFY-DELIVERY; no unlock without durable notice).
	if err = s.l.enqueue(ctx, q, control, user.ID, "authenticator_bound", now); err != nil {
		return CompleteResult{}, nil, errSetupLogical
	}
	if n, err = q.MarkSetupCompleted(ctx, nullableInt(now)); err != nil {
		return CompleteResult{}, nil, err
	} else if n != 1 {
		return CompleteResult{}, nil, errSetupLogical
	}
	if err = endSession(ctx, q, sess, now, "completed"); err != nil {
		return CompleteResult{}, nil, err
	}
	// Every outstanding initial token/session/file is invalidated atomically.
	removals, err := revokePurpose(ctx, q, PurposeInitialSetup, now, "setup_completed")
	if err != nil {
		return CompleteResult{}, nil, err
	}
	return CompleteResult{Purpose: PurposeInitialSetup, Username: user.Username}, removals, nil
}

func (s *Setup) completeReset(ctx context.Context, q *store.Queries, sess store.SetupSession, tok store.SetupToken, totp store.Authenticator, now int64) (CompleteResult, []string, error) {
	if !sess.TargetUserID.Valid || totp.UserID != sess.TargetUserID.String || (tok.ReplacePassword == 1) != (sess.StagedVerifier != nil) {
		return CompleteResult{}, nil, errSetupLogical
	}
	control, err := q.GetInstallationControl(ctx)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	user, err := q.GetUser(ctx, sess.TargetUserID.String)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if !activeControl(control) || user.State != "active" || user.MfaRequirement == "webauthn" || (user.Compromised != 0 && tok.ReplacePassword == 0) {
		return CompleteResult{}, nil, errSetupLogical
	}
	if ok, e := isActiveAdministrator(ctx, q, user.ID); e != nil {
		return CompleteResult{}, nil, e
	} else if !ok {
		return CompleteResult{}, nil, errSetupLogical
	}
	// Old factors never revive. They were already retired when this generation was
	// issued (S3.2); repeating it is idempotent and also covers anything bound
	// since. The newly proven factor is the only survivor.
	if err = retireUserCredentials(ctx, q, user.ID, totp.ID, retireRecovered, now); err != nil {
		return CompleteResult{}, nil, err
	}
	if n, err := q.ActivateProvenTOTP(ctx, store.ActivateProvenTOTPParams{Generation: control.CredentialGeneration, Now: nullableInt(now), ID: totp.ID}); err != nil {
		return CompleteResult{}, nil, err
	} else if n != 1 {
		return CompleteResult{}, nil, errSetupLogical
	}
	if err = q.ResolveRetiredFactors(ctx, store.ResolveRetiredFactorsParams{Now: nullableInt(now), UserID: user.ID}); err != nil {
		return CompleteResult{}, nil, err
	}
	if tok.ReplacePassword == 1 {
		binding, err := q.GetLocalBinding(ctx, user.ID)
		if err != nil {
			return CompleteResult{}, nil, err
		}
		n, err := q.UpdateVerifier(ctx, store.UpdateVerifierParams{ID: binding.ID, ObservedVerifier: binding.VerifierHash, VerifierHash: sess.StagedVerifier, PasswordFormat: sess.StagedPasswordFormat, PasswordCodepoints: sess.StagedPasswordCodepoints, CredentialGeneration: binding.CredentialGeneration, Now: nullableInt(now)})
		if err != nil {
			return CompleteResult{}, nil, err
		}
		if n != 1 {
			return CompleteResult{}, nil, errSetupLogical
		}
		if _, err = q.ClearCompromiseFlag(ctx, user.ID); err != nil {
			return CompleteResult{}, nil, err
		}
	}
	if err = q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: user.ID, Now: nullableInt(now)}); err != nil {
		return CompleteResult{}, nil, err
	}
	for _, event := range []string{"authenticator_replaced", "recovery_completed"} {
		if err = s.l.enqueue(ctx, q, control, user.ID, event, now); err != nil {
			return CompleteResult{}, nil, errSetupLogical // no completion without durable notices
		}
	}
	if err = endSession(ctx, q, sess, now, "completed"); err != nil {
		return CompleteResult{}, nil, err
	}
	return CompleteResult{Purpose: PurposeMFAReset, Username: user.Username}, nil, nil
}
