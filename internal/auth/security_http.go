package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Browser account-security routes (P1.16.4, slice 2): step-up, the factor
// lifecycle, recovery codes, notification addresses, notice health and WebAuthn
// login/step-up/enrolment. Like login_http.go this adds NO authority. Every proof
// and every state change is made by the existing services (Sessions, Lifecycle,
// WebAuthnService, the address service), every route sits behind the Browser
// boundary with an explicit RoutePolicy, and every mutation of a TD §4.3 class is
// registered with that class so the freshness/assurance gate is applied BEFORE the
// handler runs and again inside the service transaction. No request field can set
// an assurance, a method, a role, a time or an authenticator the account does not
// own; no query string is accepted.
//
// Public outcomes (the SPA interprets only these):
//
//	401 unauthenticated      no/ended session or capability (cookie cleared by the boundary)
//	403 denied               the service refused (wrong/replayed/throttled proof, last factor,
//	                         unknown or foreign id, policy): ONE outcome, never a reason
//	403 step_up_required     boundary: session valid but not fresh/strong enough for this class
//	403 assurance_unavailable boundary: the account cannot meet the class right now
//	403 forbidden            boundary: Origin/CSRF
//	409 conflict             WebAuthn not configured on this installation
//	503 unavailable          storage/relay uncertainty; never access
const (
	StepUpKnowledgePath        = "/api/v1/stepup/password"
	StepUpTOTPPath             = "/api/v1/stepup/totp"
	StepUpKeyBeginPath         = "/api/v1/stepup/webauthn/begin"
	StepUpKeyFinishPath        = "/api/v1/stepup/webauthn/finish"
	LoginWebAuthnBeginPath     = "/api/v1/login/webauthn/begin"
	LoginWebAuthnFinishPath    = "/api/v1/login/webauthn/finish"
	AccountSecurityPath        = "/api/v1/account/security"
	AccountTOTPPath            = "/api/v1/account/totp"
	AccountTOTPConfirmPath     = "/api/v1/account/totp/confirm"
	AccountTOTPRemovePath      = "/api/v1/account/totp/remove"
	AccountRecoveryCodesPath   = "/api/v1/account/recovery-codes"
	AccountKeyBeginPath        = "/api/v1/account/webauthn/register/begin"
	AccountKeyFinishPath       = "/api/v1/account/webauthn/register/finish"
	AccountKeyRemovePath       = "/api/v1/account/webauthn/remove"
	AccountAddressPath         = "/api/v1/account/addresses"
	AccountAddressProofPath    = "/api/v1/account/addresses/proof"
	AccountAddressConfirmPath  = "/api/v1/account/addresses/confirm"
	AccountAddressRemovePath   = "/api/v1/account/addresses/remove"
	totpAlgorithm              = "SHA256"
	totpDigits, totpPeriodSecs = 6, 30
	maxSecurityKeys            = 16
)

// SecurityPaths lists the exact paths RegisterSecurityRoutes may serve, for
// mounting. A path whose feature is off (WebAuthn not configured) is simply not
// registered and answers 404 behind the boundary.
func SecurityPaths() []string {
	return []string{
		StepUpKnowledgePath, StepUpTOTPPath, StepUpKeyBeginPath, StepUpKeyFinishPath,
		LoginWebAuthnBeginPath, LoginWebAuthnFinishPath,
		AccountSecurityPath, AccountTOTPPath, AccountTOTPConfirmPath, AccountTOTPRemovePath, AccountRecoveryCodesPath,
		AccountKeyBeginPath, AccountKeyFinishPath, AccountKeyRemovePath,
		AccountAddressPath, AccountAddressProofPath, AccountAddressConfirmPath, AccountAddressRemovePath,
		RecoveryPath, RecoveryStatePath, RecoveryTOTPPath, RecoveryTOTPConfirmPath, RecoveryKeyBeginPath, RecoveryKeyFinishPath,
	}
}

type securityHTTP struct {
	b *Browser
	s *Sessions
}

// RegisterSecurityRoutes mounts the slice-2 routes on b. It refuses a nil
// boundary or service, a boundary of another Sessions, and any re-registration.
func RegisterSecurityRoutes(b *Browser, s *Sessions) error {
	if b == nil || s == nil || b.sessions != s {
		return ErrDenied
	}
	h := &securityHTTP{b: b, s: s}
	session := RoutePolicy{Require: RequireSession}
	factor := RoutePolicy{Require: RequireSession, Sensitive: OpAuthenticatorChange}
	address := RoutePolicy{Require: RequireSession, Sensitive: OpNotificationAddress}
	routes := []struct {
		pattern string
		policy  RoutePolicy
		handler http.HandlerFunc
	}{
		{"POST " + StepUpKnowledgePath, session, h.stepUpPassword},
		{"POST " + StepUpTOTPPath, session, h.stepUpTOTP},
		{"GET " + AccountSecurityPath, session, h.inventory},
		{"POST " + AccountTOTPPath, factor, h.totpBegin},
		{"POST " + AccountTOTPConfirmPath, factor, h.totpConfirm},
		{"POST " + AccountTOTPRemovePath, factor, h.totpRemove},
		{"POST " + AccountRecoveryCodesPath, factor, h.issueCodes},
		{"POST " + AccountAddressPath, address, h.addressPropose},
		{"POST " + AccountAddressProofPath, address, h.addressSend},
		{"POST " + AccountAddressConfirmPath, address, h.addressConfirm},
		{"POST " + AccountAddressRemovePath, address, h.addressRemove},
	}
	if s.webauthnReady() {
		routes = append(routes, []struct {
			pattern string
			policy  RoutePolicy
			handler http.HandlerFunc
		}{
			{"POST " + StepUpKeyBeginPath, session, h.stepUpKeyBegin},
			{"POST " + StepUpKeyFinishPath, session, h.stepUpKeyFinish},
			{"POST " + LoginWebAuthnBeginPath, RoutePolicy{Require: RequirePreauth}, h.loginKeyBegin},
			{"POST " + LoginWebAuthnFinishPath, RoutePolicy{Require: RequirePreauth}, h.loginKeyFinish},
			{"POST " + AccountKeyBeginPath, factor, h.keyBegin},
			{"POST " + AccountKeyFinishPath, factor, h.keyFinish},
			{"POST " + AccountKeyRemovePath, factor, h.keyRemove},
		}...)
	}
	for _, r := range routes {
		if err := b.Handle(r.pattern, r.policy, noQuery(r.handler)); err != nil {
			return err
		}
	}
	return registerRecoveryRoutes(b, s)
}

func (h *securityHTTP) session(w http.ResponseWriter, r *http.Request) (Session, bool) {
	session, ok := SessionFrom(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
	}
	return session, ok
}

// fault maps a service error: a refusal is the one public denial, anything else is
// storage uncertainty. The session cookie is only ever cleared by the boundary or
// by an operation that revoked the session.
func fault(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrDenied) {
		writeJSONError(w, http.StatusForbidden, "denied")
		return
	}
	writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
}

// ───────────────────────── step-up ─────────────────────────

func (h *securityHTTP) stepUpPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	password := []byte(body.Password)
	body.Password = ""
	issued, err := h.s.StepUpPassword(r.Context(), session.Secret(), password, peerIP(r))
	clear(password)
	h.finishStepUp(w, issued, err)
}

// stepUpTOTP verifies password + TOTP. A named authenticator must be one of the
// account's own usable TOTP factors; an unnamed request is accepted only when the
// account has exactly one (never guessed).
func (h *securityHTTP) stepUpTOTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password        string `json:"password"`
		Code            string `json:"code"`
		AuthenticatorID string `json:"authenticator_id"`
	}
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	secret := session.Secret()
	_, acct, err := h.s.stepUpCandidate(r.Context(), secret)
	if err != nil {
		fault(w, err)
		return
	}
	id, chosen := chooseTOTP(acct, body.AuthenticatorID)
	if !chosen {
		writeJSONError(w, http.StatusForbidden, "denied")
		return
	}
	password := []byte(body.Password)
	body.Password = ""
	issued, err := h.s.StepUpTOTP(r.Context(), secret, password, id, body.Code, peerIP(r))
	clear(password)
	body.Code = ""
	h.finishStepUp(w, issued, err)
}

func (h *securityHTTP) finishStepUp(w http.ResponseWriter, issued IssuedSession, err error) {
	if err != nil {
		fault(w, err)
		return
	}
	// The predecessor was revoked in the same transaction: its cookie is replaced,
	// its CSRF token is dead, and the page re-reads the session to adopt the new one.
	h.b.SetSessionCookie(w, issued)
	writeJSON(w, http.StatusOK, map[string]any{"step": "session"})
}

// chooseTOTP returns the usable TOTP authenticator to verify. Naming one must hit a
// usable factor of THIS account; naming none works only for exactly one.
func chooseTOTP(acct accountView, named string) (string, bool) {
	if named != "" {
		return named, acct.usableTOTP(named)
	}
	ids := usableTOTPIDs(acct)
	if len(ids) != 1 {
		return "", false
	}
	return ids[0], true
}

func usableTOTPIDs(acct accountView) []string {
	ids := make([]string, 0, len(acct.totp))
	for id := range acct.totp {
		if acct.usableTOTP(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// totpFactorRows lists the account's USABLE TOTP factors, oldest first, so the page
// can offer a choice. Identifiers are random, non-secret record IDs.
func totpFactorRows(acct accountView) []totpRow {
	rows := []totpRow{}
	for _, id := range usableTOTPIDs(acct) {
		rows = append(rows, totpRow{ID: id, AddedAt: acct.totp[id].BoundAt.Int64, Status: "active"})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].AddedAt < rows[j].AddedAt || (rows[i].AddedAt == rows[j].AddedAt && rows[i].ID < rows[j].ID)
	})
	return rows
}

// stepUpMethods lists, in preference order, the proofs the server would accept for
// a step-up of THIS session right now. It mirrors the service checks so the page
// never offers a proof the service would refuse; the service remains the authority.
func (a accountView) stepUpMethods(session Session, webauthn bool) []string {
	var out []string
	if webauthn && len(a.keys) > 0 {
		out = append(out, "webauthn")
	}
	if a.allowsTOTP() && len(a.totp) > 0 && a.hasPassword && !session.PhishingResistant {
		out = append(out, "totp")
	}
	if a.floor < 2 && !a.hasSecondFactor() && a.passwordOnlyAllowed() {
		out = append(out, "password")
	}
	return out
}

// ───────────────────────── inventory ─────────────────────────

type totpRow struct {
	ID      string `json:"id"`
	AddedAt int64  `json:"added_at"`
	Status  string `json:"status"`
}

type keyRow struct {
	ID      string `json:"id"`
	AddedAt int64  `json:"added_at"`
}

// inventory returns the signed-in account's own factor, recovery-code and address
// state plus the AGGREGATE security-notice health. It carries no secret, verifier,
// recipient of anyone else, SMTP diagnostic or message content.
func (h *securityHTTP) inventory(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	totp, keys := []totpRow{}, []keyRow{}
	codes := 0
	err := h.s.read(r.Context(), func(q *store.Queries) error {
		now := h.s.l.now().Unix()
		c, e := q.GetInstallationControl(r.Context())
		if e != nil {
			return e
		}
		all, e := q.ListUserAuthenticators(r.Context(), session.UserID)
		if e != nil {
			return e
		}
		for _, a := range all {
			if a.RevokedAt.Valid || a.CredentialGeneration != c.CredentialGeneration || !a.BoundAt.Valid {
				continue
			}
			switch {
			case a.Kind == "totp" && (a.State == "active" || a.State == "disabled"):
				status := "active"
				if !liveFactor(c, a, now) {
					status = "disabled"
				}
				totp = append(totp, totpRow{ID: a.ID, AddedAt: a.BoundAt.Int64, Status: status})
			case a.Kind == "webauthn" && a.State == "active":
				keys = append(keys, keyRow{ID: a.ID, AddedAt: a.BoundAt.Int64})
			case a.Kind == "recovery_code" && liveFactor(c, a, now):
				codes++
			}
		}
		return nil
	})
	if err != nil {
		h.readFault(w, err)
		return
	}
	addresses, err := h.s.l.ManagedAddresses(r.Context(), session.Secret())
	if err != nil {
		h.readFault(w, err)
		return
	}
	// Notice health is aggregate-only; an unreadable status is "unknown", never healthy.
	health, healthErr := h.s.l.NoticeHealth(r.Context())
	notices := map[string]any{"pending": health.Pending, "failed": health.Failed, "bounced": health.Bounced, "quarantined": health.Quarantined, "protective": health.Protective, "unknown": healthErr != nil}
	sort.Slice(totp, func(i, j int) bool {
		return totp[i].AddedAt < totp[j].AddedAt || (totp[i].AddedAt == totp[j].AddedAt && totp[i].ID < totp[j].ID)
	})
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].AddedAt < keys[j].AddedAt || (keys[i].AddedAt == keys[j].AddedAt && keys[i].ID < keys[j].ID)
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"totp":               totp,
		"keys":               keys,
		"max_keys":           maxSecurityKeys,
		"webauthn_available": h.s.webauthnReady(),
		"recovery_codes":     map[string]any{"remaining": codes},
		"addresses":          addresses,
		"max_addresses":      maxManagedAddresses,
		"notices":            notices,
	})
}

// readFault maps an inventory failure. The Browser boundary already accepted the session, so a service
// denial here means the session lacks the authority to see this account's factors and addresses (a
// password-only session of an MFA-capable account): 403, so the page can explain it instead of showing
// "your session ended". Anything else is a fault, never an empty or healthy-looking answer.
func (h *securityHTTP) readFault(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrDenied) {
		writeJSONError(w, http.StatusForbidden, "denied")
		return
	}
	writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
}

// ───────────────────────── authenticator app (TOTP) ─────────────────────────

func (h *securityHTTP) totpBegin(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	enrollment, err := h.s.l.BeginTOTP(r.Context(), session.Secret(), totpAlgorithm)
	if err != nil {
		fault(w, err)
		return
	}
	seed := enrollment.ExportOnce()
	defer clear(seed)
	writeJSON(w, http.StatusOK, map[string]any{"authenticator_id": enrollment.ID, "secret": string(seed), "algorithm": totpAlgorithm, "digits": totpDigits, "period": totpPeriodSecs})
}

func (h *securityHTTP) totpConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AuthenticatorID string `json:"authenticator_id"`
		Code            string `json:"code"`
	}
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	err := h.s.l.ConfirmTOTP(r.Context(), session.Secret(), body.AuthenticatorID, body.Code, peerIP(r))
	body.Code = ""
	if err != nil {
		fault(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// totpRemove retires an owned authenticator. The service revokes EVERY session of
// the account in the same transaction (the removed factor may have been the one
// that proved this very session), so this response ends the session: the cookie is
// cleared and the page goes to sign-in.
func (h *securityHTTP) totpRemove(w http.ResponseWriter, r *http.Request) {
	h.remove(w, r, func(ctx context.Context, secret []byte, id string) error {
		return h.s.l.RevokeTOTP(ctx, secret, id)
	})
}

func (h *securityHTTP) remove(w http.ResponseWriter, r *http.Request, revoke func(context.Context, []byte, string) error) {
	var body struct {
		AuthenticatorID string `json:"authenticator_id"`
	}
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := revoke(r.Context(), session.Secret(), body.AuthenticatorID); err != nil {
		fault(w, err)
		return
	}
	h.b.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"signed_out": true})
}

// ───────────────────────── recovery codes ─────────────────────────

// issueCodes issues (or replaces) the ten saved recovery codes. They are returned
// ONCE in this response; the service stores only verifiers and cannot show them
// again. Issuing needs a fresh AAL2 session.
func (h *securityHTTP) issueCodes(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	codes, err := h.s.l.IssueRecoveryCodes(r.Context(), session.Secret())
	if err != nil {
		fault(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"codes": codes.ExportOnce()})
}

// ───────────────────────── notification addresses ─────────────────────────

func (h *securityHTTP) addressPropose(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Address string `json:"address"`
	}
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	view, err := h.s.l.ProposeAddress(r.Context(), session.Secret(), body.Address)
	if err != nil {
		fault(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"address": view})
}

func (h *securityHTTP) addressSend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	err := h.s.l.SendAddressConfirmation(r.Context(), session.Secret(), body.ID, peerIP(r))
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrAddressMail):
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
	default:
		fault(w, err)
	}
}

func (h *securityHTTP) addressConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	err := h.s.l.ConfirmAddressProof(r.Context(), session.Secret(), body.ID, body.Code, peerIP(r))
	body.Code = ""
	if err != nil {
		fault(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *securityHTTP) addressRemove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.s.l.RemoveAddress(r.Context(), session.Secret(), body.ID); err != nil {
		fault(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ───────────────────────── WebAuthn ─────────────────────────

// ceremonyBody is the finish request: the server-issued challenge id and the
// browser's serialised credential, passed UNMODIFIED to the service (which bounds
// it to 32 KiB and verifies origin, RP, challenge, UV and the owning session).
type ceremonyBody struct {
	ID       string          `json:"id"`
	Response json.RawMessage `json:"response"`
}

func decodeCeremony(r *http.Request) (ceremonyBody, bool) {
	var body ceremonyBody
	if !decodeStrict(r, &body, false) || body.ID == "" || len(body.Response) == 0 {
		return ceremonyBody{}, false
	}
	return body, true
}

func writeCeremonyOptions(w http.ResponseWriter, id string, options any) {
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "options": options})
}

func (h *securityHTTP) loginKeyBegin(w http.ResponseWriter, r *http.Request) {
	pre, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	options, err := h.s.BeginLoginWebAuthn(r.Context(), pre.Secret())
	if err != nil {
		fault(w, err)
		return
	}
	writeCeremonyOptions(w, options.ID, options.Options)
}

func (h *securityHTTP) loginKeyFinish(w http.ResponseWriter, r *http.Request) {
	pre, ok := h.session(w, r)
	if !ok {
		return
	}
	body, valid := decodeCeremony(r)
	if !valid {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	issued, err := h.s.LoginWebAuthn(r.Context(), pre.Secret(), body.ID, body.Response, peerIP(r))
	if err != nil {
		fault(w, err)
		return
	}
	h.b.SetSessionCookie(w, issued)
	writeJSON(w, http.StatusOK, map[string]any{"step": "session"})
}

func (h *securityHTTP) stepUpKeyBegin(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	options, err := h.s.BeginStepUpWebAuthn(r.Context(), session.Secret())
	if err != nil {
		fault(w, err)
		return
	}
	writeCeremonyOptions(w, options.ID, options.Options)
}

func (h *securityHTTP) stepUpKeyFinish(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	body, valid := decodeCeremony(r)
	if !valid {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	issued, err := h.s.StepUpWebAuthn(r.Context(), session.Secret(), body.ID, body.Response, peerIP(r))
	h.finishStepUp(w, issued, err)
}

func (h *securityHTTP) keyBegin(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	options, err := h.s.w.BeginRegistration(r.Context(), session.Secret(), false)
	if err != nil {
		fault(w, err)
		return
	}
	writeCeremonyOptions(w, options.ID, options.Options)
}

func (h *securityHTTP) keyFinish(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	body, valid := decodeCeremony(r)
	if !valid {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.s.w.FinishRegistration(r.Context(), session.Secret(), body.ID, body.Response); err != nil {
		fault(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *securityHTTP) keyRemove(w http.ResponseWriter, r *http.Request) {
	h.remove(w, r, func(ctx context.Context, secret []byte, id string) error {
		return h.s.w.Revoke(ctx, secret, id)
	})
}
