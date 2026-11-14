// Package authz provides the unified default-deny policy authorizer and
// composite container selector evaluator for Mandatary.
package authz

import (
	"errors"
	"log/slog"
	"net/http"
)

// Error is a fixed, secret-free public sentinel error. Raw SQL, Docker, token,
// or container metadata values are never wrapped or echoed.
type Error string

func (e Error) Error() string        { return string(e) }
func (e Error) String() string       { return string(e) }
func (e Error) GoString() string     { return string(e) }
func (e Error) LogValue() slog.Value { return slog.StringValue(string(e)) }

const (
	// ErrUnauthenticated represents a 401 authentication or credential-status denial.
	ErrUnauthenticated Error = "authentication required"
	// ErrForbidden represents a 403 authorization, self-protection, or parameter denial.
	ErrForbidden Error = "operation not permitted"
	// ErrInvalidConfig represents an invalid Authorizer construction configuration.
	ErrInvalidConfig Error = "invalid authorizer configuration"
)

// DenialReason classifies the internal cause of a denial using fixed, secret-free constants.
type DenialReason string

const (
	ReasonSelfProtected        DenialReason = "self_protected"
	ReasonSafetyUnverified     DenialReason = "safety_unverified"
	ReasonUnauthenticated      DenialReason = "unauthenticated"
	ReasonRestoreQuarantined   DenialReason = "restore_quarantined"
	ReasonEndpointInactive     DenialReason = "endpoint_inactive"
	ReasonInvalidOperation     DenialReason = "invalid_operation"
	ReasonInvalidParameters    DenialReason = "invalid_parameters"
	ReasonParameterCapExceeded DenialReason = "parameter_cap_exceeded"
	ReasonInvalidSelector      DenialReason = "invalid_selector"
	ReasonTargetMissing        DenialReason = "target_missing"
	ReasonExplicitDeny         DenialReason = "explicit_deny"
	ReasonDefaultDeny          DenialReason = "default_deny"
	ReasonDecisionStale        DenialReason = "decision_stale"
)

// DenialError pairs a fixed public Error sentinel with a fixed secret-free DenialReason.
type DenialError struct {
	Base   Error
	Reason DenialReason
	// attr is the usage attribution of a denial of a verified principal (see
	// AttributionOf). It is unexported and never formatted.
	attr *Attribution
	// fault marks a fail-closed 403 whose cause is a storage fault, not a policy
	// decision: it is never attributed (attribute leaves it alone), so a fault is
	// never accounted as a denial. Unexported and never formatted.
	fault bool
}

func (e *DenialError) Error() string {
	if e == nil || e.Base == "" {
		return string(ErrForbidden)
	}
	return string(e.Base)
}

func (e *DenialError) String() string   { return e.Error() }
func (e *DenialError) GoString() string { return e.Error() }

func (e *DenialError) LogValue() slog.Value {
	if e == nil {
		return slog.StringValue(string(ErrForbidden))
	}
	return slog.GroupValue(
		slog.String("error", string(e.Base)),
		slog.String("reason", string(e.Reason)),
	)
}

func (e *DenialError) Unwrap() error {
	if e == nil || e.Base == "" {
		return ErrForbidden
	}
	return e.Base
}

func newUnauthenticated(reason DenialReason) error {
	if reason == "" {
		reason = ReasonUnauthenticated
	}
	return &DenialError{Base: ErrUnauthenticated, Reason: reason}
}

// newForbiddenFault is a fail-closed refusal with EXACTLY the public shape of
// newForbidden(reason) (same sentinel, status, reason and text) that additionally
// carries the private fault marker: the cause is a storage/infrastructure error of
// a callback (verification, endpoint or policy query), never a policy decision, so
// it is never attributed or accounted as a denial. It grants nothing.
func newForbiddenFault(reason DenialReason) error {
	if reason == "" {
		reason = ReasonDefaultDeny
	}
	return &DenialError{Base: ErrForbidden, Reason: reason, fault: true}
}

// isFault reports whether err is a refusal marked as an infrastructure fault. Any
// error that is not an authz DenialError at all (for example an arbitrary error of a
// replaced CredentialVerifier) is also a fault, never a logical denial.
func isFault(err error) bool {
	var de *DenialError
	if errors.As(err, &de) && de != nil {
		return de.fault
	}
	return err != nil
}

// verificationRefusal normalizes a CredentialVerifier error: authz refusals pass
// through unchanged (logical 401s stay logical, query faults keep their marker) and
// any other error becomes a fault-marked 401, never a raw error or an attributed denial.
func verificationRefusal(err error) error {
	var de *DenialError
	if errors.As(err, &de) && de != nil {
		return err
	}
	return &DenialError{Base: ErrUnauthenticated, Reason: ReasonUnauthenticated, fault: true}
}

func newForbidden(reason DenialReason) error {
	if reason == "" {
		reason = ReasonDefaultDeny
	}
	return &DenialError{Base: ErrForbidden, Reason: reason}
}

// StatusCode maps an authorization error to its canonical HTTP status code (401 or 403).
func StatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if errors.Is(err, ErrUnauthenticated) {
		return http.StatusUnauthorized
	}
	return http.StatusForbidden
}

// ReasonOf extracts the fixed DenialReason from err, if present.
func ReasonOf(err error) (DenialReason, bool) {
	var de *DenialError
	if errors.As(err, &de) && de != nil {
		return de.Reason, true
	}
	return "", false
}

// HasReason reports whether err carries the specified DenialReason.
func HasReason(err error, reason DenialReason) bool {
	r, ok := ReasonOf(err)
	return ok && r == reason
}
