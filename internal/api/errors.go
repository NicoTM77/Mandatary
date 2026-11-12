package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// Stable machine-readable error codes (the "common errors" of contract v1). The
// same codes and statuses are used by REST responses and by MCP tool errors.
const (
	CodeUnauthenticated    = "unauthenticated"     // 401
	CodeForbidden          = "forbidden"           // 403 (see Reason*)
	CodeInvalidRequest     = "invalid_request"     // 400
	CodeNotFound           = "not_found"           // 404 (route/tool/target)
	CodeMethodNotAllowed   = "method_not_allowed"  // 405
	CodePayloadTooLarge    = "payload_too_large"   // 413
	CodeUnsupportedMedia   = "unsupported_media"   // 415
	CodeTooManyStreams     = "too_many_streams"    // 429
	CodeCanceled           = "canceled"            // 499
	CodeInternal           = "internal"            // 500
	CodeBackendFailed      = "backend_failed"      // 502
	CodeBackendUnavailable = "backend_unavailable" // 503
	CodeTimeout            = "timeout"             // 504
)

// Public 403 reasons. Everything target- or policy-specific (self/peer protection,
// missing target, explicit deny, default deny, stale decision, selector faults) is
// reported as ReasonDefaultDeny: protected, missing and ungranted targets must be
// indistinguishable to a caller (TD §2.1: no visibility of Mandatary or its peers).
// The authorizer's precise reason is retained server-side in the service and its
// tests; it is never part of an adapter response.
const (
	ReasonDefaultDeny        = "default_deny"
	ReasonRestoreQuarantined = "restore_quarantined"
	ReasonSafetyUnverified   = "safety_unverified"
	ReasonEndpointInactive   = "endpoint_inactive"
	ReasonCapExceeded        = "parameter_cap_exceeded"
	ReasonAuthorizationEnded = "authorization_ended"
	ReasonForbiddenOrigin    = "forbidden_origin"
)

// Fixed messages (never derived from input, errors, tokens or Docker data).
var messages = map[string]string{
	CodeUnauthenticated:    "authentication required",
	CodeForbidden:          "operation not permitted",
	CodeInvalidRequest:     "invalid request",
	CodeNotFound:           "not found",
	CodeMethodNotAllowed:   "method not allowed",
	CodePayloadTooLarge:    "request body too large",
	CodeUnsupportedMedia:   "unsupported content type",
	CodeTooManyStreams:     "too many concurrent streams",
	CodeCanceled:           "request canceled",
	CodeInternal:           "internal error",
	CodeBackendFailed:      "backend operation failed",
	CodeBackendUnavailable: "backend unavailable",
	CodeTimeout:            "operation timed out",
}

// Problem is the transport-neutral error of contract v1.
type Problem struct {
	Status  int
	Code    string
	Reason  string // 403 only
	Message string
}

func (p *Problem) Error() string {
	if p == nil {
		return ""
	}
	return p.Message
}

// ErrorDetail and ErrorBody are the JSON shape of every adapter error.
type ErrorDetail struct {
	Code    string `json:"code"`
	Status  int    `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// Body renders the problem as its JSON shape.
func (p *Problem) Body() ErrorBody {
	return ErrorBody{Error: ErrorDetail{Code: p.Code, Status: p.Status, Reason: p.Reason, Message: p.Message}}
}

func newProblem(status int, code string) *Problem {
	return &Problem{Status: status, Code: code, Message: messages[code]}
}

func forbidden(reason string) *Problem {
	p := newProblem(http.StatusForbidden, CodeForbidden)
	p.Reason = reason
	return p
}

func invalid() *Problem { return newProblem(http.StatusBadRequest, CodeInvalidRequest) }

// publicReason collapses the authorizer's reason to the public vocabulary.
func publicReason(err error) string {
	r, _ := authz.ReasonOf(err)
	switch r {
	case authz.ReasonRestoreQuarantined:
		return ReasonRestoreQuarantined
	case authz.ReasonSafetyUnverified:
		return ReasonSafetyUnverified
	case authz.ReasonEndpointInactive:
		return ReasonEndpointInactive
	case authz.ReasonParameterCapExceeded:
		return ReasonCapExceeded
	}
	return ReasonDefaultDeny
}

// Classify maps any error returned by the authorizer, the shared operation service
// or the backend to its Problem. It never embeds the error text, so no credential,
// SQL, Docker or container data can reach a response.
func Classify(err error) *Problem {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, authz.ErrUnauthenticated):
		return newProblem(http.StatusUnauthorized, CodeUnauthenticated)
	case errors.Is(err, authz.ErrForbidden):
		return forbidden(publicReason(err))
	case errors.Is(err, ops.ErrInvalidRequest),
		errors.Is(err, docker.ErrInvalidTarget),
		errors.Is(err, docker.ErrInvalidParameter),
		errors.Is(err, docker.ErrUnsupportedOperation):
		return invalid()
	case errors.Is(err, ops.ErrStreamRevoked):
		return forbidden(ReasonAuthorizationEnded)
	case errors.Is(err, docker.ErrProtectedTarget), errors.Is(err, docker.ErrEndpointMismatch):
		return forbidden(ReasonDefaultDeny)
	case errors.Is(err, docker.ErrUnverified):
		return forbidden(ReasonSafetyUnverified)
	case errors.Is(err, docker.ErrTargetNotFound):
		return newProblem(http.StatusNotFound, CodeNotFound)
	case errors.Is(err, docker.ErrBackendUnavailable), errors.Is(err, docker.ErrUnsupportedAPIVersion):
		return newProblem(http.StatusServiceUnavailable, CodeBackendUnavailable)
	case errors.Is(err, docker.ErrBackendFailed), errors.Is(err, docker.ErrLogLimitExceeded):
		return newProblem(http.StatusBadGateway, CodeBackendFailed)
	case errors.Is(err, context.DeadlineExceeded):
		return newProblem(http.StatusGatewayTimeout, CodeTimeout)
	case errors.Is(err, context.Canceled), errors.Is(err, ops.ErrStreamClosed):
		return newProblem(499, CodeCanceled)
	}
	return newProblem(http.StatusInternalServerError, CodeInternal)
}

var statuses = map[string]int{
	CodeUnauthenticated:    http.StatusUnauthorized,
	CodeForbidden:          http.StatusForbidden,
	CodeInvalidRequest:     http.StatusBadRequest,
	CodeNotFound:           http.StatusNotFound,
	CodeMethodNotAllowed:   http.StatusMethodNotAllowed,
	CodePayloadTooLarge:    http.StatusRequestEntityTooLarge,
	CodeUnsupportedMedia:   http.StatusUnsupportedMediaType,
	CodeTooManyStreams:     http.StatusTooManyRequests,
	CodeCanceled:           499,
	CodeInternal:           http.StatusInternalServerError,
	CodeBackendFailed:      http.StatusBadGateway,
	CodeBackendUnavailable: http.StatusServiceUnavailable,
	CodeTimeout:            http.StatusGatewayTimeout,
}

// ProblemOf builds the Problem of a known code (reason is used for 403 only). The MCP
// adapter uses it so both adapters share one status/message table.
func ProblemOf(code, reason string) *Problem {
	status, ok := statuses[code]
	if !ok {
		return newProblem(http.StatusInternalServerError, CodeInternal)
	}
	p := newProblem(status, code)
	if code == CodeForbidden {
		p.Reason = reason
	}
	return p
}
