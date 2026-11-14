// Package backup is the logical backup and transactional restore service (TD 6.3,
// security-contracts.md S2, RESTORE-01..11).
//
// The package never decides who may call it: the caller supplies an authorization callback that
// runs INSIDE the same durable control transaction as the availability-changing transition. It
// authenticates nothing from an archive: a valid integrity tag proves only that the holder of the
// master key wrote the document at some time, never that anything in it is current, and nothing
// imported becomes effective (security-contracts.md S2.1/S2.2). See docs/backup-restore.md.
package backup

import (
	"errors"
	"fmt"
	"strings"
)

// Fixed, input-free failure classes. None of them carries archive content, a record value, a key,
// a path or a storage detail, so they are safe to log and to map to an HTTP status.
var (
	// ErrMalformed: not a single strict JSON object of the documented shape, or over a bound.
	ErrMalformed = errors.New("backup: archive is malformed")
	// ErrUnsupportedVersion: an unknown format, archive version or database schema version.
	ErrUnsupportedVersion = errors.New("backup: unsupported archive version")
	// ErrIntegrity: the integrity tag or content digest does not match. A wrong master key and a
	// modified archive are deliberately indistinguishable.
	ErrIntegrity = errors.New("backup: archive integrity check failed")
	// ErrConsistency: the archive is authentic but its records are not a consistent snapshot.
	ErrConsistency = errors.New("backup: archive records are inconsistent")
	// ErrUnauthenticated: a clean archive whose integrity tag this installation's key cannot verify
	// may only be restored with an explicit acknowledgement.
	ErrUnauthenticated = errors.New("backup: archive provenance is unverified and was not acknowledged")
	// ErrDenied: the initiator is not authorized (the callback refused). Nothing was changed.
	ErrDenied = errors.New("backup: initiator not authorized")
	// ErrUnavailable: storage or the transaction failed. The import is never partially applied; a
	// restore transition that already committed stays in quarantine.
	ErrUnavailable = errors.New("backup: storage unavailable")
	// ErrSuperseded: another restore changed the control state between the two transactions.
	ErrSuperseded = errors.New("backup: restore superseded by a competing restore")
	// ErrQuarantined: reapproval needs an installation that left restore quarantine.
	ErrQuarantined = errors.New("backup: installation is in restore quarantine")
	// ErrNoRestore: there is no restore manifest to review.
	ErrNoRestore = errors.New("backup: no restore manifest")
	// ErrNotFound / ErrConflict: reapproval of a record that is not in the manifest or cannot be
	// approved now. ErrConflict carries the per-item reasons in a ConflictError.
	ErrNotFound = errors.New("backup: manifest entry not found")
	ErrConflict = errors.New("backup: approval conflict")
	// ErrInvalid: a malformed approval request.
	ErrInvalid = errors.New("backup: invalid request")
)

// ConsistencyError names the structural rule an archive broke. Code is one of a small fixed set.
type ConsistencyError struct{ Code string }

func (e *ConsistencyError) Error() string {
	return "backup: archive records are inconsistent: " + e.Code
}
func (e *ConsistencyError) Is(target error) bool {
	return target == ErrConsistency
}

func inconsistent(code string) error { return &ConsistencyError{Code: code} }

// Failure is one approval that could not be made. Reason is a fixed code, never a value.
type Failure struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// ConflictError lists every approval that refused. The whole request is then rolled back.
type ConflictError struct{ Failures []Failure }

func (e *ConflictError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		parts = append(parts, fmt.Sprintf("%s:%s", f.Kind, f.Reason))
	}
	return ErrConflict.Error() + ": " + strings.Join(parts, ",")
}
func (e *ConflictError) Is(target error) bool { return target == ErrConflict }

// quarantinedError marks a failure that happened AFTER the availability-changing transition had
// committed: the installation is in restore quarantine and no archive record was applied. Callers
// (and the UI contract) use Quarantined to tell this apart from a refusal that changed nothing.
type quarantinedError struct{ err error }

func (e *quarantinedError) Error() string { return e.err.Error() }
func (e *quarantinedError) Unwrap() error { return e.err }

func afterTransition(err error) error { return &quarantinedError{err: err} }

// Quarantined reports whether err left the installation in restore quarantine.
func Quarantined(err error) bool {
	var q *quarantinedError
	return errors.As(err, &q)
}
