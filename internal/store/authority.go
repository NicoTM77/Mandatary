package store

import "context"

// Generations contains server-resolved, current local controls. It must never be
// copied from an import or accepted as a client's assurance assertion. Positive
// generations and no quarantine are necessary, NOT sufficient, for authority:
// callers must still verify record state, proofs, expiry, policy and self-safety.
type Generations struct {
	Credential, Session, Authority, Restore int64
}

// ReadActive checks the live non-importable controls in the SAME read snapshot
// as the records it supplies. Missing/zero/mismatched controls never default to
// active. Dispatch cancellation/rechecking remains with the owning authz service.
func (r *Repository) ReadActive(ctx context.Context, expected Generations, fn func(*Queries) error) error {
	return r.Read(ctx, func(q *Queries) error {
		control, err := q.GetInstallationControl(ctx)
		if err != nil || control.RestoreQuarantined != 0 || expected.Credential <= 0 || expected.Session <= 0 || expected.Authority <= 0 || expected.Restore <= 0 || control.CredentialGeneration != expected.Credential || control.SessionGeneration != expected.Session || control.AuthorityGeneration != expected.Authority || control.RestoreGeneration != expected.Restore {
			return ErrStorage
		}
		return fn(q)
	})
}
