package auth

import (
	"context"
	"errors"

	"github.com/NicoTM77/Mandatary/internal/backup"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.18 protected administrative export and restore (security-contracts.md S2, TD 6.3, RESTORE-01..11).
//
// Same authority model as every other administrative service here: the live, fresh AAL2 session of the
// single administrator, decided from persisted state inside the durable transaction that acts. The
// backup package owns archive validation, the quarantine transition, the import and the manifest;
// this file only supplies the in-transaction authorization and maps its results to the Admin errors.
//
// What an authenticated archive does NOT do: it never proves freshness and never grants authority.
// A restore ends with the installation in restore quarantine, every administrator session revoked,
// every control generation rotated and every imported record inactive. The administrator who started
// it is signed out and cannot sign in again: only the host-authorized recovery ceremony (host helper,
// never a web route) ends quarantine, after which each record is approved explicitly with
// ReapproveRestored. See docs/backup-restore.md.

// SetBackup attaches the logical backup service. It must be called before the Admin serves requests;
// without it the backup and restore routes are not registered and every method here refuses.
func (a *Admin) SetBackup(s *backup.Service) error {
	if a == nil || s == nil {
		return ErrDenied
	}
	a.backup = s
	return nil
}

// backupAuthorizer re-verifies the administrator inside the transaction that reads or changes state.
func (a *Admin) backupAuthorizer(secret []byte) backup.Authorizer {
	return func(ctx context.Context, q *store.Queries, _ store.InstallationControl, _ int64) error {
		// The session clock is the Admin's (the one every other administrative decision uses), not the
		// backup service's, so one clock decides freshness everywhere.
		c, u, _, err := freshSession(ctx, q, secret, a.l.now().Unix())
		if err != nil {
			return err
		}
		return requireAdministrator(ctx, q, c, u)
	}
}

// requireFreshAdministrator is the cheap pre-check that keeps an unauthorized direct caller from
// making the service parse and authenticate a large archive.
func (a *Admin) requireFreshAdministrator(ctx context.Context, secret []byte) error {
	var decided error // Repository.Read does not pass the callback's error through, so keep the decision
	err := a.l.repo.Read(ctx, func(q *store.Queries) error {
		decided = a.backupAuthorizer(secret)(ctx, q, store.InstallationControl{}, 0)
		return decided
	})
	if decided != nil {
		return decided
	}
	return err
}

func backupAdminError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, backup.ErrDenied):
		return ErrDenied
	case errors.Is(err, backup.ErrInvalid):
		return ErrAdminInvalid
	}
	return ErrAdminUnavailable
}

// ExportBackup returns a signed archive of the documented scope. Mode "full" carries credential
// material sealed under the master key (restore needs the same key); "clean" carries none. The
// export is a protected, fresh-AAL2 operation and reads one coherent snapshot.
func (a *Admin) ExportBackup(ctx context.Context, secret []byte, mode backup.Mode) ([]byte, backup.ExportInfo, error) {
	if a.backup == nil {
		return nil, backup.ExportInfo{}, ErrAdminUnavailable
	}
	if ctx.Err() != nil {
		return nil, backup.ExportInfo{}, ErrDenied
	}
	raw, info, err := a.backup.Export(ctx, mode, a.backupAuthorizer(secret))
	if err != nil {
		return nil, backup.ExportInfo{}, backupAdminError(err)
	}
	return raw, info, nil
}

// RestoreResult is what a committed restore reports. Notified is false when the shared authorizer
// could not be told (its cached decisions then lapse at its next revalidation tick); the durable
// quarantine is in force either way.
type RestoreResult struct {
	Report   backup.Report
	Notified bool
}

// RestoreBackup validates the archive (version, integrity tag, envelope, structure: no side effect on
// failure), then authorizes the administrator inside the transition's own transaction, enters restore
// quarantine, rotates the control generations, revokes every session (the caller's included) and
// imports the archive as inactive records. acknowledgeUnauthenticated is required for a clean archive
// this installation's key cannot authenticate. The returned error satisfies backup.Quarantined when
// the transition committed but the import did not.
func (a *Admin) RestoreBackup(ctx context.Context, secret, archive []byte, acknowledgeUnauthenticated bool) (RestoreResult, error) {
	if a.backup == nil {
		return RestoreResult{}, ErrAdminUnavailable
	}
	if ctx.Err() != nil {
		return RestoreResult{}, ErrDenied
	}
	if err := a.requireFreshAdministrator(ctx, secret); err != nil {
		if errors.Is(err, ErrDenied) {
			return RestoreResult{}, ErrDenied
		}
		return RestoreResult{}, ErrAdminUnavailable
	}
	verified, err := a.backup.Verify(archive)
	if err != nil {
		return RestoreResult{}, err
	}
	report, err := a.backup.Restore(ctx, verified, backup.RestoreOptions{Initiator: backup.InitiatorAdmin, Authorize: a.backupAuthorizer(secret), AcknowledgeUnauthenticated: acknowledgeUnauthenticated})
	if err != nil && !backup.Quarantined(err) {
		return RestoreResult{}, err
	}
	// Active decisions and streams must end now, whether or not the import completed.
	notified := a.changed(ctx) == nil
	if err != nil {
		return RestoreResult{}, err
	}
	return RestoreResult{Report: report, Notified: notified}, nil
}

// RestoreManifest is the redacted authority manifest of the latest restore: what was imported or
// retired, what the archive claimed and what is effective now. It is only reachable after the host
// recovery ceremony ended quarantine and an administrator signed in again.
func (a *Admin) RestoreManifest(ctx context.Context, secret []byte) (backup.ManifestView, error) {
	if a.backup == nil {
		return backup.ManifestView{}, ErrAdminUnavailable
	}
	var view backup.ManifestView
	var inner error
	err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, _ int64) error {
		view, inner = backup.Manifest(ctx, q)
		if errors.Is(inner, backup.ErrNoRestore) {
			return ErrAdminNotFound
		}
		return inner
	})
	if err != nil {
		return backup.ManifestView{}, err
	}
	return view, nil
}

// ReapproveRestored makes the NAMED manifest entries effective again at the current generations. It is
// all-or-nothing and never approves "everything": each principal, membership, rule and the endpoint is
// a separate named entry. The error satisfies backup.ErrConflict (with the per-entry reasons) when any
// entry cannot be approved; nothing is then changed. Approval issues no credential.
func (a *Admin) ReapproveRestored(ctx context.Context, secret []byte, refs []backup.ItemRef) ([]backup.ItemResult, error) {
	if a.backup == nil {
		return nil, ErrAdminUnavailable
	}
	var results []backup.ItemResult
	var detail error
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		var e error
		results, e = backup.Approve(ctx, q, c, now, refs)
		switch {
		case e == nil:
			return nil
		case errors.Is(e, backup.ErrConflict), errors.Is(e, backup.ErrInvalid), errors.Is(e, backup.ErrNoRestore), errors.Is(e, backup.ErrQuarantined):
			detail = e
			return ErrAdminConflict // logical: rolls the whole request back
		}
		return e
	})
	if detail != nil {
		return nil, detail
	}
	if err != nil {
		return nil, err
	}
	if err = a.changed(ctx); err != nil {
		return results, err
	}
	return results, nil
}
