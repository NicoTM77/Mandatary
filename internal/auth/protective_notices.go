package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/NicoTM77/Mandatary/internal/store"
)

type noticeRecipient struct {
	ID      string
	Version int64
	Address string
}

// A failed notice write must not make the enclosing protective transaction roll
// back a revocation. Poison acknowledgement, but let Control commit the actual
// credential/session invalidation. Where storage permits, retain an unmatched
// minimal event as operator-visible evidence; it is never silently retargeted.
func (l *Lifecycle) protectiveIntent(ctx context.Context, q *store.Queries, c store.InstallationControl, user, event string, now int64) error {
	if e := l.writeProtectiveIntent(ctx, q, c, user, event, now); e != nil {
		l.repo.FailClosed()
		reference := sha256.Sum256([]byte(fmt.Sprintf("protective:%s:%s:%d:%d", user, event, now, c.AuthorityGeneration)))
		id := hex.EncodeToString(reference[:])
		_ = q.CreateSecurityEvent(ctx, store.CreateSecurityEventParams{ID: id, UserID: user, EventType: event, OccurredAt: now, RetainUntil: now + 30*86400, DeduplicationKey: id})
	}
	return nil
}

func (l *Lifecycle) writeProtectiveIntent(ctx context.Context, q *store.Queries, c store.InstallationControl, user, event string, now int64) error {
	all, e := q.ListNotificationAddresses(ctx, user)
	if e != nil {
		return e
	}
	recipients := []noticeRecipient{}
	for _, a := range all {
		if a.State == "active" && a.VerifiedAt.Valid && !a.RevokedAt.Valid && a.AuthorityGeneration == c.AuthorityGeneration {
			recipients = append(recipients, noticeRecipient{ID: a.ID, Version: a.Version, Address: a.Address})
		}
	}
	data, e := json.Marshal(recipients)
	if e != nil {
		return e
	}
	id, e := randomID()
	if e != nil {
		return e
	}
	return q.CreateProtectiveIntent(ctx, store.CreateProtectiveIntentParams{ID: id, UserID: user, EventType: event, OccurredAt: now, AuthorityGeneration: c.AuthorityGeneration, Recipients: string(data)})
}

// Expand only CURRENT local intents. Restore must quarantine these local
// controls, never import/replay old records. Snapshot recipients are never
// resolved again, so correcting an address cannot silently retarget an alert.
// An outbox failure leaves the original revocation and intent durably committed.
// After repair/reopen, dispatch retries expansion without reviving credentials.
func (l *Lifecycle) expandProtectiveIntents(ctx context.Context) error {
	e := l.repo.Control(ctx, func(q *store.Queries) error {
		c, e := q.GetInstallationControl(ctx)
		if e != nil || !activeControl(c) {
			return ErrDenied
		}
		intents, e := q.ListProtectiveIntents(ctx, c.AuthorityGeneration)
		if e != nil {
			return e
		}
		for _, intent := range intents {
			var recipients []noticeRecipient
			if e = json.Unmarshal([]byte(intent.Recipients), &recipients); e != nil || len(recipients) == 0 {
				return ErrDenied
			}
			queued, e := q.NoticeQueueSize(ctx)
			if e != nil {
				return e
			}
			if int64(len(recipients)) > 1024-queued {
				return nil
			}
			if e = q.CreateSecurityEvent(ctx, store.CreateSecurityEventParams{ID: intent.ID, UserID: intent.UserID, EventType: intent.EventType, OccurredAt: intent.OccurredAt, RetainUntil: intent.OccurredAt + 30*86400, DeduplicationKey: intent.ID}); e != nil {
				return e
			}
			for _, r := range recipients {
				id, e := randomID()
				if e != nil {
					return e
				}
				if e = q.ReadyNoticeIntent(ctx, store.ReadyNoticeIntentParams{ID: id, EventID: intent.ID, UserID: intent.UserID, AddressID: r.ID, AddressVersion: r.Version, RecipientSnapshot: r.Address, RetainUntil: intent.OccurredAt + 30*86400, AuthorityGeneration: intent.AuthorityGeneration}); e != nil {
					return e
				}
			}
			n, e := q.MarkProtectiveIntentExpanded(ctx, intent.ID)
			if e != nil || n != 1 {
				return ErrDenied
			}
		}
		return nil
	}, nil)
	if e != nil {
		return ErrDenied
	}
	return nil
}
