package auth

import (
	"context"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// NoticeStatus contains no recipients, SMTP diagnostics or credential material.
// P1.16/19 owns authenticated UI/readiness integration, not a public route here.
type NoticeStatus struct {
	Pending, Failed, Bounced, Quarantined, Protective int64
	Degraded                                          bool
}

func (l *Lifecycle) NoticeHealth(ctx context.Context) (NoticeStatus, error) {
	result := NoticeStatus{Degraded: true}
	e := l.repo.Read(ctx, func(q *store.Queries) error {
		n, e := q.GetNoticeHealth(ctx)
		if e != nil {
			return e
		}
		result = NoticeStatus{Pending: n.Pending, Failed: n.Failed, Bounced: n.Bounced, Quarantined: n.Quarantined, Protective: n.Protective}
		result.Degraded = n.Pending != 0 || n.Failed != 0 || n.Bounced != 0 || n.Quarantined != 0 || n.Protective != 0
		return nil
	})
	if e != nil {
		return NoticeStatus{Degraded: true}, ErrDenied
	}
	return result, nil
}

// AccountNoticeHealth is the delivery health of ONE account's own security notices: the same
// aggregate counts as NoticeHealth over that user's records only, with no recipient, event
// content or other account's count (P1.18.4 P116-L3, least privilege). An unreadable status is
// reported as degraded with ErrDenied, never as healthy.
func (l *Lifecycle) AccountNoticeHealth(ctx context.Context, userID string) (NoticeStatus, error) {
	result := NoticeStatus{Degraded: true}
	if userID == "" {
		return result, ErrDenied
	}
	e := l.repo.Read(ctx, func(q *store.Queries) error {
		n, e := q.GetAccountNoticeHealth(ctx, userID)
		if e != nil {
			return e
		}
		result = NoticeStatus{Pending: n.Pending, Failed: n.Failed, Bounced: n.Bounced, Quarantined: n.Quarantined, Protective: n.Protective}
		result.Degraded = n.Pending != 0 || n.Failed != 0 || n.Bounced != 0 || n.Quarantined != 0 || n.Protective != 0
		return nil
	})
	if e != nil {
		return NoticeStatus{Degraded: true}, ErrDenied
	}
	return result, nil
}

// RetryNotice is an explicit, fresh-maximum-assurance repair of this account's
// failed recipient record, not an address rewrite. Preserve lifetime attempts,
// snapshot, Message-ID and incident; allow at most three further eight-attempt
// cycles inside the original 30-day retention marker. Each cycle is at most72h.
func (l *Lifecycle) RetryNotice(ctx context.Context, session []byte, id string) error {
	e := l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, _, e := freshSession(ctx, q, session, now)
		if e != nil {
			return e
		}
		n, e := q.GetNotice(ctx, id)
		if e != nil || n.UserID != u.ID || n.AuthorityGeneration != c.AuthorityGeneration || n.DispatchState != "ready" || n.DeliveryState != "failed" {
			return ErrDenied
		}
		queued, e := q.NoticeQueueSize(ctx)
		if e != nil || queued >= 1024 {
			return ErrDenied
		}
		count, e := q.RetryNotice(ctx, store.RetryNoticeParams{ID: id, Now: nullable(now)})
		if e != nil || count != 1 {
			return ErrDenied
		}
		return nil
	}, nil)
	if e != nil {
		return ErrDenied
	}
	return nil
}
