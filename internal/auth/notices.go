package auth

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// A dispatcher invocation is bounded to 32 records and each network transaction
// to 10s. Four durable 30s leases bound concurrent workers across processes.
// Network I/O NEVER holds the security-control lock or delays revocation.
// A send/ack crash retains pending state and a stable Message-ID: at least once,
// not exactly once. SMTP success is explicitly relay acceptance, not delivery.
func (l *Lifecycle) DispatchNotices(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 32 || !l.notices.valid() {
		return 0, ErrDenied
	}
	if e := l.expandProtectiveIntents(ctx); e != nil {
		return 0, ErrDenied
	}
	submitted := 0
	for i := 0; i < limit; i++ {
		var notice store.NextNoticeRow
		var observedControl store.InstallationControl
		var token string
		claimed, processed := false, false
		e := l.repo.Control(ctx, func(q *store.Queries) error {
			c, e := q.GetInstallationControl(ctx)
			if e != nil {
				return e
			}
			if !activeControl(c) {
				return ErrDenied
			}
			observedControl = c
			now := l.now().Unix()
			if now < 0 || now > 253402300799 {
				return ErrDenied
			}
			notice, e = q.NextNotice(ctx, store.NextNoticeParams{Generation: c.AuthorityGeneration, Now: now})
			if errors.Is(e, sql.ErrNoRows) {
				return nil
			}
			if e != nil {
				return e
			}
			ageStart := notice.OccurredAt
			if notice.RetryStartedAt.Valid {
				ageStart = notice.RetryStartedAt.Int64
			}
			if now < ageStart {
				return ErrDenied
			}
			if notice.Attempts >= 8 || now-ageStart >= 72*3600 {
				n, e := q.FailExhaustedNotice(ctx, notice.ID)
				if e != nil || n != 1 {
					return ErrDenied
				}
				processed = true
				return nil
			}
			token, e = randomID()
			if e != nil {
				return e
			}
			n, e := q.ClaimNotice(ctx, store.ClaimNoticeParams{ID: notice.ID, Now: nullable(now), LeaseUntil: now + 30, Token: sql.NullString{String: token, Valid: true}})
			if e != nil || n != 1 {
				return ErrDenied
			}
			claimed = true
			return nil
		}, nil)
		if e != nil {
			return submitted, ErrDenied
		}
		if !claimed {
			if processed {
				continue // Counts against the finite per-invocation record budget.
			}
			break
		}
		failure := l.sendNotice(ctx, notice)
		e = l.repo.Control(ctx, func(q *store.Queries) error {
			current, e := q.GetInstallationControl(ctx)
			if e != nil || !activeControl(current) || current != observedControl {
				return ErrDenied
			}
			state := "relay-accepted"
			var fail sql.NullString
			var next sql.NullInt64
			if failure != "" {
				state = "pending"
				fail = sql.NullString{String: failure, Valid: true}
				attempts := notice.Attempts + 1
				ageStart := notice.OccurredAt
				if notice.RetryStartedAt.Valid {
					ageStart = notice.RetryStartedAt.Int64
				}
				if failure == "permanent" || failure == "recipient" || attempts >= 8 || l.now().Unix()-ageStart >= 72*3600 {
					state = "failed"
				} else {
					wait := noticeWait(attempts)
					next = nullable(l.now().Unix() + wait)
				}
			}
			n, e := q.FinishNotice(ctx, store.FinishNoticeParams{ID: notice.ID, Token: sql.NullString{String: token, Valid: true}, State: state, Failure: fail, NextAttempt: next})
			if e != nil || n != 1 {
				return ErrDenied
			}
			return nil
		}, nil)
		if e != nil {
			return submitted, ErrDenied
		}
		if failure == "" {
			submitted++
		}
	}
	return submitted, nil
}

func noticeWait(attempt int64) int64 {
	switch attempt {
	case 1:
		return 60
	case 2:
		return 120
	case 3:
		return 240
	case 4:
		return 480
	case 5:
		return 960
	case 6:
		return 1920
	default:
		return 3600
	}
}

// Only fixed classified outcomes leave this function; raw server diagnostics,
// addresses, authentication data and server echoes are never wrapped/logged.
func smtpFailure(e error) string {
	var reply *textproto.Error
	if errors.As(e, &reply) && reply.Code >= 500 && reply.Code <= 599 {
		return "permanent"
	}
	return "temporary"
}
func (l *Lifecycle) sendNotice(parent context.Context, n store.NextNoticeRow) string {
	if !validMailbox(n.RecipientSnapshot) {
		return "recipient"
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	host, _, e := net.SplitHostPort(l.notices.Relay)
	if e != nil {
		return "permanent"
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, e := dialer.DialContext(ctx, "tcp", l.notices.Relay)
	if e != nil {
		return "temporary"
	}
	defer func() { _ = conn.Close() }()
	deadline, ok := ctx.Deadline()
	if !ok || conn.SetDeadline(deadline) != nil {
		return "temporary"
	}
	// Freeze the underlying transport for cancellation. conn is subsequently
	// replaced with its TLS wrapper; capturing that mutable interface races a
	// cancellation arriving exactly as HandshakeContext completes.
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	tlsConfig := &tls.Config{ServerName: host, RootCAs: l.notices.RootCAs, MinVersion: tls.VersionTLS12}
	if l.notices.Mode == "implicit" {
		secure := tls.Client(conn, tlsConfig)
		if e = secure.HandshakeContext(ctx); e != nil {
			return "tls"
		}
		conn = secure
	}
	client, e := smtp.NewClient(conn, host)
	if e != nil {
		return smtpFailure(e)
	}
	defer func() { _ = client.Close() }()
	if l.notices.Mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return "tls"
		}
		if e = client.StartTLS(tlsConfig); e != nil {
			return "tls"
		}
	}
	if state, ok := client.TLSConnectionState(); !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return "tls"
	}
	if l.notices.Username != "" || l.notices.CredentialID != "" {
		if l.notices.Username == "" || l.notices.CredentialID == "" {
			return "auth"
		}
		password, e := l.repo.SMTPSecret(ctx, l.notices.CredentialID)
		if e != nil {
			return "auth"
		}
		defer clear(password)
		if e = client.Auth(smtp.PlainAuth("", l.notices.Username, string(password), host)); e != nil {
			return "auth"
		}
	}
	if e = client.Mail(l.notices.Sender); e != nil {
		return smtpFailure(e)
	}
	if e = client.Rcpt(n.RecipientSnapshot); e != nil {
		var reply *textproto.Error
		if errors.As(e, &reply) && reply.Code >= 500 {
			return "recipient"
		}
		return "temporary"
	}
	data, e := client.Data()
	if e != nil {
		return smtpFailure(e)
	}
	// Only schema-allowlisted event types and server-generated IDs appear in the
	// payload. No password, code, seed, bearer, approval link or Docker content.
	reference := n.EventID
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Mandatary security event\r\nMessage-ID: <%s.%s@mandatary.invalid>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSecurity event: %s\r\nUTC: %s\r\nAccount reference: %s\r\nIf this was not you, dispute this event through %s. This message does not authorize any access.\r\nService: %s\r\nRelay acceptance is not proof of inbox delivery or human receipt.\r\n", l.notices.Sender, n.RecipientSnapshot, reference, n.ID, n.EventType, time.Unix(n.OccurredAt, 0).UTC().Format(time.RFC3339), n.UserID, l.notices.Contact, strings.TrimSuffix(l.notices.Origin, "/"))
	if _, e = data.Write([]byte(message)); e != nil {
		return "ambiguous"
	}
	if e = data.Close(); e != nil {
		return "ambiguous"
	}
	// A failed QUIT after DATA's successful 250 cannot erase relay acceptance.
	_ = client.Quit()
	return ""
}
