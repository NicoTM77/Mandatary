package auth

import (
	"context"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestProtectiveReportControlAdmissionFailureStopsAcceptance(t *testing.T) {
	s, r, db := serviceFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.Control(ctx, func(_ *store.Queries) error {
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}, nil)
	}()
	<-held
	// Hold the real shared control lock past storage's admission deadline within
	// the report's bounded timeout: failure BEFORE its callback, not a write trigger.
	report := s.MarkCompromised(t.Context(), "u")
	close(release)
	if e := <-done; e != store.ErrStorage {
		t.Fatal("in-flight lock holder acknowledged after protective failure", e)
	}
	if report != ErrDenied || scalarFixture(t, db, `SELECT compromised FROM users WHERE id='u'`) != 0 {
		t.Fatal("blocked protective intent was acknowledged or unexpectedly persisted")
	}
	if _, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.2"); e != ErrDenied {
		t.Fatal("unpersisted authorized protective report left password acceptance enabled")
	}
}

func TestMissingProtectiveReportTargetDoesNotPoisonOtherAccounts(t *testing.T) {
	s, _, _ := serviceFixture(t)
	if e := s.MarkCompromised(context.Background(), "synthetic-missing-user"); e != ErrDenied {
		t.Fatal("missing target acknowledged")
	}
	if _, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.2"); e != nil {
		t.Fatal("known absent target disabled an unrelated account")
	}
}
