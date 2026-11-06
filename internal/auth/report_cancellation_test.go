package auth

import (
	"context"
	"testing"
)

func TestAuthorizedProtectiveIntentSurvivesCallerDisconnect(t *testing.T) {
	s, _, db := serviceFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e := s.MarkCompromised(ctx, "u"); e != nil {
		t.Fatal("authorized protective report canceled by transport", e)
	}
	if scalarFixture(t, db, `SELECT compromised FROM users WHERE id='u'`) != 1 {
		t.Fatal("report not durable")
	}
}
