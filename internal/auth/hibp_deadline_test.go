package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestHIBPDeadlineAndOfflineFloor(t *testing.T) {
	calls := 0
	policy := DefaultPolicy()
	policy.hibp = newHIBP(roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Error("unbounded outbound deadline")
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	if _, e := policy.Validate(context.Background(), []byte("password1"), true, nil); e == nil || calls != 0 {
		t.Fatal("offline floor consulted network")
	}
	if _, e := policy.Validate(context.Background(), []byte("synthetic uncommon public timeout phrase"), false, nil); e != nil || calls != 1 {
		t.Fatal("timeout did not retain offline fallback")
	}
}
