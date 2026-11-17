package api_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// deadlineWriter records every write deadline the handler sets, like the server's connection.
type deadlineWriter struct {
	http.ResponseWriter
	mu        sync.Mutex
	deadlines []time.Time
}

func (d *deadlineWriter) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deadlines = append(d.deadlines, t)
	return nil
}

func (d *deadlineWriter) set() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.deadlines...)
}

// P120-F2-API-01: the observer sets the write deadline to the announced bound plus the margin, only
// moves it forward, and does nothing until the service announces (a request that is never admitted
// leaves the connection's own bound untouched).
func TestAdmissionDeadlineExtendsOnlyOnAnnouncementAndOnlyForward(t *testing.T) {
	w := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	r := api.WithAdmissionDeadline(w, httptest.NewRequest(http.MethodPost, "/x", nil))
	observe := ops.DispatchObserverFrom(r.Context())
	if observe == nil {
		t.Fatal("no observer on the request context")
	}
	if got := w.set(); len(got) != 0 {
		t.Fatalf("a deadline was set before any announcement: %v", got)
	}
	before := time.Now()
	observe(25 * time.Second)
	got := w.set()
	if len(got) != 1 {
		t.Fatalf("deadlines after one announcement = %v", got)
	}
	want := before.Add(25*time.Second + api.AdmittedWriteMargin)
	if got[0].Before(want) || got[0].After(want.Add(2*time.Second)) {
		t.Fatalf("deadline %v, want about %v (bound + margin)", got[0], want)
	}
	observe(time.Second) // a shorter announcement must never shorten it
	if n := len(w.set()); n != 1 {
		t.Fatalf("a shorter announcement moved the deadline backwards (%d writes)", n)
	}
	observe(300 * time.Second)
	if all := w.set(); len(all) != 2 || !all[1].After(all[0]) {
		t.Fatalf("a longer announcement did not extend: %v", all)
	}
}

// A writer that cannot take a deadline (recorder, wrapper without support) must not break the request.
func TestAdmissionDeadlineOnAWriterWithoutDeadlineSupportIsHarmless(t *testing.T) {
	r := api.WithAdmissionDeadline(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/x", nil))
	ops.DispatchObserverFrom(r.Context())(25 * time.Second)
}
