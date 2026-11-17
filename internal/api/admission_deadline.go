package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/NicoTM77/Mandatary/internal/ops"
)

// AdmittedWriteMargin is added to an admitted stop/restart's own dispatch bound to give the response
// itself time to be written once the operation is over.
const AdmittedWriteMargin = 5 * time.Second

// WithAdmissionDeadline returns r carrying an ops.DispatchObserver that lets THIS connection's response
// be written for as long as the admitted operation itself may run.
//
// The product server bounds every response write to 10 s, while an admitted one-shot stop or restart
// may run timeout_seconds plus StopGrace (25 s by default, up to 315 s): without this the client loses
// the result (an EOF, behind the shipped proxy a 502 with an empty body) of an operation the daemon
// already executed and the service already counted as allowed. The shared service announces the bound
// only after authorization and immediately before the backend call, so an unauthenticated, invalid,
// denied or unverified request never gets more than the server-wide bound, and no other route changes.
// Only the write deadline moves (the 10 s read bound ends with the request and does not cancel a
// running handler: pinned by the tests). The deadline only ever moves forward, so a second
// announcement can never shorten the first.
func WithAdmissionDeadline(w http.ResponseWriter, r *http.Request) *http.Request {
	rc := http.NewResponseController(w)
	var (
		mu     sync.Mutex
		latest time.Time
	)
	observe := func(bound time.Duration) {
		deadline := time.Now().Add(bound + AdmittedWriteMargin)
		mu.Lock()
		defer mu.Unlock()
		if !deadline.After(latest) {
			return
		}
		latest = deadline
		_ = rc.SetWriteDeadline(deadline)
	}
	return r.WithContext(ops.WithDispatchObserver(r.Context(), observe))
}
