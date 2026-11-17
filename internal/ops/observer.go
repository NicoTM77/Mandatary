package ops

import (
	"context"
	"time"
)

// DispatchObserver is told, at most once per Execute and only for stop and restart, that the
// operation has passed authorization (a lease is registered and the decision still stands) and that
// its backend call is about to start under a deadline of bound. It runs on the Execute goroutine
// before the call, must not block and receives nothing but a duration: no identity, target, name or
// error ever reaches it.
//
// It exists for one reason. A transport bounds how long a response may take to be written (the
// product server's WriteTimeout is 10 s), while a stop or restart is allowed timeout_seconds plus
// StopGrace (25 s by default, up to 315 s). Without the notice the transport would drop the result
// of an operation the daemon had already executed and the service had already counted as allowed.
// The notice is given only after authorization, so an unauthenticated, invalid or denied request
// never gets more time than the server-wide bound.
type DispatchObserver func(bound time.Duration)

type dispatchObserverKey struct{}

// WithDispatchObserver returns a context that carries observe for Execute.
func WithDispatchObserver(ctx context.Context, observe DispatchObserver) context.Context {
	return context.WithValue(ctx, dispatchObserverKey{}, observe)
}

// DispatchObserverFrom returns the observer carried by ctx, or nil.
func DispatchObserverFrom(ctx context.Context) DispatchObserver {
	observe, _ := ctx.Value(dispatchObserverKey{}).(DispatchObserver)
	return observe
}
