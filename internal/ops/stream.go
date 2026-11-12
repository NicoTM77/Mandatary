package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

// LogStream is the handle returned for container:logs. It owns the authorizer lease
// the stream was admitted under and ends, deterministically, when that
// authorization ends: token, session or policy revocation or expiry, target or
// safety-state change (push: Service.NotifyAuthorityChange or the authorizer's own
// notifications; pull: the stream's revalidation tick), the consumer closing it, or
// the request context ending. Once ended it never yields another frame.
//
// A stream yields typed, labelled frames only; it exposes no raw byte pipe. Next
// calls are serialized; Close, Done and Revalidate are safe from any goroutine.
type LogStream struct {
	svc    *Service
	lease  *authz.Lease
	inner  docker.LogStream
	reqCtx context.Context

	readSem        chan struct{}
	consumerClosed atomic.Bool
	sticky         atomic.Pointer[error]
	watchDone      chan struct{}
}

func (s *Service) newLogStream(reqCtx context.Context, lease *authz.Lease, inner docker.LogStream) *LogStream {
	st := &LogStream{
		svc:       s,
		lease:     lease,
		inner:     inner,
		reqCtx:    reqCtx,
		readSem:   make(chan struct{}, 1),
		watchDone: make(chan struct{}),
	}
	// A transport read that ignores its context is still unblocked: ending the
	// authorization closes the backend stream.
	context.AfterFunc(lease.Context(), func() { _ = inner.Close() })
	go st.watch(s.newTicker(s.interval))
	return st
}

// watch is the pull path: it revalidates the stream's authorization every tick and
// releases the lease however the authorization ended.
func (st *LogStream) watch(tk Ticker) {
	defer close(st.watchDone)
	defer tk.Stop()
	ctx := st.lease.Context()
	defer st.lease.Release()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C():
			// reqCtx carries only values here: Revalidate detaches cancellation.
			if st.Revalidate(st.reqCtx) != nil {
				return
			}
		}
	}
}

// Revalidate re-checks the stream's authorization synchronously against current
// storage, credential, policy, target and safety state. A failure ends the stream
// before it returns (fail closed). It is detached from ctx's cancellation so one
// caller's ending request cannot fail-close its healthy sibling streams.
func (st *LogStream) Revalidate(ctx context.Context) error {
	if st == nil {
		return ErrStreamClosed
	}
	if err := st.terminalErr(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), st.svc.revalidateTimeout)
	defer cancel()
	if err := st.lease.Revalidate(rctx); err != nil {
		return err
	}
	return nil
}

// Done is closed as soon as the stream's authorization ends for any reason.
func (st *LogStream) Done() <-chan struct{} { return st.lease.Context().Done() }

// terminalErr reports why the stream can no longer deliver, or nil while live.
func (st *LogStream) terminalErr() error {
	if p := st.sticky.Load(); p != nil {
		return *p
	}
	if st.consumerClosed.Load() {
		return ErrStreamClosed
	}
	if st.lease.Context().Err() != nil {
		if cerr := st.reqCtx.Err(); cerr != nil {
			return docker.SanitizeError(cerr)
		}
		return ErrStreamRevoked
	}
	return nil
}

func streamErr(err error) error {
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	return docker.SanitizeError(err)
}

// finish records a sticky terminal outcome and releases everything.
func (st *LogStream) finish(err error) {
	mapped := streamErr(err)
	st.sticky.CompareAndSwap(nil, &mapped)
	st.lease.Release()
	_ = st.inner.Close()
}

// Next returns the next frame. ctx bounds this read: cancelling it while the read is
// in progress returns ctx's error and ends the stream, because a backend stream
// cannot resume after an interrupted read. Cancelling it while merely waiting for
// another consumer's read leaves the stream untouched. Revocation or expiry, a
// closed stream or an ended request context return the stream's terminal error
// instead, and no frame read concurrently with that end is delivered.
func (st *LogStream) Next(ctx context.Context) (docker.LogFrame, error) {
	if st == nil {
		return docker.LogFrame{}, ErrStreamClosed
	}
	if ctx == nil {
		return docker.LogFrame{}, ErrInvalidRequest
	}
	if err := st.terminalErr(); err != nil {
		return docker.LogFrame{}, err
	}
	select {
	case st.readSem <- struct{}{}:
		defer func() { <-st.readSem }()
	case <-ctx.Done():
		return docker.LogFrame{}, docker.SanitizeError(ctx.Err())
	case <-st.lease.Context().Done():
		return docker.LogFrame{}, st.terminalErr()
	}
	if err := st.terminalErr(); err != nil {
		return docker.LogFrame{}, err
	}

	rctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(st.lease.Context(), cancel)
	frame, err := st.inner.Next(rctx)
	stop()
	cancel()

	// Post-I/O fence: a frame read while the authorization ended is discarded.
	if terr := st.terminalErr(); terr != nil {
		return docker.LogFrame{}, terr
	}
	if err != nil {
		// Backend streams cannot resume after an interrupted read (the read
		// position is unknowable), so a read ended by ctx ends the stream too.
		if cerr := ctx.Err(); cerr != nil {
			err = cerr
		}
		st.finish(err)
		return docker.LogFrame{}, *st.sticky.Load()
	}
	return frame, nil
}

// Close ends the stream, releases its lease and closes the backend stream. It is
// idempotent and unblocks a pending Next.
func (st *LogStream) Close() error {
	if st == nil {
		return nil
	}
	if st.lease.Context().Err() == nil {
		st.consumerClosed.Store(true)
	}
	st.lease.Release()
	_ = st.inner.Close()
	return nil
}

const redactedStream = "ops.LogStream{[REDACTED]}"

func (st *LogStream) String() string   { return redactedStream }
func (st *LogStream) GoString() string { return redactedStream }
func (st *LogStream) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedStream))
}
func (st *LogStream) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedStream + `"`), nil }
func (st *LogStream) LogValue() slog.Value         { return slog.StringValue(redactedStream) }
