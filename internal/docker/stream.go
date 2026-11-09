package docker

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// This cause distinguishes our fail-closed watchdog from consumer deadlines.
var errStreamCheckDeadline = errors.New("stream continuity check deadline")

func isStreamConsumerAbort(ctx context.Context, err error) bool {
	if ctx.Err() == nil || context.Cause(ctx) == errStreamCheckDeadline {
		return false
	}
	// SDK/url wrappers around the canceled request are local. A multi-error
	// (e.g. cancellation joined with an observed connection fault) is uncertain,
	// not a pure cancellation; errors.Is alone would mask its other branches.
	for err != nil {
		if err == ctx.Err() {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}

// safetyLogStream keeps inventory continuity an admission condition for both
// framed and buffered reads. The bounded watcher also cancels idle follow I/O;
// explicit event/reconnect invalidation still cancels immediately via ctx.
type safetyLogStream struct {
	inner     LogStream
	ctx       context.Context
	cancel    context.CancelFunc
	check     func(context.Context) error
	onError   func(error) error
	once      sync.Once
	watchDone chan struct{}
}

func guardLogStream(ctx context.Context, inner LogStream, check func(context.Context) error, onError func(error) error) *safetyLogStream {
	ctx, cancel := context.WithCancel(ctx)
	s := &safetyLogStream{inner: inner, ctx: ctx, cancel: cancel, check: check, onError: onError, watchDone: make(chan struct{})}
	go func() {
		defer close(s.watchDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer func() { _ = s.Close() }()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if s.verify(ctx) != nil {
					return
				}
			}
		}
	}()
	return s
}

func (s *safetyLogStream) verify(ctx context.Context) error {
	if s.ctx.Err() != nil {
		return ErrUnverified
	}
	if ctx.Err() != nil {
		return SanitizeError(ctx.Err())
	}
	checkCtx, cancel := context.WithTimeoutCause(ctx, 2*time.Second, errStreamCheckDeadline)
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	if err := s.check(checkCtx); err != nil {
		_ = s.Close()
		return ErrUnverified
	}
	if s.ctx.Err() != nil {
		return ErrUnverified
	}
	if ctx.Err() != nil {
		return SanitizeError(ctx.Err())
	}
	return nil
}

func (s *safetyLogStream) result(err error) error {
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrLogLimitExceeded) && s.ctx.Err() == nil {
		return s.onError(err)
	}
	return err
}

func (s *safetyLogStream) Next(ctx context.Context) (LogFrame, error) {
	if err := s.verify(ctx); err != nil {
		return LogFrame{}, err
	}
	frame, err := s.inner.Next(ctx)
	if err != nil {
		// A canceled consumer read is not proof of daemon loss. The body
		// observer already revoked synchronously if it saw a live I/O fault.
		// In particular, local body Close may still be unwinding before the
		// stream unregisters from safety and cancels our parent context.
		if ctx.Err() != nil {
			return LogFrame{}, SanitizeError(ctx.Err())
		}
		return LogFrame{}, s.result(err)
	}
	if err = s.verify(ctx); err != nil {
		return LogFrame{}, err
	}
	return frame, nil
}

func (s *safetyLogStream) Read(p []byte) (int, error) {
	if err := s.verify(s.ctx); err != nil {
		return 0, err
	}
	// Do not write into the caller's buffer until post-I/O continuity is proven.
	buf := make([]byte, min(len(p), MaxLogFrameBytes))
	n, err := s.inner.Read(buf)
	if err != nil {
		return 0, s.result(err)
	}
	if err = s.verify(s.ctx); err != nil {
		return 0, err
	}
	return copy(p, buf[:n]), nil
}

func (s *safetyLogStream) Close() error {
	s.once.Do(func() { s.cancel(); _ = s.inner.Close() })
	return nil
}
