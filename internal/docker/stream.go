package docker

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// safetyLogStream keeps inventory continuity an admission condition for both
// framed and buffered reads. The bounded watcher also cancels idle follow I/O;
// explicit event/reconnect invalidation still cancels immediately via ctx.
type safetyLogStream struct {
	inner   LogStream
	ctx     context.Context
	cancel  context.CancelFunc
	check   func(context.Context) error
	onError func(error) error
	once    sync.Once
}

func guardLogStream(ctx context.Context, inner LogStream, check func(context.Context) error, onError func(error) error) *safetyLogStream {
	ctx, cancel := context.WithCancel(ctx)
	s := &safetyLogStream{inner: inner, ctx: ctx, cancel: cancel, check: check, onError: onError}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer s.Close()
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
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
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
