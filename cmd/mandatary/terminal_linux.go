//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// hostTerminal implements auth.Terminal on the process's real controlling
// terminal. The secret bypasses slog and is written to stdout only after Verify
// proved stdin, stdout and stderr are all that terminal (S3.1a).
type hostTerminal struct{ out io.Writer }

func newHostTerminal() *hostTerminal { return &hostTerminal{out: os.Stdout} }

var errNotTerminal = errors.New("not a controlling terminal")

// Verify refuses pipes, files, sockets, redirections and a terminal that is not
// this process's controlling terminal. TIOCGSID succeeds only on the caller's
// controlling terminal and must equal the caller's session, so a different
// terminal (or none) is rejected. It runs BEFORE any claim or plaintext access.
func (t *hostTerminal) Verify() error {
	sid, err := unix.Getsid(0)
	if err != nil {
		return errNotTerminal
	}
	for _, fd := range []int{0, 1, 2} {
		if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err != nil {
			return errNotTerminal
		}
		terminalSession, err := unix.IoctlGetInt(fd, unix.TIOCGSID)
		if err != nil || terminalSession != sid {
			return errNotTerminal
		}
	}
	return nil
}

// WriteSecret performs one bounded write. A timeout/partial/failed write is
// reported as failure and treated by the protocol as uncertain delivery.
func (t *hostTerminal) WriteSecret(ctx context.Context, data []byte) error {
	// The writer owns a private copy: after a timeout or cancellation this call
	// returns while the goroutine may still be blocked in Write, and the caller
	// clears its payload on return. The copy is wiped once the write ends.
	own := append([]byte(nil), data...)
	done := make(chan error, 1)
	go func() {
		defer clear(own)
		n, err := t.out.Write(own)
		if err == nil && n != len(own) {
			err = io.ErrShortWrite
		}
		done <- err
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return errors.New("terminal write timed out")
	case <-ctx.Done():
		return ctx.Err()
	}
}
