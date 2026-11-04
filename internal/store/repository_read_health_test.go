package store

import (
	"context"
	"database/sql"
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestQueuedReadRechecksHealth(t *testing.T) {
	for _, active := range []bool{false, true} {
		for _, poison := range []bool{false, true} {
			name := "Read"
			if active {
				name = "ReadActive"
			}
			if poison {
				name += "/poisoned"
			} else {
				name += "/healthy"
			}
			t.Run(name, func(t *testing.T) {
				r, _ := openFixture(t)
				// Explicit test-only activation makes ReadActive's positive path
				// reachable; a quarantine denial cannot mask the health regression.
				if _, err := r.writer.ExecContext(t.Context(), `UPDATE installation_control SET credential_generation=1,session_generation=1,authority_generation=1,restore_generation=1,restore_quarantined=0`); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				var held []*sql.Conn
				for range r.readers.Stats().MaxOpenConnections {
					conn, err := r.readers.Conn(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = conn.Close() }()
					held = append(held, conn)
				}
				before := r.readers.Stats().WaitCount
				done := make(chan error, 1)
				called := false
				go func() {
					callback := func(*Queries) error { called = true; return nil }
					if active {
						done <- r.ReadActive(ctx, Generations{Credential: 1, Session: 1, Authority: 1, Restore: 1}, callback)
					} else {
						done <- r.Read(ctx, callback)
					}
				}()
				// Observe actual database/sql pool contention, not a sleep guess.
				for r.readers.Stats().WaitCount == before {
					if ctx.Err() != nil {
						t.Fatal("read never queued on saturated pool")
					}
					runtime.Gosched()
				}
				if poison {
					poisonFixture(t, r)
				}
				if err := held[0].Close(); err != nil {
					t.Fatal(err)
				}
				err := <-done
				if poison {
					if !errors.Is(err, ErrStorage) || called {
						t.Fatal("queued read continued after uncertain delivery")
					}
				} else if err != nil || !called {
					t.Fatal("healthy queued read refused")
				}
			})
		}
	}
}

func poisonFixture(t *testing.T, r *Repository) {
	t.Helper()
	err := r.Control(t.Context(), func(*Queries) error { return nil }, func() error {
		return errors.New("synthetic uncertain delivery")
	})
	if !errors.Is(err, ErrStorage) || !r.poisoned.Load() {
		t.Fatal("control did not poison fixture")
	}
}

func TestReadDeniesPoisonDuringCallback(t *testing.T) {
	r, _ := openFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.Read(t.Context(), func(*Queries) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	poisonFixture(t, r)
	close(release)
	if err := <-done; !errors.Is(err, ErrStorage) {
		t.Fatal("read acknowledged after observing uncertain handle")
	}
}
