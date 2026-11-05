package store

import (
	"errors"
	"os"
	"testing"
)

func TestControlPoisonTerminatesInFlightAcknowledgement(t *testing.T) {
	for _, phase := range []string{"callback", "sync", "delivery"} {
		t.Run(phase, func(t *testing.T) {
			r, _ := openFixture(t)
			if phase == "sync" {
				r.syncFile = func(f *os.File) error { r.FailClosed(); return f.Sync() }
			}
			delivered := false
			err := r.Control(t.Context(), func(q *Queries) error {
				if err := q.CreateUser(t.Context(), CreateUserParams{ID: "unacknowledged", Username: "unacknowledged"}); err != nil {
					return err
				}
				if phase == "callback" {
					r.FailClosed()
				}
				return nil
			}, func() error {
				delivered = true
				if phase == "delivery" {
					r.FailClosed()
				}
				return nil
			})
			if !errors.Is(err, ErrStorage) {
				t.Fatal("poisoned in-flight control acknowledged success")
			}
			if phase != "delivery" && delivered {
				t.Fatal("delivery began after terminal poison")
			}
			var count int
			if err := r.readers.QueryRowContext(t.Context(), `SELECT count(*) FROM users WHERE id='unacknowledged'`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatal("terminal poison erased a successfully evaluated control update")
			}
		})
	}
}
