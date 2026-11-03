// Package fixtures contains deliberately non-secret, non-production test data.
// These are inputs for later suites, NOT a substitute authorizer or auth service.
package fixtures

import (
	"sync"
	"time"
)

// Clock is deterministic and safe for concurrent test readers.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

func NewClock() *Clock                   { return &Clock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} }
func (c *Clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *Clock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

type Credential struct {
	ID          string
	ExpiresAt   time.Time
	Revoked     bool
	Quarantined bool
}

// Credentials returns independent active and adverse input states, no secrets.
func Credentials() []Credential {
	now := NewClock().Now()
	return []Credential{
		{ID: "synthetic-active", ExpiresAt: now.Add(time.Hour)},
		{ID: "synthetic-revoked", ExpiresAt: now.Add(time.Hour), Revoked: true},
		{ID: "synthetic-quarantined", ExpiresAt: now.Add(time.Hour), Quarantined: true},
		{ID: "synthetic-expired", ExpiresAt: now.Add(-time.Second)},
	}
}

type Target struct {
	Endpoint  string
	Name      string
	ID        string
	Protected bool
}

func Targets() []Target {
	return []Target{
		{Endpoint: "synthetic-local", Name: "sample", ID: "synthetic-a"},
		{Endpoint: "synthetic-other", Name: "sample", ID: "synthetic-b"},
		{Endpoint: "synthetic-local", Name: "mandatary", ID: "synthetic-self", Protected: true},
	}
}
