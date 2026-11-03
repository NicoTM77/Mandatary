// Package fixtures provides synthetic test inputs, not authentication decisions.
package fixtures

import (
	"testing"
	"time"
)

func TestSyntheticClockAndInputsAreDeterministic(t *testing.T) {
	clock := NewClock()
	before := clock.Now()
	clock.Advance(time.Minute)
	if clock.Now().Sub(before) != time.Minute || before.Location() != time.UTC {
		t.Fatal("fixture clock is not deterministic UTC")
	}
	first, second := Credentials(), Credentials()
	if len(first) != 4 || first[0].ExpiresAt != before.Add(time.Hour) || !first[1].Revoked || !first[2].Quarantined || !first[3].ExpiresAt.Before(before) {
		t.Fatal("missing active/revoked/quarantined/expired synthetic inputs")
	}
	first[0].ID = "changed"
	if second[0].ID != "synthetic-active" {
		t.Fatal("credential fixtures share mutable state")
	}
	targets := Targets()
	if len(targets) != 3 || targets[0].Endpoint == targets[1].Endpoint || targets[0].Name != targets[1].Name || !targets[2].Protected {
		t.Fatal("missing cross-endpoint/synthetic protected target inputs")
	}
}
