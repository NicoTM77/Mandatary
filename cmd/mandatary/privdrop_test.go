//go:build linux

package main

import "testing"

// The effective setgroups/setgid/setuid sequence needs CAP_SETUID/CAP_SETGID and is
// therefore verified only by the documented operator procedure; this unprivileged
// test covers the refusal rules that must hold before any syscall is attempted.
func TestDropPrivilegesRefusesPrivilegedIdentities(t *testing.T) {
	for _, ids := range [][2]int{{0, 0}, {0, 1000}, {1000, 0}, {-1, 1000}, {1000, -1}} {
		if err := dropPrivileges(ids[0], ids[1]); err == nil {
			t.Fatalf("dropPrivileges(%d,%d) accepted", ids[0], ids[1])
		}
	}
}
