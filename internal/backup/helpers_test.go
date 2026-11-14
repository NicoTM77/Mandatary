package backup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
)

var snapshotTables = []string{"users", "groups", "agents", "user_group_memberships", "agent_group_memberships", "administrative_roles", "endpoints", "container_selectors",
	"policies", "notification_addresses", "authenticators", "agent_credentials", "webauthn_users", "webauthn_credentials", "sessions", "usage_stats_hourly", "restore_reports", "restore_manifest"}

// snapshot is a canonical dump of every table a restore may touch, so a failed restore can be proven
// to have changed nothing byte for byte.
func (e *env) snapshot() map[string]string {
	e.t.Helper()
	out := map[string]string{}
	for _, table := range snapshotTables {
		rows, err := e.db.Query(`SELECT * FROM ` + table + ` ORDER BY 1,2`)
		if err != nil {
			e.t.Fatal(err)
		}
		cols, _ := rows.Columns()
		var buf bytes.Buffer
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				e.t.Fatal(err)
			}
			fmt.Fprintf(&buf, "%v\n", values)
		}
		_ = rows.Close()
		out[table] = buf.String()
	}
	c := e.controls()
	out["installation_control"] = fmt.Sprintf("%+v", c)
	return out
}

func (e *env) sameExceptControl(before map[string]string) {
	e.t.Helper()
	after := e.snapshot()
	var diff []string
	for k, v := range before {
		if k == "installation_control" {
			continue
		}
		if after[k] != v {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	if len(diff) > 0 {
		e.t.Fatalf("tables changed: %v", diff)
	}
}

// sign re-signs a modified archive with this installation's own key: the position of an attacker
// who HOLDS the master key. The result is authentic and still must not become authority.
func (e *env) sign(raw []byte, f func(a *Archive)) []byte {
	e.t.Helper()
	var a Archive
	if err := json.Unmarshal(raw, &a); err != nil {
		e.t.Fatal(err)
	}
	f(&a)
	canonical, err := a.canonical()
	if err != nil {
		e.t.Fatal(err)
	}
	salt, err := base64.StdEncoding.DecodeString(a.HMACSalt)
	if err != nil {
		e.t.Fatal(err)
	}
	key, err := e.repo.DeriveBackupKey(integrityInfo, salt)
	if err != nil {
		e.t.Fatal(err)
	}
	a.ContentDigest = digestOf(canonical)
	a.IntegrityHMAC = tagOf(key, canonical)
	out, err := json.Marshal(a)
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) activeAuthority() int64 {
	e.t.Helper()
	return e.scalar(`SELECT (SELECT count(*) FROM users WHERE state='active')+(SELECT count(*) FROM groups WHERE state='active')+(SELECT count(*) FROM agents WHERE state='active')
 +(SELECT count(*) FROM user_group_memberships WHERE state='active')+(SELECT count(*) FROM agent_group_memberships WHERE state='active')+(SELECT count(*) FROM administrative_roles WHERE state='active')
 +(SELECT count(*) FROM policies WHERE state='active')+(SELECT count(*) FROM endpoints WHERE state='active')+(SELECT count(*) FROM notification_addresses WHERE state='active')
 +(SELECT count(*) FROM authenticators WHERE state='active')+(SELECT count(*) FROM agent_credentials WHERE state='active')+(SELECT count(*) FROM sessions WHERE state='active')`)
}

func mustErrorIs(t *testing.T, err, want error) {
	t.Helper()
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("error %v, want %v", err, want)
	}
}
