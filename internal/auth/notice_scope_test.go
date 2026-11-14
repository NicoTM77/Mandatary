package auth

import (
	"net/http"
	"strings"
	"testing"
)

// P1.18.4 P116-L3 (least privilege): the security inventory shows an ordinary signed-in
// user ONLY the delivery health of that user's own notices. Another account's notices (and
// their count) must neither appear nor change what this user sees; the server computes
// this scope, the page never merely hides totals. Fixtures are real SQLite rows.

func (h *securityHarness) seedNotice(user, address, id, delivery, dispatch string) {
	h.t.Helper()
	h.e.exec(`INSERT INTO security_events(id,user_id,event_type,occurred_at,retain_until,deduplication_key) VALUES(?,?,'authenticator_bound',2000000000,2002592000,?)`, id, user, "dedup-"+id)
	h.e.exec(`INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,delivery_state,dispatch_state,authority_generation,retain_until,attempts,last_attempt_at,failure_code) VALUES(?,?,?,?,1,?,?,?,1,2002592000,?,?,?)`,
		id, id, user, address, "recipient-"+id+"@example.invalid", delivery, dispatch, map[string]int{"failed": 1, "bounced": 1}[delivery], map[bool]any{true: int64(2000000001), false: nil}[delivery == "failed" || delivery == "bounced"],
		map[bool]any{true: "temporary", false: nil}[delivery == "failed"])
}

func TestSecurityInventoryNoticeCountsAreScopedToTheSignedInAccount(t *testing.T) {
	h := newSecurityHarness(t)
	s := h.signIn()
	// Signing in already produced this account's own (healthy or pending) notices: measure, do not assume.
	base := h.inventory(s).Notices
	h.e.exec(`INSERT INTO users(id,username,state,credential_generation,authority_generation) VALUES('v','synthetic-other','active',1,1)`)
	h.e.exec(`INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('vaddr','v','other@example.invalid',1,1,1,'active',1)`)

	// Another account has every kind of unhealthy notice; this account has none.
	h.seedNotice("v", "vaddr", "v-pending", "pending", "ready")
	h.seedNotice("v", "vaddr", "v-failed", "failed", "ready")
	h.seedNotice("v", "vaddr", "v-bounced", "bounced", "ready")
	h.seedNotice("v", "vaddr", "v-quarantined", "pending", "quarantined")
	h.e.exec(`INSERT INTO protective_notice_intents VALUES('v-intent','v','authenticator_suspended',2000000009,1,'[{"ID":"vaddr","Version":1,"Address":"other@example.invalid"}]','pending')`)
	h.e.exec(`INSERT INTO security_events(id,user_id,event_type,occurred_at,retain_until,deduplication_key) VALUES('v-removed','v','authenticator_removed',2000000010,2002592010,'dedup-v-removed')`)

	inv := h.inventory(s)
	if inv.Notices != base || inv.Notices.Unknown {
		t.Fatalf("an ordinary user saw another account's notice health: %+v (own baseline %+v)", inv.Notices, base)
	}
	// The raw body carries no recipient, event or other account identifier either.
	body := h.get(s, AccountSecurityPath).Body.String()
	for _, leak := range []string{"other@example.invalid", "recipient-v-", "synthetic-other", "vaddr", "v-failed", `"v"`} {
		if strings.Contains(body, leak) {
			t.Fatalf("the inventory leaks %q: %s", leak, body)
		}
	}

	// This account's own notices ARE counted, exactly, and the other account's still are not.
	h.e.exec(`INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('uaddr2','u','own-second@example.invalid',1,1,1,'active',1)`)
	h.seedNotice("u", "uaddr2", "u-failed", "failed", "ready")
	h.seedNotice("u", "uaddr2", "u-pending", "pending", "ready")
	h.e.exec(`INSERT INTO security_events(id,user_id,event_type,occurred_at,retain_until,deduplication_key) VALUES('u-removed','u','authenticator_removed',2000000011,2002592011,'dedup-u-removed')`)
	inv = h.inventory(s)
	want := base
	want.Pending, want.Failed, want.Protective = base.Pending+1, base.Failed+1, base.Protective+1
	if inv.Notices != want {
		t.Fatalf("own notice counts wrong: %+v, want %+v", inv.Notices, want)
	}

	// More notices of the other account never move this user's numbers.
	h.seedNotice("v", "vaddr", "v-failed-2", "failed", "ready")
	if after := h.inventory(s); after.Notices != inv.Notices {
		t.Fatalf("another account's notice changed this user's view: %+v -> %+v", inv.Notices, after.Notices)
	}

	// Lifecycle-level negative controls: an empty identity is refused and degraded, and the
	// installation-wide aggregate still exists for operators but is not what the page serves.
	if st, err := h.e.l.AccountNoticeHealth(t.Context(), ""); err == nil || !st.Degraded {
		t.Fatalf("an empty account must not read as healthy: %+v %v", st, err)
	}
	if st, err := h.e.l.NoticeHealth(t.Context()); err != nil || st.Failed != h.e.scalar(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='failed'`) || st.Failed != inv.Notices.Failed+2 {
		t.Fatalf("control: the global aggregate should include every account, got %+v %v", st, err)
	}
	if w := h.do(loginCall{method: "GET", path: AccountSecurityPath}); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous inventory: %d", w.Code)
	}
}
