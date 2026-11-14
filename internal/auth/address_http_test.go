package auth

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// P1.16.4 post-setup notification-address management (NIST ANOT-2..4). The REAL
// address service, outbox and a real loopback TLS SMTP receiver are used; only the
// clock, the origin and the synthetic password are synthetic.

type addressHarness struct {
	*securityHarness
	smtp *smtpFixture
}

func newAddressHarness(t *testing.T) *addressHarness {
	t.Helper()
	h := newSecurityHarness(t)
	smtp := receiver(t, "implicit", "", false, false)
	h.e.l.notices.Relay, h.e.l.notices.RootCAs = smtp.relay, smtp.roots
	return &addressHarness{securityHarness: h, smtp: smtp}
}

func (h *addressHarness) propose(s cookieSession, address string) (id string, code int) {
	h.t.Helper()
	w := h.post(s, AccountAddressPath, map[string]string{"address": address})
	var out struct {
		Address AddressView `json:"address"`
	}
	if w.Code == http.StatusCreated {
		mustDecode(h.t, w.Body.Bytes(), &out)
		if out.Address.Confirmed || out.Address.Address != address {
			h.t.Fatalf("a proposed address is not pending: %+v", out.Address)
		}
	}
	return out.Address.ID, w.Code
}

// lastProof returns the newest proof mailed to the given recipient.
func (h *addressHarness) lastProof(to string) string {
	h.t.Helper()
	messages := h.smtp.received()
	for i := len(messages) - 1; i >= 0; i-- {
		if strings.Contains(messages[i], "To: "+to+"\r\n") {
			if m := proofLine.FindStringSubmatch(messages[i]); m != nil {
				return m[1]
			}
		}
	}
	h.t.Fatalf("no proof was mailed to %s", to)
	return ""
}

func (h *addressHarness) confirm(s cookieSession, id, code string) int {
	h.t.Helper()
	return h.post(s, AccountAddressConfirmPath, map[string]string{"id": id, "code": code}).Code
}

func (h *addressHarness) send(s cookieSession, id string) int {
	h.t.Helper()
	return h.post(s, AccountAddressProofPath, map[string]string{"id": id}).Code
}

func (h *addressHarness) remove(s cookieSession, id string) int {
	h.t.Helper()
	return h.post(s, AccountAddressRemovePath, map[string]string{"id": id}).Code
}

func (h *addressHarness) recipients(event string) []string {
	h.t.Helper()
	rows, err := h.e.db.Query(`SELECT o.recipient_snapshot FROM security_notice_outbox o JOIN security_events e ON e.id=o.event_id WHERE e.event_type=? ORDER BY o.recipient_snapshot`, event)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var r string
		if err = rows.Scan(&r); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestAddressHTTPProposeProveConfirmAndRemove(t *testing.T) {
	h := newAddressHarness(t)
	e := h.e
	s := h.signIn()

	id, code := h.propose(s, "third@example.invalid")
	if code != http.StatusCreated || id == "" {
		t.Fatalf("propose: %d", code)
	}
	// An unconfirmed address is listed as such, was told nothing and is not a notice
	// destination; the CONFIRMED addresses were told that a change was proposed.
	for _, a := range h.inventory(s).Addresses {
		if a.ID == id && a.Confirmed {
			t.Fatal("a proposed address is already confirmed")
		}
	}
	if got := strings.Join(h.recipients("address_change_proposed"), ","); got != "first@example.invalid,second@example.invalid" {
		t.Fatalf("proposal alert recipients: %q", got)
	}
	if len(h.smtp.received()) != 0 {
		t.Fatal("something was mailed before any proof was requested")
	}

	// Proof: only to the proposed address; wrong, foreign and replayed proofs are one refusal.
	if got := h.send(s, id); got != http.StatusNoContent {
		t.Fatalf("send proof: %d", got)
	}
	proof := h.lastProof("third@example.invalid")
	if got := h.send(s, id); got != http.StatusForbidden {
		t.Fatalf("an immediate resend was accepted: %d", got)
	}
	if got := h.confirm(s, id, "AAAAAAAAAAAAAAAAAAAAAAAAAA"); got != http.StatusForbidden {
		t.Fatalf("wrong proof: %d", got)
	}
	if got := h.confirm(s, id, "not a proof"); got != http.StatusForbidden {
		t.Fatalf("malformed proof: %d", got)
	}
	other, _ := h.propose(s, "fourth@example.invalid")
	e.clock.Advance(61 * time.Second)
	if h.send(s, other) != http.StatusNoContent {
		t.Fatal("proof for the second proposal")
	}
	if got := h.confirm(s, id, h.lastProof("fourth@example.invalid")); got != http.StatusForbidden {
		t.Fatalf("a proof sent to another address confirmed this one: %d", got)
	}
	if got := h.confirm(s, "no-such-address", proof); got != http.StatusForbidden {
		t.Fatalf("unknown address id: %d", got)
	}
	if got := h.confirm(s, id, proof); got != http.StatusNoContent {
		t.Fatalf("confirm: %d", got)
	}
	if got := h.confirm(s, id, proof); got != http.StatusForbidden {
		t.Fatalf("a consumed proof was accepted again: %d", got)
	}
	got := h.inventory(s).Addresses
	confirmed := 0
	for _, a := range got {
		if a.Confirmed {
			confirmed++
		}
	}
	if len(got) != 4 || confirmed != 3 {
		t.Fatalf("addresses after confirmation: %+v", got)
	}
	// The change is announced to every confirmed address, the new one included.
	if r := strings.Join(h.recipients("address_changed"), ","); r != "first@example.invalid,second@example.invalid,third@example.invalid" {
		t.Fatalf("change alert recipients: %q", r)
	}

	// Removing an address tells it first (its snapshot precedes the revocation).
	before := len(h.recipients("address_changed"))
	if got := h.remove(s, id); got != http.StatusNoContent {
		t.Fatalf("remove: %d", got)
	}
	if after := len(h.recipients("address_changed")); after != before+3 {
		t.Fatalf("removal alert recipients %d -> %d", before, after)
	}
	if got := h.remove(s, id); got != http.StatusForbidden {
		t.Fatalf("an already removed address was removed again: %d", got)
	}
	// An unconfirmed proposal can simply be withdrawn, without any notice.
	notices := h.e.scalar(`SELECT count(*) FROM security_notice_outbox`)
	if got := h.remove(s, other); got != http.StatusNoContent {
		t.Fatalf("withdraw: %d", got)
	}
	if h.e.scalar(`SELECT count(*) FROM security_notice_outbox`) != notices {
		t.Fatal("withdrawing an unconfirmed proposal produced notices")
	}

	// A removed address can be proposed again and is a NEW version needing a NEW proof.
	if id2, code := h.propose(s, "THIRD@example.invalid"); code != http.StatusCreated || id2 == id {
		t.Fatalf("re-propose: %d", code)
	} else {
		e.clock.Advance(61 * time.Second)
		if h.send(s, id2) != http.StatusNoContent {
			t.Fatal("proof for the re-proposed address")
		}
		if got := h.confirm(s, id2, proof); got != http.StatusForbidden {
			t.Fatalf("the OLD version's proof confirmed the new version: %d", got)
		}
	}
}

func TestAddressHTTPKeepsAtLeastOneConfirmedAndBoundsTheList(t *testing.T) {
	h := newAddressHarness(t)
	s := h.signIn()
	if got := h.remove(s, "addr1"); got != http.StatusNoContent {
		t.Fatalf("remove one of two: %d", got)
	}
	if got := h.remove(s, "addr2"); got != http.StatusForbidden || errorCode(h.post(s, AccountAddressRemovePath, map[string]string{"id": "addr2"})) != "denied" {
		t.Fatalf("the last confirmed address was removable: %d", got)
	}
	if inv := h.inventory(s); len(inv.Addresses) != 1 || !inv.Addresses[0].Confirmed {
		t.Fatalf("addresses: %+v", inv.Addresses)
	}
	// Cap of four live addresses (confirmed or pending).
	for i, a := range []string{"a@example.invalid", "b@example.invalid", "c@example.invalid"} {
		if _, code := h.propose(s, a); code != http.StatusCreated {
			t.Fatalf("proposal %d: %d", i, code)
		}
	}
	if _, code := h.propose(s, "e@example.invalid"); code != http.StatusForbidden {
		t.Fatalf("a fifth live address was accepted: %d", code)
	}
	// Duplicates (any case) of a live address are refused.
	if _, code := h.propose(s, "A@EXAMPLE.INVALID"); code != http.StatusForbidden {
		t.Fatalf("a duplicate was accepted: %d", code)
	}
}

func TestAddressHTTPRefusesUnusableAddressesAndAbuse(t *testing.T) {
	h := newAddressHarness(t)
	s := h.signIn()
	for _, bad := range []string{"", "not-an-address", "Name <a@example.invalid>", "a@example.invalid\r\nBcc: attacker@example.invalid", "a@example.invalid, b@example.invalid", strings.Repeat("a", 250) + "@example.invalid"} {
		if _, code := h.propose(s, bad); code != http.StatusForbidden {
			t.Errorf("%q: %d", bad, code)
		}
	}
	if got := h.e.scalar(`SELECT count(*) FROM notification_addresses`); got != 2 {
		t.Fatalf("an unusable address was stored: %d rows", got)
	}
	// An expired proof never confirms.
	id, _ := h.propose(s, "late@example.invalid")
	if h.send(s, id) != http.StatusNoContent {
		t.Fatal("send")
	}
	proof := h.lastProof("late@example.invalid")
	h.e.clock.Advance(16 * time.Minute)
	if got := h.confirm(h.signIn(), id, proof); got != http.StatusForbidden {
		t.Fatalf("an expired proof confirmed: %d", got)
	}
	// Proofs per address are bounded.
	fresh := h.signIn()
	sent := 1
	for ; sent < 12; sent++ {
		h.e.clock.Advance(61 * time.Second)
		if h.send(fresh, id) != http.StatusNoContent {
			break
		}
	}
	if sent > maxProofsPerAddress {
		t.Fatalf("%d proofs were sent for one address", sent)
	}
}

// A stale session cannot touch addresses (boundary), and a relay outage leaves the
// proposal pending without confirming or retargeting anything.
func TestAddressHTTPNeedsFreshAssuranceAndReportsRelayFailure(t *testing.T) {
	h := newAddressHarness(t)
	s := h.signIn()
	id, _ := h.propose(s, "later@example.invalid")
	h.e.l.notices.Relay = "127.0.0.1:1" // nothing listens: the proof cannot be delivered
	if w := h.post(s, AccountAddressProofPath, map[string]string{"id": id}); w.Code != http.StatusServiceUnavailable || errorCode(w) != "unavailable" {
		t.Fatalf("relay outage: %d %s", w.Code, w.Body.String())
	}
	if inv := h.inventory(s); len(inv.Addresses) != 3 {
		t.Fatalf("addresses: %+v", inv.Addresses)
	}
	h.e.clock.Advance(16 * time.Minute)
	for _, path := range []string{AccountAddressPath, AccountAddressProofPath, AccountAddressConfirmPath, AccountAddressRemovePath} {
		if w := h.post(s, path, map[string]string{"address": "x@example.invalid", "id": id, "code": "AAAAAAAAAAAAAAAAAAAAAAAAAA"}); w.Code != http.StatusForbidden || errorCode(w) != "step_up_required" {
			t.Errorf("%s with a stale session: %d %s", path, w.Code, w.Body.String())
		}
	}
	// Reads stay possible: the page can still show the account and ask for step-up.
	if inv := h.inventory(s); len(inv.Addresses) != 3 {
		t.Fatalf("addresses after expiry: %+v", inv.Addresses)
	}
}

// P1.18.4 P116-L5: a storage/infrastructure fault of an address mutation is the fixed 503
// "unavailable", never the opaque 403 "denied" that is reserved for LOGICAL refusals; it
// leaks no SQL or driver text, never claims success and leaves no uncommitted state, notice
// or proof. The logical controls (unknown/foreign address, wrong proof, last confirmed
// address) stay 403 denied.
func TestAddressHTTPStorageFaultsAreUnavailableNeverDeniedAndChangeNothing(t *testing.T) {
	type op struct {
		name string
		// prepare returns the request path and body after any setup (before the fault is armed).
		prepare func(h *addressHarness, s cookieSession) (path string, body map[string]string)
	}
	ops := []op{
		{"propose", func(h *addressHarness, s cookieSession) (string, map[string]string) {
			return AccountAddressPath, map[string]string{"address": "fault-new@example.invalid"}
		}},
		{"resend-proof", func(h *addressHarness, s cookieSession) (string, map[string]string) {
			id, _ := h.propose(s, "fault-pending@example.invalid")
			return AccountAddressProofPath, map[string]string{"id": id}
		}},
		{"confirm", func(h *addressHarness, s cookieSession) (string, map[string]string) {
			id, _ := h.propose(s, "fault-confirm@example.invalid")
			if h.send(s, id) != http.StatusNoContent {
				h.t.Fatal("setup send")
			}
			return AccountAddressConfirmPath, map[string]string{"id": id, "code": h.lastProof("fault-confirm@example.invalid")}
		}},
		{"remove", func(h *addressHarness, s cookieSession) (string, map[string]string) {
			return AccountAddressRemovePath, map[string]string{"id": "addr1"} // one of two confirmed addresses
		}},
	}
	faults := []struct {
		name string
		arm  func(h *addressHarness)
	}{
		{"transaction-begin", func(h *addressHarness) { h.e.l.repo.FailClosed() }},
		{"read", func(h *addressHarness) {
			h.e.exec(`ALTER TABLE notification_addresses RENAME TO notification_addresses_x`)
		}},
		{"write-address-row", func(h *addressHarness) {
			h.e.exec(`CREATE TRIGGER p1184_fail_addr_ins BEFORE INSERT ON notification_addresses BEGIN SELECT RAISE(ABORT,'synthetic write fault'); END`)
			h.e.exec(`CREATE TRIGGER p1184_fail_addr_upd BEFORE UPDATE ON notification_addresses BEGIN SELECT RAISE(ABORT,'synthetic write fault'); END`)
		}},
		{"write-proof-row", func(h *addressHarness) {
			h.e.exec(`CREATE TRIGGER p1184_fail_proof_ins BEFORE INSERT ON notification_address_proofs BEGIN SELECT RAISE(ABORT,'synthetic write fault'); END`)
			h.e.exec(`CREATE TRIGGER p1184_fail_proof_upd BEFORE UPDATE ON notification_address_proofs BEGIN SELECT RAISE(ABORT,'synthetic write fault'); END`)
		}},
		{"write-notice-event", func(h *addressHarness) {
			h.e.exec(`CREATE TRIGGER p1184_fail_event BEFORE INSERT ON security_events BEGIN SELECT RAISE(ABORT,'synthetic write fault'); END`)
		}},
	}
	// A fault that cannot reach a given operation's path is skipped, but every operation must be
	// hit by at least the begin and one other fault, and every combination that DOES fail must be 503.
	for _, o := range ops {
		hit := 0
		for _, f := range faults {
			t.Run(o.name+"/"+f.name, func(t *testing.T) {
				h := newAddressHarness(t)
				s := h.signIn()
				path, body := o.prepare(h, s)
				// Only tables the fault leaves readable are snapshotted (a renamed table cannot be).
				snapshot := func() string {
					var b strings.Builder
					for _, q := range []string{
						`SELECT count(*) FROM security_events`, `SELECT count(*) FROM security_notice_outbox`,
						`SELECT count(*) FROM notification_address_proofs`, `SELECT count(*) FROM notification_address_proofs WHERE consumed_at IS NOT NULL`,
					} {
						b.WriteString(fmt.Sprint(h.e.scalar(q)) + "|")
					}
					return b.String()
				}
				before := snapshot()
				f.arm(h)
				w := h.post(s, path, body)
				if w.Code == http.StatusNoContent || w.Code == http.StatusCreated {
					return // this fault does not touch that operation's path: nothing to assert
				}
				hit++
				if w.Code != http.StatusServiceUnavailable || errorCode(w) != "unavailable" {
					t.Fatalf("%s under %s fault: %d %s, want 503 unavailable (never 403 denied)", o.name, f.name, w.Code, w.Body.String())
				}
				for _, leak := range []string{"synthetic", "no such table", "SQL", "notification_addresses", "constraint"} {
					if strings.Contains(w.Body.String(), leak) {
						t.Fatalf("response leaks %q: %s", leak, w.Body.String())
					}
				}
				if f.name != "read" && f.name != "write-address-row" || o.name == "confirm" {
					if got := snapshot(); got != before {
						t.Fatalf("uncommitted state/notice/proof after a failed %s: before %s after %s", o.name, before, got)
					}
				}
			})
		}
		if hit < 3 {
			t.Fatalf("%s: only %d of %d injected faults reached the operation; the fault matrix is not exercising it", o.name, hit, len(faults))
		}
	}

	// Logical controls are still the opaque 403 denied, with no fault involved.
	h := newAddressHarness(t)
	s := h.signIn()
	for name, c := range map[string]struct {
		path string
		body map[string]string
	}{
		"remove-unknown-address":  {AccountAddressRemovePath, map[string]string{"id": "no-such-address"}},
		"send-for-unknown":        {AccountAddressProofPath, map[string]string{"id": "no-such-address"}},
		"confirm-wrong-proof":     {AccountAddressConfirmPath, map[string]string{"id": "addr1", "code": "AAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		"propose-duplicate-email": {AccountAddressPath, map[string]string{"address": "first@example.invalid"}},
	} {
		if w := h.post(s, c.path, c.body); w.Code != http.StatusForbidden || errorCode(w) != "denied" {
			t.Errorf("%s: %d %s, want 403 denied", name, w.Code, w.Body.String())
		}
	}
	if got := h.remove(s, "addr1"); got != http.StatusNoContent {
		t.Fatalf("control removal of one of two: %d", got)
	}
	if w := h.post(s, AccountAddressRemovePath, map[string]string{"id": "addr2"}); w.Code != http.StatusForbidden || errorCode(w) != "denied" {
		t.Errorf("last confirmed address removal: %d %s, want 403 denied", w.Code, w.Body.String())
	}
}
