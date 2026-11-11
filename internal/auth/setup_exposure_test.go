package auth

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// SETUP logging-exposure acceptance: run the ENTIRE ceremony (issue, reveal,
// exchange, stage, proof, TOTP, completion, an MFA reset) with an unredacted
// debug slog handler, the standard logger and every formatting verb attached, then
// require that no secret value appears in any log byte, error string, formatted
// value or outbound mail.
func TestNoSecretReachesLogsErrorsFormattingOrMail(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(&logs)
	t.Cleanup(func() { slog.SetDefault(previous); log.SetOutput(nil) })

	e := newSetupEnv(t)
	e.ensure()
	term := &fakeTerminal{}
	if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term); err != nil {
		t.Fatal(err)
	}
	token := term.token()
	var errs []string
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	// Failing paths too: every error string is collected.
	_, err := e.s.Exchange(e.ctx(), strings.Repeat("A", setupTokenChars), setupTestIP)
	collect(err)
	e.advance(10 * time.Minute)
	session, err := e.s.Exchange(e.ctx(), token, setupTestIP)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.s.Exchange(e.ctx(), token, setupTestIP) // replay
	collect(err)
	_, err = e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: setupTestUser, Password: []byte("short"), Addresses: []string{"first@example.invalid"}})
	collect(err)
	addresses, err := e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword), Addresses: []string{"first@example.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	a := firstAdmin{session: session, addresses: addresses}
	e.confirmAddress(a, 0)
	en, err := e.s.BeginTOTP(e.ctx(), session.Secret(), "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	seed := en.secret
	a.totp = en
	collect(e.s.ConfirmTOTP(e.ctx(), session.Secret(), "000000", setupTestIP))
	e.advance(31 * time.Second)
	if err = e.s.ConfirmTOTP(e.ctx(), session.Secret(), enrollmentCode(t, en, e.clock.Now()), setupTestIP); err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.Complete(e.ctx(), session.Secret()); err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, RiskAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	resetToken := e.reveal(PurposeMFAReset, setupTestUser)
	if _, err = e.l.DispatchNotices(e.ctx(), 32); err != nil {
		t.Fatal(err)
	}

	proof := e.lastProof()
	cookie := string(session.Secret())
	secrets := map[string]string{
		"initial token": token, "reset token": resetToken, "password": setupTestPassword,
		"proof": proof, "totp seed": seed, "session secret": cookie, "csrf": session.CSRFToken(),
		"grouped token": string(groupedToken([]byte(token))),
	}
	// Formatting verbs on the carriers must redact.
	var formatted strings.Builder
	for _, v := range []any{session, &session, en, &en} {
		fmt.Fprintf(&formatted, "%v|%+v|%#v|%s|%q|%x\n", v, v, v, v, v, v)
	}
	slog.Info("carrier", "session", session, "enrollment", en)
	for name, secret := range secrets {
		if secret == "" {
			t.Fatalf("test bug: empty %s", name)
		}
		for label, haystack := range map[string]string{"logs": logs.String(), "errors": strings.Join(errs, "\n"), "formatted": formatted.String(), "mail": strings.Join(e.smtp.received(), "\n")} {
			if name == "proof" && label == "mail" {
				continue // the confirmation code is DELIVERED by mail by design
			}
			if strings.Contains(haystack, secret) {
				t.Fatalf("%s leaked into %s", name, label)
			}
			if lower := strings.ToLower(secret); len(lower) > 12 && strings.Contains(strings.ToLower(haystack), lower) {
				t.Fatalf("%s leaked (case-folded) into %s", name, label)
			}
		}
	}
	// Notices and proofs name only the configured origin, never a token URL.
	for _, message := range e.smtp.received() {
		if strings.Contains(message, "token=") || strings.Contains(message, "/setup?") {
			t.Fatal("mail carries a token-bearing URL")
		}
	}
	// The proof mail is a confirmation only: no setup token and no password.
	if !strings.Contains(strings.Join(e.smtp.received(), "\n"), "Address confirmation code") {
		t.Fatal("no proof mail was sent")
	}
}

// Status, reconcile reports and issue results are redacted by construction.
func TestOperatorViewsCarryNoSecretMaterial(t *testing.T) {
	e := newSetupEnv(t)
	issued := e.ensure()
	names, _ := e.repo.RevealFileNames()
	status, err := e.s.Status(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	report, err := e.s.Reconcile(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	rendered := fmt.Sprintf("%+v %#v %+v %+v %+v", status, status, report, issued, names)
	digest := e.text(`SELECT hex(digest) FROM setup_tokens`)
	if strings.Contains(strings.ToUpper(rendered), digest) {
		t.Fatal("a token digest reached an operator view")
	}
	raw := e.reveal(PurposeInitialSetup, "")
	if strings.Contains(rendered, raw) {
		t.Fatal("token in operator views")
	}
}
