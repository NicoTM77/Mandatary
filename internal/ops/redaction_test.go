package ops_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

func leaks(s string) bool {
	if strings.Contains(s, canaryToken) || strings.Contains(s, canarySecret) {
		return true
	}
	for _, raw := range [][]byte{[]byte(canaryToken), []byte(canarySecret)} {
		if strings.Contains(s, base64.StdEncoding.EncodeToString(raw)) ||
			strings.Contains(s, base64.RawStdEncoding.EncodeToString(raw)) ||
			strings.Contains(s, base64.URLEncoding.EncodeToString(raw)) ||
			strings.Contains(s, hex.EncodeToString(raw)) {
			return true
		}
	}
	return false
}

// P113-REDACT-01 (TD §9.3, SELF-L3 caller formatting): credential material carried
// by a Request, and every handle the service returns, never appears in any fmt
// verb, JSON encoding or structured log (text and JSON handlers).
func TestCredentialsAreNeverFormattedByRequestsResultsStreamsOrErrors(t *testing.T) {
	e := newEnv(t)
	canaryHuman := authz.PrincipalCredentials{SessionID: authz.SessionID(aliceSess), SessionSecret: []byte(canarySecret)}
	canaryAgent := authz.PrincipalCredentials{AgentToken: canaryToken, AgentTokenHash: []byte(canaryToken)}

	var subjects []any
	for _, c := range []authz.PrincipalCredentials{canaryHuman, canaryAgent} {
		r := req(c, "edge-proxy", docker.OpLogs)
		subjects = append(subjects, r, &r)
		// Denials (the canaries are unknown credentials) must not echo them.
		_, err := e.svc.Execute(t.Context(), r)
		if err == nil {
			t.Fatal("canary credentials were accepted")
		}
		subjects = append(subjects, err)
	}
	// A successful result and a live stream, authorized with real credentials.
	res, err := e.svc.Execute(t.Context(), followReq(botCreds()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Logs.Close() }()
	subjects = append(subjects, res, &res, res.Logs)
	sres, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectStatus))
	if err != nil {
		t.Fatal(err)
	}
	subjects = append(subjects, sres)

	// The live request carries the real bot token: it must be redacted as well.
	live := followReq(botCreds())
	subjects = append(subjects, live)
	realToken := tokenFor("1")

	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"}
	for i, s := range subjects {
		// The Stringer/GoStringer/LogValuer methods themselves must also be safe,
		// not merely shadowed by a Formatter.
		var direct []string
		if st, ok := s.(fmt.Stringer); ok {
			direct = append(direct, st.String())
		}
		if gs, ok := s.(fmt.GoStringer); ok {
			direct = append(direct, gs.GoString())
		}
		if lv, ok := s.(slog.LogValuer); ok {
			direct = append(direct, fmt.Sprint(lv.LogValue().Any()), lv.LogValue().String())
		}
		for _, out := range direct {
			if leaks(out) || strings.Contains(out, realToken) || strings.Contains(out, string(secretFor(aliceSess))) {
				t.Fatalf("subject %d direct method leaked credentials: %.200q", i, out)
			}
		}
		for _, v := range verbs {
			out := fmt.Sprintf(v, s)
			if leaks(out) || strings.Contains(out, realToken) || strings.Contains(out, string(secretFor(aliceSess))) {
				t.Fatalf("subject %d verb %s leaked credentials: %.200q", i, v, out)
			}
		}
		if b, err := json.Marshal(s); err == nil && (leaks(string(b)) || strings.Contains(string(b), realToken)) {
			t.Fatalf("subject %d json leaked credentials: %.200q", i, b)
		}
		for _, mk := range []func(*bytes.Buffer) slog.Handler{
			func(b *bytes.Buffer) slog.Handler {
				return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
			},
			func(b *bytes.Buffer) slog.Handler {
				return slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
			},
		} {
			var buf bytes.Buffer
			slog.New(mk(&buf)).Info("subject", "value", s, slog.Any("again", s))
			if leaks(buf.String()) || strings.Contains(buf.String(), realToken) || strings.Contains(buf.String(), string(secretFor(aliceSess))) {
				t.Fatalf("subject %d slog leaked credentials: %.300q", i, buf.String())
			}
		}
	}
}
