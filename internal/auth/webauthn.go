package auth

import (
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/net/publicsuffix"
)

// WebAuthnSettings is trusted deployment configuration, never Host/forwarded
// headers or client-provided policy. Only HTTPS, same-RP, top-level ceremonies.
type WebAuthnSettings struct {
	RPID    string
	Origins []string
}
type WebAuthnService struct {
	lifecycle   *Lifecycle
	verifier    *wa.WebAuthn
	verifyLogin func(wa.User, wa.SessionData, *protocol.ParsedCredentialAssertionData) (*wa.Credential, error)
}

// Process-wide, non-waiting admission across service handles bounds challenge,
// parser and cryptographic work. Caller adapters still bound request bytes and
// peer traffic; durable per-key budgets remain independent of this work limit.
var webAuthnWork = make(chan struct{}, 4)

func admitWebAuthn() bool {
	select {
	case webAuthnWork <- struct{}{}:
		return true
	default:
		return false
	}
}

func NewWebAuthn(l *Lifecycle, c WebAuthnSettings) (*WebAuthnService, error) {
	if l == nil || c.RPID != strings.ToLower(c.RPID) || protocol.ValidateRPID(c.RPID) != nil || len(c.Origins) == 0 || len(c.Origins) > 8 {
		return nil, ErrDenied
	}
	suffix, _ := publicsuffix.PublicSuffix(c.RPID)
	if suffix == c.RPID {
		return nil, ErrDenied
	}
	for _, s := range c.Origins {
		u, e := url.Parse(s)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host != strings.ToLower(u.Host) || (u.Hostname() != c.RPID && !strings.HasSuffix(u.Hostname(), "."+c.RPID)) {
			return nil, ErrDenied
		}
	}
	v, e := wa.New(&wa.Config{RPID: c.RPID, RPDisplayName: "Mandatary", RPOrigins: append([]string(nil), c.Origins...), AttestationPreference: protocol.PreferNoAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}})
	if e != nil {
		return nil, ErrDenied
	}
	return &WebAuthnService{lifecycle: l, verifier: v, verifyLogin: v.ValidateLogin}, nil
}
