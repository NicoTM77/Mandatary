package auth

import "context"

// ReportCompromise accepts a still-bound password only for protective
// invalidation of an owned key and existing sessions. It cannot replace a key,
// relax WebAuthn-only policy, issue a recovery capability or establish AAL2.
func (w *WebAuthnService) ReportCompromise(ctx context.Context, name string, password []byte, id, ip string) error {
	return w.lifecycle.reportCompromise(ctx, name, password, id, ip, "webauthn")
}
