package auth

import (
	"context"
	"fmt"
	"strings"
)

// sendAddressProof delivers one address-control proof over the SAME verified-TLS
// submission path as security notices. The message is a separate, narrow
// ceremony: it carries only the proof, the configured service origin and the
// repudiation contact. It is never an authentication or recovery code, grants no
// access, and is not a notice (no outbox row, no retry: the ceremony may resend).
func (l *Lifecycle) sendAddressProof(ctx context.Context, to, proof string) string {
	if !validMailbox(to) || len(proof) != 26 {
		return "recipient"
	}
	id, err := randomID()
	if err != nil {
		return "permanent"
	}
	return l.submit(ctx, to, func() string {
		return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Mandatary address confirmation\r\nMessage-ID: <%s@mandatary.invalid>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nAddress confirmation code: %s\r\nEnter this code in the Mandatary page that asked for it to confirm that you control this address. It expires shortly and can be used once.\r\nIf you did not request this, ignore this message or contact %s. This message does not authorize any access.\r\nService: %s\r\n", l.notices.Sender, to, id, proof, l.notices.Contact, strings.TrimSuffix(l.notices.Origin, "/"))
	})
}
