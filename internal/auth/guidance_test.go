package auth

import (
	"context"
	"strings"
	"testing"
)

func TestBlocklistReasonAndGuidance(t *testing.T) {
	_, e := DefaultPolicy().Validate(context.Background(), []byte("synthetic-account-identity"), false, []string{"synthetic-account-identity"})
	if e == nil || !strings.Contains(e.Error(), "password is common, expected or compromised") || !strings.Contains(e.Error(), "choose a different uncommon passphrase") {
		t.Fatal("missing safe blocklist reason/guidance", e)
	}
}
