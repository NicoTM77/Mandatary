package nfc17

import (
	"strings"
	"testing"
)

func TestOrdinaryNFC(t *testing.T) {
	for _, n := range []int{29, 30, 31, 32, 127, 254, 255, 256, 510} {
		a := "q" + strings.Repeat("\u0301", n) + "\u0323"
		want := "q\u0323" + strings.Repeat("\u0301", n)
		if got := string(mustNFC(t, a)); got != want {
			t.Errorf("ordinary NFC at %d marks: canonical order/bytes differ", n)
		}
	}
}
func TestFixed17(t *testing.T) {
	if got := string(mustNFC(t, "\U000105D2\u0307")); got != "\U000105C9" {
		t.Fatal("Unicode17 Todhri composition differs")
	}
}
func TestExplicitCGJ(t *testing.T) {
	s := "q\u034f" + strings.Repeat("\u0301", 31)
	if string(mustNFC(t, s)) != s {
		t.Fatal("explicit CGJ was changed")
	}
}

func mustNFC(t *testing.T, s string) []byte {
	t.Helper()
	b, err := Bytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
