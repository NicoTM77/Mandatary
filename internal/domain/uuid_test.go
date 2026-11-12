package domain

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestNewUUIDIsCanonicalV4AndFailsClosedOnShortOrBrokenSource(t *testing.T) {
	id, err := NewUUID(bytes.NewReader(bytes.Repeat([]byte{0xff}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if id != "ffffffff-ffff-4fff-bfff-ffffffffffff" {
		t.Fatalf("version/variant bits not forced: %s", id)
	}
	if _, err := ParseEndpointID(id); err != nil {
		t.Fatalf("not a canonical UUID: %v", err)
	}
	for name, source := range map[string]*bytes.Reader{"empty": bytes.NewReader(nil), "short": bytes.NewReader(make([]byte, 15))} {
		if out, err := NewUUID(source); err == nil || out != "" {
			t.Fatalf("%s source produced an identifier: %q", name, out)
		}
	}
	if out, err := NewUUID(failingReader{}); err == nil || out != "" || strings.Contains(err.Error(), "boom") {
		t.Fatalf("failing source: %q %v", out, err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
