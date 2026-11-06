package auth

import (
	"context"
	"crypto/sha1" // Protocol test vector only, never password storage.
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHIBPPrivacy(t *testing.T) {
	p := []byte("synthetic uncommon test password")
	full := fmt.Sprintf("%X", sha1.Sum(p))
	calls := 0
	h := newHIBP(roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.String() != "https://api.pwnedpasswords.com/range/"+full[:5] || r.Body != nil || r.Header.Get("Add-Padding") != "true" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("HIBP disclosure contract")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(full[5:] + ":2\r\n"))}, nil
	}))
	if found, available := h.Check(context.Background(), p); !found || !available || calls != 1 {
		t.Fatal("range lookup failed")
	}
	policy := DefaultPolicy()
	if _, e := policy.Validate(context.Background(), p, false, nil); e != nil || calls != 1 {
		t.Fatal("default-off made an external call")
	}
	policy.hibp = h
	if _, e := policy.Validate(context.Background(), p, false, nil); e == nil {
		t.Fatal("breached value accepted")
	}
	for _, transport := range []http.RoundTripper{roundTrip(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("synthetic canary must not escape")
	}), roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("malformed"))}, nil
	}), roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader(""))}, nil
	})} {
		policy.hibp = newHIBP(transport)
		if _, e := policy.Validate(context.Background(), p, false, nil); e != nil {
			t.Fatal("offline fallback unavailable")
		}
		if _, e := policy.Validate(context.Background(), []byte("password1"), true, nil); e == nil {
			t.Fatal("outage skipped offline screening")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h = newHIBP(roundTrip(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() }))
	if _, available := h.Check(ctx, p); available {
		t.Fatal("cancelled lookup marked available")
	}
}
