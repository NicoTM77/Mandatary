package auth

import (
	"context"
	"crypto/sha1" // #nosec G505 -- HIBP's range protocol requires SHA1; not a verifier.
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HIBP has a fixed HTTPS destination, no cookies, proxy/redirect forwarding,
// identity or full-hash disclosure. Prefixes still disclose partial information.
// No response cache is retained. Errors are availability-only, never echoed.
type HIBP struct{ client *http.Client }

func NewHIBP() *HIBP {
	return newHIBP(&http.Transport{Proxy: nil, MaxIdleConns: 2, MaxConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: time.Second})
}
func newHIBP(transport http.RoundTripper) *HIBP {
	return &HIBP{client: &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (h *HIBP) Check(ctx context.Context, canonical []byte) (found, available bool) {
	if len(canonical) > 8192 {
		return false, false
	}
	sum := sha1.Sum(canonical) // #nosec G401 -- protocol lookup only, never password hashing/storage.
	full := fmt.Sprintf("%X", sum)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+full[:5], nil)
	if e != nil {
		return false, false
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "Mandatary-password-screen")
	res, e := h.client.Do(req)
	if e != nil {
		return false, false
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		return false, false
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 1024*1024+1))
	if e != nil || len(b) > 1024*1024 {
		return false, false
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\r\n"), "\n")
	if len(lines) == 0 {
		return false, false
	}
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		parts := strings.Split(line, ":")
		if len(parts) != 2 || len(parts[0]) != 35 {
			return false, false
		}
		for _, c := range parts[0] {
			if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
				return false, false
			}
		}
		count, e := strconv.ParseUint(parts[1], 10, 64)
		if e != nil {
			return false, false
		}
		if parts[0] == full[5:] && count > 0 {
			found = true
		}
	}
	return found, true
}
