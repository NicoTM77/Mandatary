// Package web serves the compiled admin application shell and its assets, not
// product APIs. Account/session/setup JSON routes are mounted separately by
// cmd/mandatary behind their own browser boundary.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

// Build the frontend before compiling Go; no placeholder assets are embedded.
//
//go:embed dist/index.html dist/assets/*
var assets embed.FS

// contentSecurityPolicy is the document policy. Compared with the P1.01 skeleton
// exactly one directive changed: connect-src 'self' lets the application call its
// own /api/v1/* origin. Nothing inline, remote, framed, rebased or form-posted.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"

// documentRoutes is the EXACT set of paths that serve the application shell
// (D-ROUTE-1). The single-page application reads location.pathname to choose its
// view. There is deliberately no wildcard or SPA fallback: every other path that
// is not /assets/<file> is 404. Whether a route does anything is decided by the
// API behind it (for example the setup API answers 404 when no generation is
// live); serving the static shell discloses nothing.
var documentRoutes = map[string]bool{"/": true, "/setup": true, "/login": true, "/security": true, "/recovery": true, "/agents": true,
	"/policy": true, "/policy/users": true, "/policy/groups": true, "/policy/agents": true,
	"/backup": true, "/restore": true, "/restore/review": true}

// Handler returns an exact static-file surface with no SPA wildcard or listings.
func Handler() http.Handler {
	files, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err) // Invalid compile-time asset layout is a build/programming error.
	}
	static := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// RawPath is set only when the request spelled the path differently from its canonical encoding (for
		// example %2f for a slash). With nested document routes such a spelling would otherwise alias one.
		if documentRoutes[r.URL.Path] && r.URL.RawPath == "" {
			serveIndex(w, r, files)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if !strings.HasPrefix(r.URL.Path, "/assets/") || !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		info, err := fs.Stat(files, name)
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
}

// serveIndex writes the embedded index.html directly. http.FileServer would
// redirect /index.html to /, and the document must be served in place at every
// allowlisted path so the address bar keeps /setup or /login.
func serveIndex(w http.ResponseWriter, r *http.Request, files fs.FS) {
	file, err := files.Open("index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = file.Close() }()
	seeker, ok := file.(interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	})
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "", time.Time{}, seeker)
}
