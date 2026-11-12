package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NicoTM77/Mandatary/internal/docker"
)

// Config configures the REST handler.
type Config struct {
	// Gateway is the shared authentication/execution core (also used by MCP).
	Gateway *Gateway
	// Ready reports whether the Docker-backed surface is ready (every configured
	// endpoint verified, SELF-01/02). It must not block.
	Ready func() bool
	// AllowedOrigins lists the only Origin header values a request may carry. Bearer
	// API clients are not browsers and send none; the default (empty) refuses every
	// request that carries an Origin header (N63B4 S05, no cross-site browser access).
	AllowedOrigins []string
	// MaxStreamsPerCredential and MaxStreams cap concurrent follow streams (defaults 4
	// and 64): each costs a goroutine, an authorizer lease and a revalidation read.
	MaxStreamsPerCredential int
	MaxStreams              int
	// StreamWriteTimeout bounds each follow-stream write (default 30s).
	StreamWriteTimeout time.Duration
}

// Defaults for Config.
const (
	DefaultMaxStreamsPerCredential = 4
	DefaultMaxStreams              = 64
	DefaultStreamWriteTimeout      = 30 * time.Second
)

// Handler serves /api/v1. It is an http.Handler for the exact route inventory below
// and nothing else; every other path is 404 and every other method on a known route
// is 405, both before authentication state or any backend is touched.
//
//	GET  /api/v1/readyz                                                (unauthenticated)
//	GET  /api/v1/endpoints/{endpoint}/containers/{container}/status
//	GET  /api/v1/endpoints/{endpoint}/containers/{container}/config
//	GET  /api/v1/endpoints/{endpoint}/containers/{container}/logs      ?tail&stdout&stderr&timestamps&since&until&follow
//	POST /api/v1/endpoints/{endpoint}/containers/{container}/start
//	POST /api/v1/endpoints/{endpoint}/containers/{container}/stop      {"timeout_seconds"}
//	POST /api/v1/endpoints/{endpoint}/containers/{container}/restart   {"timeout_seconds"}
type Handler struct {
	gw      *Gateway
	ready   func() bool
	origins map[string]bool
	streams *streamLimiter
	wtimeo  time.Duration
}

// ErrInvalidConfig reports an unusable Config.
var ErrInvalidConfig = errors.New("invalid api configuration")

// NewHandler validates cfg fail-closed.
func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Gateway == nil || cfg.Ready == nil || cfg.MaxStreamsPerCredential < 0 || cfg.MaxStreams < 0 || cfg.StreamWriteTimeout < 0 {
		return nil, ErrInvalidConfig
	}
	h := &Handler{gw: cfg.Gateway, ready: cfg.Ready, origins: map[string]bool{}, wtimeo: cfg.StreamWriteTimeout}
	for _, o := range cfg.AllowedOrigins {
		if o == "" || o == "null" || o == "*" || strings.ContainsAny(o, " \t\r\n") {
			return nil, ErrInvalidConfig
		}
		h.origins[o] = true
	}
	per, total := cfg.MaxStreamsPerCredential, cfg.MaxStreams
	if per == 0 {
		per = DefaultMaxStreamsPerCredential
	}
	if total == 0 {
		total = DefaultMaxStreams
	}
	if h.wtimeo == 0 {
		h.wtimeo = DefaultStreamWriteTimeout
	}
	h.streams = &streamLimiter{per: map[[32]byte]int{}, maxPer: per, maxTotal: total}
	return h, nil
}

// streamLimiter bounds concurrent follow streams per presented credential and overall.
type streamLimiter struct {
	mu       sync.Mutex
	per      map[[32]byte]int
	total    int
	maxPer   int
	maxTotal int
}

func (l *streamLimiter) acquire(tok Token) (release func(), ok bool) {
	key := sha256.Sum256([]byte(tok.v))
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.per[key] >= l.maxPer {
		return nil, false
	}
	l.total++
	l.per[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.per[key]--; l.per[key] <= 0 {
				delete(l.per, key)
			}
		})
	}, true
}

type routeKind int

const (
	routeReady routeKind = iota + 1
	routeOperation
)

type route struct {
	kind      routeKind
	spec      Spec
	endpoint  string
	container string
	// unsafeID marks a well-formed route whose endpoint or container segment decodes
	// to a path separator or control byte (for example an encoded slash). It is an
	// invalid identifier, not another route: refused as invalid_request after
	// authentication, never forwarded.
	unsafeID bool
}

// parseRoute maps the escaped request path to a route. It does not consult the method.
func parseRoute(r *http.Request) (route, bool) {
	p := r.URL.EscapedPath()
	rest, ok := strings.CutPrefix(p, BasePath+"/")
	if !ok {
		return route{}, false
	}
	parts := strings.Split(rest, "/")
	seg := make([]string, len(parts))
	unsafe := make([]bool, len(parts))
	for i, raw := range parts {
		if raw == "" {
			return route{}, false
		}
		s, err := url.PathUnescape(raw)
		if err != nil {
			return route{}, false
		}
		seg[i], unsafe[i] = s, strings.ContainsAny(s, "/\\\x00") || hasControl(s)
	}
	if len(seg) == 1 && seg[0] == "readyz" && !unsafe[0] {
		return route{kind: routeReady}, true
	}
	if len(seg) == 5 && seg[0] == "endpoints" && seg[2] == "containers" && !unsafe[0] && !unsafe[2] && !unsafe[4] {
		for _, s := range Specs() {
			if s.Segment == seg[4] {
				return route{kind: routeOperation, spec: s, endpoint: seg[1], container: seg[3], unsafeID: unsafe[1] || unsafe[3]}, true
			}
		}
	}
	return route{}, false
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func setCommonHeaders(w http.ResponseWriter) {
	hd := w.Header()
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("X-Mandatary-API-Version", ContractVersion)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	setCommonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteProblem writes p in the common error shape. 401 carries a Bearer challenge.
func WriteProblem(w http.ResponseWriter, p *Problem) {
	if p.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mandatary"`)
	}
	writeJSON(w, p.Status, p.Body())
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	WriteProblem(w, newProblem(http.StatusMethodNotAllowed, CodeMethodNotAllowed))
}

// OriginAllowed implements the shared cross-origin rule of both adapters: a request
// without an Origin header passes; a request with one passes only if it is exactly one
// of the configured origins.
func OriginAllowed(h http.Header, allowed map[string]bool) bool {
	vals := h.Values("Origin")
	if len(vals) == 0 {
		return true
	}
	return len(vals) == 1 && allowed[vals[0]]
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !OriginAllowed(r.Header, h.origins) {
		WriteProblem(w, forbidden(ReasonForbiddenOrigin))
		return
	}
	rt, ok := parseRoute(r)
	if !ok {
		WriteProblem(w, newProblem(http.StatusNotFound, CodeNotFound))
		return
	}
	switch rt.kind {
	case routeReady:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		h.serveReady(w, r)
	case routeOperation:
		if r.Method != rt.spec.Method {
			methodNotAllowed(w, rt.spec.Method)
			return
		}
		h.serveOperation(w, r, rt)
	}
}

func (h *Handler) serveReady(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.ContentLength > 0 {
		WriteProblem(w, invalid())
		return
	}
	ready := h.ready()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, ReadyResult{Ready: ready, Version: ContractVersion})
}

func (h *Handler) serveOperation(w http.ResponseWriter, r *http.Request, rt route) {
	// Authentication FIRST: before the query, the body or any target is looked at.
	tok, prob := BearerToken(r.Header)
	if prob == nil {
		prob = h.gw.Authenticate(r.Context(), tok)
	}
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	if rt.unsafeID {
		WriteProblem(w, invalid())
		return
	}
	call, prob := h.decode(w, r, rt)
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	if call.Follow {
		h.serveFollow(w, r, tok, call)
		return
	}
	value, prob := h.gw.Run(r.Context(), tok, call)
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

// decode turns the query and body into a Call under the strict schema of the route.
func (h *Handler) decode(w http.ResponseWriter, r *http.Request, rt route) (Call, *Problem) {
	op := rt.spec.Operation
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return Call{}, invalid()
	}
	fields, prob := QueryFields(op, q)
	if prob != nil {
		return Call{}, prob
	}
	body, prob := readBody(w, r, op)
	if prob != nil {
		return Call{}, prob
	}
	if len(body) > 0 {
		bodyFields, err := DecodeObject(body)
		if err != nil {
			return Call{}, invalid()
		}
		for k, v := range bodyFields {
			fields[k] = v // BuildCall refuses any field the operation does not define
		}
	}
	return BuildCall(op, rt.endpoint, rt.container, fields, true)
}

// readBody reads the optional JSON body. Only stop and restart accept one.
func readBody(w http.ResponseWriter, r *http.Request, op docker.Operation) ([]byte, *Problem) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	if op != docker.OpStop && op != docker.OpRestart {
		var one [1]byte
		n, _ := io.ReadFull(io.LimitReader(r.Body, 1), one[:])
		if n > 0 {
			return nil, invalid()
		}
		return nil, nil
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, newProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge)
		}
		return nil, invalid()
	}
	if len(data) == 0 {
		return nil, nil
	}
	mt, _, perr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if perr != nil || mt != "application/json" {
		return nil, newProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia)
	}
	return data, nil
}

// serveFollow streams follow-mode logs as NDJSON: one {"stream","text"} object per
// line, ended by exactly one terminal line, {"end":"eof"} or {"error":{...}} (for
// example authorization_ended after a revocation). The stream is held under the
// authorizer lease, so it stops as soon as the token, policy or safety state changes.
func (h *Handler) serveFollow(w http.ResponseWriter, r *http.Request, tok Token, call Call) {
	release, ok := h.streams.acquire(tok)
	if !ok {
		WriteProblem(w, newProblem(http.StatusTooManyRequests, CodeTooManyStreams))
		return
	}
	defer release()
	f, prob := h.gw.Follow(r.Context(), tok, call)
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	defer f.Close()

	setCommonHeaders(w)
	w.Header().Set("Content-Type", "application/x-ndjson")
	rc := http.NewResponseController(w)
	enc := json.NewEncoder(w)
	write := func(v any) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(h.wtimeo))
		if err := enc.Encode(v); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	w.WriteHeader(http.StatusOK)
	if !write(struct {
		EndpointID  string `json:"endpoint_id"`
		ContainerID string `json:"container_id"`
		Name        string `json:"name"`
	}{f.EndpointID, f.ContainerID, f.Name}) {
		return
	}
	for {
		fr, prob, done := f.Next(r.Context())
		if !done {
			if !write(fr) {
				return
			}
			continue
		}
		switch {
		case prob == nil:
			write(map[string]string{"end": "eof"})
		case prob.Code != CodeCanceled:
			write(prob.Body())
		}
		return
	}
}
