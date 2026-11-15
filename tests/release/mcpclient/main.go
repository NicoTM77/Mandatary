// Command mcpclient is the REAL MCP client of the P1.20 release acceptance (tests/release/release.py).
//
// It is the official go-sdk MCP client speaking Streamable HTTP over verified TLS to the Compose deployment, not
// a hand-written JSON-RPC poster. It reads a JSON script, executes each step with the credential named by the
// step, and prints one JSON result per step. It never prints a credential: tokens come from a 0600 file, are
// referenced by name, and a failure is classified (HTTP status, MCP error code, reason) rather than echoed.
//
// It is a test tool: it is built from this repository's locked module, never part of the shipped image.
//
//	mcpclient -script script.json -tokens tokens.json -ca ca.pem -dial 127.0.0.1:PORT -server-name mandatary.test
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type step struct {
	ID      string         `json:"id"`
	Token   string         `json:"token"`             // name in the tokens file, "literal:<value>" or "" for none
	Session string         `json:"session,omitempty"` // reuse one open session across steps
	List    bool           `json:"list,omitempty"`    // tools/list instead of a call
	Op      string         `json:"op,omitempty"`      // MCP tool name
	Args    map[string]any `json:"args,omitempty"`
	Close   bool           `json:"close,omitempty"` // close the named session
}

type loadSpec struct {
	Workers   int      `json:"workers"`
	DurationS int      `json:"duration_s"`
	Token     string   `json:"token"`
	Endpoint  string   `json:"endpoint"`
	Container string   `json:"container"`
	Ops       []string `json:"ops"`
}

type script struct {
	URL   string    `json:"url"`
	Steps []step    `json:"steps"`
	Load  *loadSpec `json:"load,omitempty"`
}

type result struct {
	ID            string          `json:"id"`
	Connected     bool            `json:"connected"`
	HTTPStatus    int             `json:"http_status,omitempty"`
	HTTPCode      string          `json:"http_code,omitempty"`
	IsError       bool            `json:"is_error,omitempty"`
	ErrCode       string          `json:"error_code,omitempty"`
	ErrReason     string          `json:"error_reason,omitempty"`
	ProtocolError string          `json:"protocol_error,omitempty"`
	Tools         []string        `json:"tools,omitempty"`
	Structured    json.RawMessage `json:"structured,omitempty"`
	Elapsed       float64         `json:"elapsed_ms"`
}

type recorder struct {
	base   http.RoundTripper
	bearer string
	mu     sync.Mutex
	failed []recorded
}

type recorded struct {
	status int
	body   []byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if r.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(data))
		r.mu.Lock()
		r.failed = append(r.failed, recorded{resp.StatusCode, data})
		r.mu.Unlock()
	}
	return resp, nil
}

func (r *recorder) first() (recorded, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.failed) == 0 {
		return recorded{}, false
	}
	return r.failed[0], true
}

type env struct {
	url    string
	tokens map[string]string
	rt     http.RoundTripper
}

func (e *env) bearer(name string) string {
	if strings.HasPrefix(name, "literal:") {
		return strings.TrimPrefix(name, "literal:")
	}
	if name == "" {
		return ""
	}
	return e.tokens[name]
}

type session struct {
	cs  *mcp.ClientSession
	rec *recorder
}

func (e *env) connect(ctx context.Context, tokenName string) (*session, error) {
	rec := &recorder{base: e.rt, bearer: e.bearer(tokenName)}
	client := mcp.NewClient(&mcp.Implementation{Name: "mandatary-p120-release-client", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             e.url,
		HTTPClient:           &http.Client{Transport: rec},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	return &session{cs: cs, rec: rec}, err
}

func classifyHTTP(res *result, f recorded) {
	res.HTTPStatus = f.status
	var body struct {
		Error struct {
			Code   string `json:"code"`
			Reason string `json:"reason"`
		} `json:"error"`
	}
	if json.Unmarshal(f.body, &body) == nil {
		res.HTTPCode = body.Error.Code
		res.ErrReason = body.Error.Reason
	}
}

func (e *env) run(ctx context.Context, s step, open map[string]*session) result {
	started := time.Now()
	res := result{ID: s.ID}
	defer func() { res.Elapsed = float64(time.Since(started).Microseconds()) / 1000 }()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var sess *session
	if s.Session != "" {
		if s.Close {
			if o := open[s.Session]; o != nil {
				_ = o.cs.Close()
				delete(open, s.Session)
			}
			res.Connected = true
			return res
		}
		sess = open[s.Session]
	}
	if sess == nil {
		var err error
		sess, err = e.connect(ctx, s.Token)
		if err != nil {
			if f, ok := sess.rec.first(); ok {
				classifyHTTP(&res, f)
			} else {
				res.ProtocolError = "connect: " + sanitize(err)
			}
			return res
		}
		if s.Session != "" {
			open[s.Session] = sess
		}
	}
	if s.Session == "" {
		defer func() { _ = sess.cs.Close() }()
	}
	res.Connected = true
	if s.List {
		var names []string
		for t, err := range sess.cs.Tools(ctx, nil) {
			if err != nil {
				if f, ok := sess.rec.first(); ok {
					classifyHTTP(&res, f)
				} else {
					res.ProtocolError = "list: " + sanitize(err)
				}
				return res
			}
			names = append(names, t.Name)
		}
		sort.Strings(names)
		res.Tools = names
		return res
	}
	out, err := sess.cs.CallTool(ctx, &mcp.CallToolParams{Name: s.Op, Arguments: s.Args})
	if err != nil {
		var je *jsonrpc.Error
		if errors.As(err, &je) {
			res.ProtocolError = fmt.Sprintf("jsonrpc %d: %s", je.Code, je.Message)
		} else if f, ok := sess.rec.first(); ok {
			classifyHTTP(&res, f)
		} else {
			res.ProtocolError = "call: " + sanitize(err)
		}
		return res
	}
	b, _ := json.Marshal(out.StructuredContent)
	if out.IsError {
		res.IsError = true
		var eo struct {
			Error struct {
				Code   string `json:"code"`
				Reason string `json:"reason"`
			} `json:"error"`
		}
		if json.Unmarshal(b, &eo) == nil {
			res.ErrCode, res.ErrReason = eo.Error.Code, eo.Error.Reason
		}
		return res
	}
	if len(b) > 4096 {
		b = []byte(`"truncated"`)
	}
	res.Structured = b
	return res
}

// sanitize keeps an error text short and free of anything resembling a credential.
func sanitize(err error) string {
	t := err.Error()
	if i := strings.Index(t, "mdt_"); i >= 0 {
		t = t[:i] + "[redacted]"
	}
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

type loadReport struct {
	Workers  int              `json:"workers"`
	Seconds  float64          `json:"seconds"`
	Calls    int64            `json:"calls"`
	OK       int64            `json:"ok"`
	Errors   int64            `json:"errors"`
	ByOp     map[string]int64 `json:"by_op"` // successful calls per tool: the exact usage the deployment must have accounted
	P50      float64          `json:"p50_ms"`
	P95      float64          `json:"p95_ms"`
	P99      float64          `json:"p99_ms"`
	ErrorSet []string         `json:"error_samples,omitempty"`
}

func (e *env) load(ctx context.Context, l loadSpec) loadReport {
	if l.Workers < 1 {
		l.Workers = 1
	}
	deadline := time.Now().Add(time.Duration(l.DurationS) * time.Second)
	var calls, okc, errc atomic.Int64
	var mu sync.Mutex
	var lat []float64
	byOp := map[string]int64{}
	samples := map[string]bool{}
	var wg sync.WaitGroup
	t0 := time.Now()
	for w := 0; w < l.Workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			sess, err := e.connect(ctx, l.Token)
			if err != nil {
				errc.Add(1)
				mu.Lock()
				samples["connect: "+sanitize(err)] = true
				mu.Unlock()
				return
			}
			defer func() { _ = sess.cs.Close() }()
			i := w
			for time.Now().Before(deadline) {
				op := l.Ops[i%len(l.Ops)]
				i++
				args := map[string]any{"endpoint": l.Endpoint, "container": l.Container}
				if op == "container_logs" {
					args["tail"] = 5
				}
				s := time.Now()
				cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				out, err := sess.cs.CallTool(cctx, &mcp.CallToolParams{Name: op, Arguments: args})
				cancel()
				d := float64(time.Since(s).Microseconds()) / 1000
				calls.Add(1)
				if err != nil || out.IsError {
					errc.Add(1)
					mu.Lock()
					if err != nil {
						samples["call: "+sanitize(err)] = true
					} else {
						samples["tool error result"] = true
					}
					mu.Unlock()
				} else {
					okc.Add(1)
					mu.Lock()
					lat = append(lat, d)
					byOp[op]++
					mu.Unlock()
				}
				time.Sleep(200 * time.Millisecond) // a polling client, not a flood
			}
		}(w)
	}
	wg.Wait()
	sort.Float64s(lat)
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(float64(len(lat)-1)*p)]
	}
	rep := loadReport{Workers: l.Workers, Seconds: time.Since(t0).Seconds(), Calls: calls.Load(), OK: okc.Load(), Errors: errc.Load(), ByOp: byOp, P50: pct(0.5), P95: pct(0.95), P99: pct(0.99)}
	for k := range samples {
		rep.ErrorSet = append(rep.ErrorSet, k)
	}
	sort.Strings(rep.ErrorSet)
	if len(rep.ErrorSet) > 5 {
		rep.ErrorSet = rep.ErrorSet[:5]
	}
	return rep
}

func main() {
	scriptPath := flag.String("script", "", "JSON script")
	tokensPath := flag.String("tokens", "", "JSON map name->token (mode 0600)")
	caPath := flag.String("ca", "", "PEM CA that signed the proxy certificate")
	dial := flag.String("dial", "", "host:port to connect to (the Compose proxy published on the isolated host)")
	serverName := flag.String("server-name", "", "TLS server name and Host of the public origin")
	flag.Parse()
	if *scriptPath == "" || *caPath == "" || *dial == "" || *serverName == "" {
		fmt.Fprintln(os.Stderr, "usage: mcpclient -script S -tokens T -ca CA -dial HOST:PORT -server-name NAME")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*scriptPath)
	must(err)
	var sc script
	must(json.Unmarshal(raw, &sc))
	tokens := map[string]string{}
	if *tokensPath != "" {
		st, err := os.Stat(*tokensPath)
		must(err)
		if st.Mode().Perm()&0o077 != 0 {
			fmt.Fprintln(os.Stderr, "refusing a tokens file readable by group or others")
			os.Exit(2)
		}
		tb, err := os.ReadFile(*tokensPath)
		must(err)
		must(json.Unmarshal(tb, &tokens))
	}
	pem, err := os.ReadFile(*caPath)
	must(err)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fmt.Fprintln(os.Stderr, "no certificate in CA file")
		os.Exit(2)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: *serverName, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, *dial)
		},
		MaxIdleConnsPerHost: 64,
	}
	e := &env{url: sc.URL, tokens: tokens, rt: tr}
	ctx := context.Background()
	if sc.Load != nil {
		must(json.NewEncoder(os.Stdout).Encode(e.load(ctx, *sc.Load)))
		return
	}
	open := map[string]*session{}
	results := make([]result, 0, len(sc.Steps))
	for _, s := range sc.Steps {
		results = append(results, e.run(ctx, s, open))
	}
	for _, o := range open {
		_ = o.cs.Close()
	}
	must(json.NewEncoder(os.Stdout).Encode(results))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpclient:", sanitize(err))
		os.Exit(1)
	}
}
