package adapters_test

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.15: usage accounting lives in the shared operation service, so REST and MCP count
// identically. The same calls, run over each transport against its own fresh store, must
// produce the same hourly rollup, and it must be exactly the declared one: allowed calls
// by their granting selector, policy denials by the deciding selector (none for a default
// deny), and nothing at all for a request that is not a decision of a verified principal
// (self/peer, unknown or revoked credential, no credential). Tool listing and transport
// errors are never usage.
func TestUsageIsAccountedIdenticallyOverRESTAndMCP(t *testing.T) {
	calls := func(e *env) []call {
		return []call{
			req(e.token("granted"), "container_status", "edge-proxy"),                                // allowed
			req(e.token("granted"), "container_config", "edge-proxy"),                                // allowed
			req(e.token("granted"), "container_logs", "edge-proxy", a("tail", 2)),                    // allowed
			req(e.token("granted"), "container_status", "billing-worker"),                            // default deny: no selector
			req(e.token("nogrant"), "container_start", "edge-proxy"),                                 // default deny: no selector
			req(e.token("capped"), "container_logs", "edge-proxy", a("tail", 6)),                     // cap exceeded: deciding selector
			req(e.token("deny"), "container_status", "billing-worker"),                               // explicit deny: deciding selector
			req(e.token("granted"), "container_status", "mandatary-self"),                            // self-protected: uncounted
			req(e.token("granted"), "container_status", "reverse-proxy"),                             // labelled peer: uncounted
			{op: "container_status", endpoint: "local", container: "edge-proxy", noAuth: true},       // no credential: uncounted
			req("mdt_unknownunknownunknownunknownunknownunknown0", "container_status", "edge-proxy"), // unknown token: uncounted
			req(e.token("revoked"), "container_status", "edge-proxy"),                                // revoked token: uncounted
		}
	}

	counts := func(e *env) map[usageKey][3]int64 {
		rows, err := e.ledger.Rollups(t.Context(), store.UsageHourly)
		if err != nil {
			t.Fatal(err)
		}
		out := map[usageKey][3]int64{}
		for _, r := range rows {
			if string(r.UserID) != ownerID || r.EndpointID != localEP {
				t.Fatalf("unexpected attribution %+v", r)
			}
			k := usageKey{string(r.AgentID), string(r.SelectorID), r.Operation}
			if _, dup := out[k]; dup {
				t.Fatalf("duplicate rollup row %+v", k)
			}
			out[k] = [3]int64{r.Allowed, r.Denied, r.Error}
		}
		return out
	}
	agent := func(n int) string { id, _ := agentN(n); return id }
	want := map[usageKey][3]int64{
		{agent(1), selEdge, "container:inspect_status"}:    {1, 0, 0},
		{agent(1), selEdge, "container:inspect_config"}:    {1, 0, 0},
		{agent(1), selEdge, "container:logs"}:              {1, 0, 0},
		{agent(1), "", "container:inspect_status"}:         {0, 1, 0},
		{agent(6), "", "container:start"}:                  {0, 1, 0},
		{agent(3), selEdge, "container:logs"}:              {0, 1, 0},
		{agent(5), selBilling, "container:inspect_status"}: {0, 1, 0},
	}
	var results []map[usageKey][3]int64
	for _, tr := range []transport{restTransport{}, mcpTransport{}} {
		e := newEnv(t, func(o *envOptions) { o.usage = true })
		for _, c := range calls(e) {
			tr.do(t, e, c)
		}
		got := counts(e)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s accounted\n got %v\nwant %v", tr.name(), render(got), render(want))
		}
		results = append(results, got)
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Errorf("REST and MCP accounted differently:\n REST %v\n MCP  %v", render(results[0]), render(results[1]))
	}
	// A refused tool listing / transport-level rejection is not usage either.
	e := newEnv(t, func(o *envOptions) { o.usage = true })
	if o := (restTransport{}).do(t, e, req(e.token("granted"), "container_status", "edge-proxy", a("all", true))); o.Status != 400 {
		t.Fatalf("unknown field: %s", o)
	}
	if n := len(counts(e)); n != 0 {
		t.Fatalf("a schema-rejected request was accounted: %d rows", n)
	}
}

type usageKey struct{ agent, selector, op string }

func render(m map[usageKey][3]int64) string {
	var lines []string
	for k, v := range m {
		lines = append(lines, fmt.Sprintf("%v=%v", k, v))
	}
	sort.Strings(lines)
	return fmt.Sprint(lines)
}
