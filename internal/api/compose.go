package api

import (
	"net/http"
	"strings"
)

// Compose joins the REST adapter, the MCP adapter and the ordinary handler (static
// site, human setup/admin/session routes that also live under /api/v1) into one root
// handler. It dispatches on the exact, unrewritten request path:
//
//   - /api/v1/readyz and /api/v1/endpoints (and everything under it) belong to REST;
//   - /mcp and everything under /mcp/ belong to MCP;
//   - everything else is fallback.
//
// The machine namespaces are reserved even when an adapter is nil: a missing adapter
// answers the common 404, so a machine route can never fall through to the static site
// (or a single-page-app fallback), and an alternate spelling ("/mcp/", "/api/v1/endpoints//x")
// reaches the adapter's own strict router, never a path-cleaning mux that would redirect
// or normalize it into a valid route. Paths outside both namespaces, including every
// other /api/v1 path, are the fallback's: they can reach no adapter and no Docker.
func Compose(rest, mcp, fallback http.Handler) http.Handler {
	notFound := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteProblem(w, newProblem(http.StatusNotFound, CodeNotFound))
	})
	if rest == nil {
		rest = notFound
	}
	if mcp == nil {
		mcp = notFound
	}
	if fallback == nil {
		fallback = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.EscapedPath()
		switch {
		case isRESTPath(p):
			rest.ServeHTTP(w, r)
		case p == MCPPath || strings.HasPrefix(p, MCPPath+"/"):
			mcp.ServeHTTP(w, r)
		default:
			fallback.ServeHTTP(w, r)
		}
	})
}

func isRESTPath(p string) bool {
	return p == BasePath+"/readyz" || p == BasePath+"/endpoints" || strings.HasPrefix(p, BasePath+"/endpoints/")
}
