package mcpserver

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sessionIdleTimeout reaps abandoned streamable-HTTP sessions so a long-lived
// listener does not accumulate goroutines per disconnected client.
const sessionIdleTimeout = 30 * time.Minute

// HTTPOptions configures the network transport for the MCP tools.
type HTTPOptions struct {
	// Token is the bearer token every request must present in the
	// Authorization header. It must be non-empty.
	Token string
}

// HTTPHandler serves the MCP server over Streamable HTTP at /mcp (and at the
// root path) behind bearer-token auth. /healthz is an unauthenticated liveness
// probe that returns no data.
func HTTPHandler(s *mcp.Server, opts HTTPOptions) http.Handler {
	stream := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{SessionTimeout: sessionIdleTimeout},
	)
	authed := requireToken(opts.Token, stream)

	mux := http.NewServeMux()
	mux.Handle("/mcp", authed)
	mux.Handle("/", authed)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func requireToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := "Bearer " + token
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="enki"`)
			http.Error(w, `{"error":"missing or invalid bearer token"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
