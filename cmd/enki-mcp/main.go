// Command enki-mcp exposes enki's scan and remediation-planning tools over the
// Model Context Protocol: stdio by default, or a bearer-token-protected
// Streamable HTTP endpoint for a self-hosted listener (e.g. a home-lab mini pc).
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yogenpoonudurai/enki/internal/mcpserver"
)

func main() {
	httpAddr := flag.String("http", "", "serve Streamable HTTP MCP on this address (e.g. 127.0.0.1:8080) instead of stdio")
	token := flag.String("token", os.Getenv("ENKI_MCP_TOKEN"), "bearer token required by --http (or set ENKI_MCP_TOKEN); mandatory with --http")
	flag.Parse()

	server := mcpserver.New()
	if *httpAddr == "" {
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *token == "" {
		log.Fatal("--http requires --token (or ENKI_MCP_TOKEN); refusing to serve unauthenticated")
	}

	srv := &http.Server{
		Addr:              *httpAddr,
		Handler:           mcpserver.HTTPHandler(server, mcpserver.HTTPOptions{Token: *token}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("enki MCP (streamable http) listening on %s — bind to localhost or a tailnet interface, not a public one", *httpAddr)
	log.Fatal(srv.ListenAndServe())
}
