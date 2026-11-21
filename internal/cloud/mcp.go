package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yogenpoonudurai/enki/internal/ai"
	"github.com/yogenpoonudurai/enki/internal/remediate"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/rules"
	"github.com/yogenpoonudurai/enki/internal/version"
)

// mcpHandler serves the hosted MCP endpoint over Streamable HTTP. Every
// request is authenticated with the same bearer token used by the REST API;
// tool calls are scoped to that token (quota, audit, BYOK).
func (s *Server) mcpHandler() http.Handler {
	handler := mcp.NewStreamableHTTPHandler(s.mcpServerForRequest, &mcp.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        true,
		SessionTimeout:      5 * time.Minute,
		MaxRequestBodyBytes: s.cfg.MaxReportBytes + (1 << 20),
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.store.GetToken(r.Context(), bearerToken(r)); err != nil {
			writeError(w, http.StatusUnauthorized, "missing or invalid token")
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (s *Server) mcpServerForRequest(r *http.Request) *mcp.Server {
	tok, err := s.store.GetToken(r.Context(), bearerToken(r))
	if err != nil {
		return nil
	}
	byok := r.Header.Get("X-Enki-Provider-Key")
	return s.buildMCPServer(tok, byok)
}

func (s *Server) buildMCPServer(tok *Token, byok string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "enki-cloud", Version: version.Version}, nil)

	type triageArgs struct {
		Report  map[string]any `json:"report" jsonschema:"the enki JSON report to triage"`
		Consent bool           `json:"consent" jsonschema:"must be true: confirm a redacted findings payload may be sent to the model provider"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name: "enki_triage",
		Description: "Rank and explain an enki report with the hosted model. Requires consent=true and consumes one triage credit " +
			"(3 lifetime on free plans; never consumed when the X-Enki-Provider-Key header is supplied). " +
			"The model may only rank and explain; it never executes actions.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args triageArgs) (*mcp.CallToolResult, any, error) {
		if !args.Consent {
			return nil, nil, errors.New("consent required: set consent=true to send a redacted findings payload to the model provider")
		}
		rep, err := decodeReportObject(args.Report)
		if err != nil {
			return nil, nil, err
		}
		result, usage, cached, err := s.triageForToken(ctx, tok, byok, rep)
		if err != nil {
			return nil, nil, err
		}
		return jsonToolResult(struct {
			Result *ai.TriageResult `json:"result"`
			Usage  usageInfo        `json:"usage"`
			Cached bool             `json:"cached,omitempty"`
		}{
			Result: result,
			Usage:  usage,
			Cached: cached,
		})
	})

	type planArgs struct {
		Report map[string]any `json:"report" jsonschema:"the enki JSON report"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "enki_plan_fix",
		Description: "Return a deterministic remediation plan for a submitted enki report. No model call, no quota consumed.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args planArgs) (*mcp.CallToolResult, any, error) {
		rep, err := decodeReportObject(args.Report)
		if err != nil {
			return nil, nil, err
		}
		plan := remediate.BuildPlan(rep)
		return jsonToolResult(struct {
			ScanID  string             `json:"scan_id"`
			Score   int                `json:"score"`
			Verdict string             `json:"verdict"`
			Actions []remediate.Action `json:"actions"`
		}{ScanID: rep.Scan.ID, Score: rep.Summary.Score, Verdict: rep.Summary.Verdict, Actions: plan})
	})

	type rulesArgs struct {
		Module string `json:"module,omitempty" jsonschema:"only return rules for this module"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "enki_rules",
		Description: "List the enki rule catalogue (IDs, modules, severities).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args rulesArgs) (*mcp.CallToolResult, any, error) {
		var list []rules.Rule
		for _, r := range rules.Catalog {
			if args.Module == "" || r.Module == args.Module {
				list = append(list, r)
			}
		}
		return jsonToolResult(struct {
			Pack  string       `json:"pack"`
			Rules []rules.Rule `json:"rules"`
		}{Pack: rules.Version, Rules: list})
	})

	type explainArgs struct {
		RuleID string `json:"rule_id" jsonschema:"the enki rule ID to explain (e.g. AEP-001)"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "enki_explain_rule",
		Description: "Explain a rule ID: what it checks, its severity, and its module.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args explainArgs) (*mcp.CallToolResult, any, error) {
		for _, r := range rules.Catalog {
			if r.ID == args.RuleID {
				return jsonToolResult(r)
			}
		}
		return nil, nil, fmt.Errorf("unknown rule %q", args.RuleID)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "enki_usage",
		Description: "Return the plan and remaining triage allowance for the authenticated token.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return jsonToolResult(usageFor(tok))
	})

	return srv
}

func decodeReportObject(obj map[string]any) (*report.Report, error) {
	if len(obj) == 0 {
		return nil, errors.New("report is required")
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("invalid enki report: %w", err)
	}
	if len(rep.Findings) == 0 {
		return nil, errors.New("report contains no findings")
	}
	return &rep, nil
}

func jsonToolResult(v any) (*mcp.CallToolResult, any, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, v, nil
}
