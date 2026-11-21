// Package ai provides a provider-agnostic LLM client and the constrained
// enki triage pipeline (redacted payloads, schema-validated output, no actions).
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Request is a single completion request.
type Request struct {
	Model       string
	System      string
	User        string
	MaxTokens   int
	Temperature float64
	JSONMode    bool
}

// Response is a normalized completion.
type Response struct {
	Text         string
	InputTokens  int
	OutputTokens int
	Model        string
}

// Provider completes chat requests.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// Config selects and authenticates a provider.
type Config struct {
	Provider string
	BaseURL  string
	APIKey   string
	Model    string
	Timeout  time.Duration
	Client   *http.Client
}

// DefaultConfig reads provider settings from the environment:
// ENKI_AI_PROVIDER, ENKI_AI_BASE_URL, ENKI_AI_KEY, ENKI_AI_MODEL, DEEPSEEK_API_KEY.
func DefaultConfig() Config {
	cfg := Config{
		Provider: os.Getenv("ENKI_AI_PROVIDER"),
		BaseURL:  os.Getenv("ENKI_AI_BASE_URL"),
		APIKey:   os.Getenv("ENKI_AI_KEY"),
		Model:    os.Getenv("ENKI_AI_MODEL"),
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("DEEPSEEK_API_KEY")
	}
	if cfg.Provider == "" {
		switch {
		case cfg.BaseURL != "":
			cfg.Provider = "openai"
		case cfg.APIKey != "":
			cfg.Provider = "deepseek"
		}
	}
	if cfg.Provider == "deepseek" && cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.deepseek.com"
	}
	if cfg.Provider == "ollama" && cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:11434/v1"
	}
	if cfg.Model == "" {
		switch cfg.Provider {
		case "ollama":
			cfg.Model = "llama3.2"
		default:
			cfg.Model = "deepseek-flash"
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	return cfg
}

// NewProvider builds a provider from cfg.
func NewProvider(cfg Config) (Provider, error) {
	if cfg.Provider == "" {
		return nil, fmt.Errorf("no AI provider configured: set DEEPSEEK_API_KEY or ENKI_AI_BASE_URL")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("provider %q has no base URL (set ENKI_AI_BASE_URL)", cfg.Provider)
	}
	if cfg.Provider != "ollama" && cfg.APIKey == "" {
		return nil, fmt.Errorf("provider %q requires an API key (ENKI_AI_KEY or DEEPSEEK_API_KEY)", cfg.Provider)
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &openAIProvider{
		name:         cfg.Provider,
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:       cfg.APIKey,
		defaultModel: cfg.Model,
		client:       client,
	}, nil
}

type openAIProvider struct {
	name         string
	baseURL      string
	apiKey       string
	defaultModel string
	client       *http.Client
}

func (p *openAIProvider) Name() string { return p.name }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	Temperature    float64         `json:"temperature"`
	ResponseFormat *chatJSONFormat `json:"response_format,omitempty"`
}

type chatJSONFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (p *openAIProvider) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = p.defaultModel
	}
	body := chatRequest{
		Model:       model,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		Messages:    make([]chatMessage, 0, 2),
	}
	if req.System != "" {
		body.Messages = append(body.Messages, chatMessage{Role: "system", Content: req.System})
	}
	body.Messages = append(body.Messages, chatMessage{Role: "user", Content: req.User})
	if req.JSONMode {
		body.ResponseFormat = &chatJSONFormat{Type: "json_object"}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Response{}, err
	}
	url := p.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "enki/0.3 (AI triage)")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Response{}, fmt.Errorf("%s returned HTTP %d: %s", p.name, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var out chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return Response{}, err
	}
	if len(out.Choices) == 0 {
		return Response{}, fmt.Errorf("%s returned no choices", p.name)
	}
	modelName := out.Model
	if modelName == "" {
		modelName = model
	}
	return Response{
		Text:         out.Choices[0].Message.Content,
		InputTokens:  out.Usage.PromptTokens,
		OutputTokens: out.Usage.CompletionTokens,
		Model:        modelName,
	}, nil
}
