package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type protocolErrorRoundTripFunc func(*http.Request) (*http.Response, error)

func (f protocolErrorRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSafeProtocolErrorBodyPreservesActionableMessage(t *testing.T) {
	const diagnostic = "App is not enabled for Slack MCP server access. Please enable it here: https://api.slack.com/apps/A123/app-assistant"
	input := []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"` + diagnostic + `"}}`)
	output := safeProtocolErrorBody(input)
	if output == nil {
		t.Fatal("normalization returned nil for a JSON-RPC error with a null ID")
	}

	var got struct {
		ID    int `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 0 || got.Error.Code != -32600 || got.Error.Message != diagnostic {
		t.Fatalf("normalized error = %#v, want code and actionable message intact", got)
	}
}

func TestSafeProtocolErrorBodyLeavesOtherBodiesAlone(t *testing.T) {
	for _, body := range []string{
		`Bad Request`,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":""}}`,
	} {
		if got := safeProtocolErrorBody([]byte(body)); got != nil {
			t.Errorf("safeProtocolErrorBody(%q) = %q, want no rewrite", body, got)
		}
	}
}

func TestSafeProtocolErrorBodyRedactsCredentialForms(t *testing.T) {
	tests := []struct {
		name        string
		id          json.RawMessage
		message     string
		wantMessage string
	}{
		{
			name:        "quoted access token and bearer",
			id:          json.RawMessage("null"),
			message:     `App disabled; access_token="secret-value"; Bearer "secret-bearer"; enable Slack MCP`,
			wantMessage: `App disabled; access_token=[REDACTED]; Bearer [REDACTED]; enable Slack MCP`,
		},
		{
			name:        "cookie and URL userinfo",
			id:          json.RawMessage("null"),
			message:     `Visit https://user:secret-pass@api.slack.com/apps/A123; Cookie: session=secret-cookie; refresh=another-secret`,
			wantMessage: `Visit https://[REDACTED]@api.slack.com/apps/A123; Cookie: [REDACTED]`,
		},
		{
			name:        "cookie before remediation",
			id:          json.RawMessage("null"),
			message:     `Cookie: session=secret-cookie; refresh=another-secret; enable Slack at https://api.slack.com/apps/A123/app-assistant`,
			wantMessage: `Cookie: [REDACTED]; enable Slack at https://api.slack.com/apps/A123/app-assistant`,
		},
		{
			name:        "private key",
			id:          json.RawMessage("null"),
			message:     "Rejected key -----BEGIN PRIVATE KEY-----\nsecret-key\n-----END PRIVATE KEY-----; enable Slack MCP",
			wantMessage: `Rejected key [REDACTED]; enable Slack MCP`,
		},
		{
			name:        "authorization header and runtime token",
			id:          json.RawMessage("null"),
			message:     `Authorization: Basic abc123; supplied vd_pat_secret123; enable Slack MCP`,
			wantMessage: `Authorization: [REDACTED]; supplied [REDACTED]; enable Slack MCP`,
		},
		{
			name:        "embedded JSON credentials and provider token",
			id:          json.RawMessage("null"),
			message:     `Rejected {"authorization":"Basic abc123","access_token":"secret-value"}; xoxb-12345678901234567890; enable Slack MCP`,
			wantMessage: `Rejected {"authorization":"[REDACTED]","access_token":"[REDACTED]"}; [REDACTED]; enable Slack MCP`,
		},
		{
			name:        "valid ID still redacted",
			id:          json.RawMessage("7"),
			message:     `App disabled; Bearer secret-bearer; enable Slack MCP`,
			wantMessage: `App disabled; Bearer [REDACTED]; enable Slack MCP`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(struct {
				Version string          `json:"jsonrpc"`
				ID      json.RawMessage `json:"id"`
				Error   struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}{Version: "2.0", ID: tt.id, Error: struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}{Code: -32600, Message: tt.message}})
			if err != nil {
				t.Fatal(err)
			}
			output := safeProtocolErrorBody(body)
			if output == nil {
				t.Fatal("normalization returned nil")
			}
			var got struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatal(err)
			}
			if got.Error.Message != tt.wantMessage {
				t.Fatalf("message = %q, want %q", got.Error.Message, tt.wantMessage)
			}
		})
	}
}

func TestProtocolErrorTransportBoundsOversizedBodyWithoutLeakingIt(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"error": map[string]any{
			"code":    -32600,
			"message": "Bearer provider-secret-token " + string(bytes.Repeat([]byte("x"), maxProtocolErrorBody)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := &http.Client{Transport: protocolErrorRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	wrapped := withSafeProtocolErrors(base)
	if wrapped == base || wrapped.Transport == base.Transport {
		t.Fatal("wrapper changed the caller's HTTP client")
	}
	req, err := http.NewRequest(http.MethodPost, "https://mcp.example.test/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := wrapped.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("error response exceeds")) || bytes.Contains(got, []byte("provider-secret-token")) {
		t.Fatalf("oversized response body = %q, want bounded safe diagnostic", got)
	}
}
