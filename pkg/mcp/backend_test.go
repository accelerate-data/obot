package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oasdiff/yaml"
	ntypes "github.com/obot-platform/nanobot/pkg/types"
	"github.com/obot-platform/obot/apiclient/types"
)

func TestEnsureServerReadyUsesHealthzPath(t *testing.T) {
	var healthzCalls, mcpCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			healthzCalls++
			if r.Method != http.MethodGet {
				t.Fatalf("expected healthz check to use GET, got %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		case "/mcp":
			mcpCalls++
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err := ensureServerReady(ctx, server.URL, ServerConfig{
		Runtime:       types.RuntimeContainerized,
		ContainerPath: "/mcp",
		HealthzPath:   "/ready",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if healthzCalls != 1 {
		t.Fatalf("expected exactly one healthz call, got %d", healthzCalls)
	}
	if mcpCalls != 0 {
		t.Fatalf("expected MCP endpoint not to be probed, got %d calls", mcpCalls)
	}
}

func TestEnsureServerReadyHealthzPathWaitsForOK(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err := ensureServerReady(ctx, server.URL+"/", ServerConfig{HealthzPath: "healthz"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls != 2 {
		t.Fatalf("expected two healthz calls, got %d", calls)
	}
}

func TestConstructMCPServerNanobotYAMLForCompositeIncludesOnlyEnabledTools(t *testing.T) {
	data, err := constructMCPServerNanobotYAMLForComposite(ServerConfig{
		Components: []ComponentServer{
			{
				Name:       "configured-ping-echo",
				URL:        "https://example.com/mcp",
				ToolPrefix: "configured_",
				Tools: []types.ToolOverride{
					{Name: "ping", Enabled: false},
					{Name: "echo", Enabled: true},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := mustUnmarshalNanobotConfig(t, data)
	server := config.MCPServers["configured-ping-echo"]
	if server.ToolPrefix != "configured_" {
		t.Fatalf("expected toolPrefix configured_, got %q", server.ToolPrefix)
	}
	if server.NoTools {
		t.Fatal("expected noTools to be false")
	}
	if len(server.ToolOverrides) != 1 {
		t.Fatalf("expected one tool override, got %#v", server.ToolOverrides)
	}
	if _, ok := server.ToolOverrides["echo"]; !ok {
		t.Fatalf("expected echo to be included, got %#v", server.ToolOverrides)
	}
	if _, ok := server.ToolOverrides["ping"]; ok {
		t.Fatalf("expected ping to be omitted, got %#v", server.ToolOverrides)
	}
}

func TestConstructMCPServerNanobotYAMLForCompositeOmitsToolConfigWhenOverridesOmitted(t *testing.T) {
	data, err := constructMCPServerNanobotYAMLForComposite(ServerConfig{
		Components: []ComponentServer{
			{
				Name: "default-tools",
				URL:  "https://example.com/mcp",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := mustUnmarshalNanobotConfig(t, data)
	server := config.MCPServers["default-tools"]
	if server.NoTools {
		t.Fatal("expected omitted overrides not to set noTools")
	}
	if strings.Contains(string(data), "toolOverrides") {
		t.Fatalf("expected omitted overrides not to set toolOverrides, got YAML:\n%s", string(data))
	}
	if len(server.ToolOverrides) != 0 {
		t.Fatalf("expected omitted overrides not to set toolOverrides, got %#v", server.ToolOverrides)
	}
}

func TestConstructMCPServerNanobotYAMLForCompositePreservesComponentsWithNoEnabledTools(t *testing.T) {
	data, err := constructMCPServerNanobotYAMLForComposite(ServerConfig{
		Components: []ComponentServer{
			{
				Name:    "ping-echo",
				URL:     "https://example.com/mcp",
				Tools:   []types.ToolOverride{},
				noTools: true,
			},
			{
				Name:       "configured-ping-echo",
				URL:        "https://example.com/configured-mcp",
				ToolPrefix: "configured_",
				Tools: []types.ToolOverride{
					{Name: "ping", Enabled: false},
					{Name: "echo", Enabled: true},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := mustUnmarshalNanobotConfig(t, data)

	disabledOnlyServer := config.MCPServers["ping-echo"]
	if !disabledOnlyServer.NoTools {
		t.Fatal("expected component with no enabled tools to set noTools")
	}
	if len(disabledOnlyServer.ToolOverrides) != 0 {
		t.Fatalf("expected no enabled tool overrides, got %#v", disabledOnlyServer.ToolOverrides)
	}

	configuredServer := config.MCPServers["configured-ping-echo"]
	if configuredServer.ToolPrefix != "configured_" {
		t.Fatalf("expected toolPrefix configured_, got %q", configuredServer.ToolPrefix)
	}
	if configuredServer.NoTools {
		t.Fatal("expected configured component to expose enabled tools")
	}
	if len(configuredServer.ToolOverrides) != 1 {
		t.Fatalf("expected one configured tool override, got %#v", configuredServer.ToolOverrides)
	}
	if _, ok := configuredServer.ToolOverrides["echo"]; !ok {
		t.Fatalf("expected echo to be included, got %#v", configuredServer.ToolOverrides)
	}
	if _, ok := configuredServer.ToolOverrides["ping"]; ok {
		t.Fatalf("expected ping to be omitted, got %#v", configuredServer.ToolOverrides)
	}
}

func TestConstructMCPServerNanobotYAMLForCompositeOmitsWebhooks(t *testing.T) {
	data, err := constructMCPServerNanobotYAMLForComposite(ServerConfig{
		Components: []ComponentServer{
			{
				Name: "component",
				URL:  "https://example.com/mcp",
			},
		},
		Webhooks: []Webhook{
			{
				Name:        "fallback-webhook",
				DisplayName: "review/webhook",
				URL:         "https://example.com/webhook",
				ToolName:    "validate",
				Definitions: types.MCPSelectors{
					{Method: "tools/call", Identifiers: []string{"echo"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := mustUnmarshalNanobotConfig(t, data)

	if _, ok := config.MCPServers["review-webhook"]; ok {
		t.Fatalf("expected webhook server to be omitted, got %#v", config.MCPServers)
	}
	if len(config.Hooks) != 0 {
		t.Fatalf("expected hook mappings to be omitted, got %#v", config.Hooks)
	}
}

func mustUnmarshalNanobotConfig(t *testing.T, data []byte) ntypes.Config {
	t.Helper()
	var config ntypes.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("failed to unmarshal nanobot config: %v\n%s", err, string(data))
	}
	return config
}

// A command runtime (npx/uvx) downloads its package on first start. When that download
// outruns nanobot's own two-minute first health check, nanobot records
// "initialize failed: context deadline exceeded" and serves it as a 500 until its health
// ticker retries a minute later — by which point the package is cached and the check
// passes. The readiness poller must survive that window instead of aborting the whole
// startup budget on the first 500 (VD-5283).
func TestEnsureServerReadyToleratesTransientInternalServerError(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		calls++
		if calls < 3 {
			http.Error(w, "initialize failed: context deadline exceeded", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err := ensureServerReady(ctx, server.URL+"/", ServerConfig{HealthzPath: "healthz"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected three healthz calls, got %d", calls)
	}
}

func TestEnsureServerReadyFailsOnPersistentInternalServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "tool listing failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	err := ensureServerReady(ctx, server.URL+"/", ServerConfig{HealthzPath: "healthz"})
	if !errors.Is(err, ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "tool listing failed") {
		t.Fatalf("expected the nanobot body to be relayed, got %v", err)
	}
}

// analyzePodStatus probes for a permanent verdict inside a watch loop rather than polling
// for readiness, so it passes a zero grace period and must still fail on the first 500.
func TestEnsureHTTPGetOKFailsFastWhenInternalServerErrorGraceIsZero(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, "tool listing failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := ensureHTTPGetOK(ctx, server.Client(), server.URL+"/healthz", 0); !errors.Is(err, ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one healthz call, got %d", calls)
	}
}

func TestEnsureHTTPGetOKGivesUpAfterInternalServerErrorGrace(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, "tool listing failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	if err := ensureHTTPGetOK(ctx, server.Client(), server.URL+"/healthz", 200*time.Millisecond); !errors.Is(err, ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("expected the grace period to end the poll, not the context")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("gave up after %v, before the grace period elapsed", elapsed)
	}
	if calls < 2 {
		t.Fatalf("expected the poll to retry within the grace period, got %d calls", calls)
	}
}

// A server alternating 500 with any other status must not postpone the permanence verdict
// for ever: the 500 window measures how long the server has been failing to come up, so
// only a 200 clears it.
func TestEnsureHTTPGetOKInternalServerErrorGraceSurvivesInterleavedStatuses(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls%2 == 0 {
			http.Error(w, "waiting for startup", http.StatusTooEarly)
			return
		}
		http.Error(w, "tool listing failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	if err := ensureHTTPGetOK(ctx, server.Client(), server.URL+"/healthz", 200*time.Millisecond); !errors.Is(err, ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("expected the grace period to end the poll, not the context")
	}
}
