package mcp

// Fork-only guarantee (fork #21, restored by VD-6903): a server-owned remote header is deployment configuration (reported missing until a credential supplies it, then sent as a server header), while a per-user header is passed through from the caller and never reported as missing server configuration. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"slices"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
)

func TestServerToServerConfig_RemoteHeadersAreDeploymentConfigAndMultiUserHeadersArePassthrough(t *testing.T) {
	baseURL := "http://localhost:8080"
	serverHeader := types.ConfigFromHeader(types.MCPHeader{Key: "X-API-Key", Required: true, Sensitive: true})
	// The pre-vMCP multiUserConfig.userDefinedHeaders migrate into Config with
	// UserAllowed set, so that flag is what marks a header as per-user.
	userHeader := serverHeader
	userHeader.UserAllowed = true

	tests := []struct {
		name                       string
		manifest                   types.MCPServerManifest
		credEnv                    map[string]string
		expectedMissing            []string
		expectedHeaders            []string
		expectedPassthroughHeaders []string
	}{
		{
			name: "remote header without deployment credential is missing server config",
			manifest: types.MCPServerManifest{
				Runtime:      types.RuntimeRemote,
				RemoteConfig: &types.RemoteRuntimeConfig{URL: "https://example.com/mcp"},
				Config:       []types.MCPConfig{serverHeader},
			},
			expectedMissing: []string{"X-API-Key"},
		},
		{
			name: "multi-user header is passthrough and not missing server config",
			manifest: types.MCPServerManifest{
				Runtime:      types.RuntimeRemote,
				RemoteConfig: &types.RemoteRuntimeConfig{URL: "https://example.com/mcp"},
				Config:       []types.MCPConfig{userHeader},
			},
			expectedPassthroughHeaders: []string{"X-API-Key"},
		},
		{
			name: "remote header with deployment credential becomes server header",
			manifest: types.MCPServerManifest{
				Runtime:      types.RuntimeRemote,
				RemoteConfig: &types.RemoteRuntimeConfig{URL: "https://example.com/mcp"},
				Config:       []types.MCPConfig{serverHeader},
			},
			credEnv:         map[string]string{"X-API-Key": "server-secret"},
			expectedHeaders: []string{"X-API-Key=server-secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpServer := v1.MCPServer{
				Name: "test-server",
				Spec: v1.MCPServerSpec{
					Manifest: tt.manifest,
				},
			}

			config, missing, err := ServerToServerConfig(mcpServer, mcpServer.ValidConnectURLs(baseURL), "test-user-id", "test-scope", "test-catalog", tt.credEnv)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(missing, tt.expectedMissing) {
				t.Fatalf("expected missing config %v, got %v", tt.expectedMissing, missing)
			}
			if !slices.Equal(config.Headers, tt.expectedHeaders) {
				t.Fatalf("expected server headers %v, got %v", tt.expectedHeaders, config.Headers)
			}
			if !slices.Equal(config.PassthroughHeaderNames, tt.expectedPassthroughHeaders) {
				t.Fatalf("expected passthrough headers %v, got %v", tt.expectedPassthroughHeaders, config.PassthroughHeaderNames)
			}
		})
	}
}
