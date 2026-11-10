package mcpgateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	nmcp "github.com/obot-platform/nanobot/pkg/mcp"
	"github.com/obot-platform/obot/pkg/jwt/persistent"
	"github.com/obot-platform/obot/pkg/mcp"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestGatewayTokenContextScopesAuthenticatedUserToMCPServer(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	authenticatedUser := &user.DefaultInfo{
		Name: "Studio User",
		UID:  "42",
		Extra: map[string][]string{
			"email":                   {"studio@example.test"},
			"auth_provider_name":      {"generic-oauth-auth-provider"},
			"auth_provider_namespace": {system.DefaultNamespace},
			"auth_provider_user_id":   {"studio-user-1"},
		},
	}
	server := mcp.ServerConfig{
		MCPServerName: "ms1server",
	}

	got := gatewayTokenContext(
		authenticatedUser,
		server.MCPServerName,
		"https://obot.example.test/mcp-connect/ms1server",
		now,
	)

	require.Equal(t, "42", got.UserID)
	require.Equal(t, "Studio User", got.UserName)
	require.Equal(t, "studio@example.test", got.UserEmail)
	require.Equal(t, "ms1server", got.MCPID)
	require.Equal(t, "https://obot.example.test/mcp-connect/ms1server", got.Audience)
	require.Equal(t, []string{"mcp", "authenticated"}, []string(got.UserGroups))
	require.Equal(t, "generic-oauth-auth-provider", got.AuthProviderName)
	require.Equal(t, system.DefaultNamespace, got.AuthProviderNamespace)
	require.Equal(t, "studio-user-1", got.AuthProviderUserID)
	require.Equal(t, now, got.IssuedAt.Time)
	require.Equal(t, now.Add(gatewayTokenExpiration), got.ExpiresAt.Time)
}

func TestGatewayTokenContextPreservesResolvedMCPServerInstance(t *testing.T) {
	const (
		instanceID = "msi1user-server"
		audience   = "https://obot.example.test/mcp-connect/ms1server"
	)
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)

	got := gatewayTokenContext(
		&user.DefaultInfo{UID: "42"},
		instanceID,
		audience,
		now,
	)

	require.Equal(t, instanceID, got.MCPID)
	require.Equal(t, audience, got.Audience)
}

func TestGatewayAuthorizationOmitsCredentialsWhenAuthenticationIsDisabled(t *testing.T) {
	mintCalled := false
	handler := Handler{
		mintToken: func(context.Context, persistent.TokenContext) (string, error) {
			mintCalled = true
			return "unexpected", nil
		},
	}

	got, err := handler.gatewayToken(t.Context(), &user.DefaultInfo{}, "", mcp.ServerConfig{})

	require.NoError(t, err)
	require.Empty(t, got)
	require.False(t, mintCalled)
}

func TestGatewayTokenUsesExactServerAudience(t *testing.T) {
	server := mcp.ServerConfig{
		MCPServerName: "ms1server",
		Audiences: []string{
			"https://obot.example.test/mcp-connect/catalog-entry",
			"https://obot.example.test/mcp-connect/ms1server",
		},
	}
	var minted persistent.TokenContext
	handler := Handler{
		mintToken: func(_ context.Context, tokenContext persistent.TokenContext) (string, error) {
			minted = tokenContext
			return "scoped-gateway-token", nil
		},
	}

	got, err := handler.gatewayToken(t.Context(), &user.DefaultInfo{UID: "42"}, server.MCPServerName, server)

	require.NoError(t, err)
	require.Equal(t, "scoped-gateway-token", got)
	require.Equal(t, "ms1server", minted.MCPID)
	require.Equal(t, "https://obot.example.test/mcp-connect/ms1server", minted.Audience)
	require.WithinDuration(t, minted.IssuedAt.Add(gatewayTokenExpiration), minted.ExpiresAt.Time, time.Second)
}

func TestGatewayTokenUsesExactServerAudienceBelowBasePath(t *testing.T) {
	server := mcp.ServerConfig{
		MCPServerName: "ms1server",
		Audiences: []string{
			"https://studio.example.test/obot/mcp-connect/catalog-entry",
			"https://studio.example.test/obot/mcp-connect/ms1server",
		},
	}
	var minted persistent.TokenContext
	handler := Handler{
		mintToken: func(_ context.Context, tokenContext persistent.TokenContext) (string, error) {
			minted = tokenContext
			return "scoped-gateway-token", nil
		},
	}

	got, err := handler.gatewayToken(t.Context(), &user.DefaultInfo{UID: "42"}, server.MCPServerName, server)

	require.NoError(t, err)
	require.Equal(t, "scoped-gateway-token", got)
	require.Equal(t, "ms1server", minted.MCPID)
	require.Equal(t, "https://studio.example.test/obot/mcp-connect/ms1server", minted.Audience)
}

func TestWithGatewayTokenReplacesInboundBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://obot.test/mcp-connect/ms1server", nil)
	req.Header.Set("Authorization", "Bearer studio-iat")

	ctx := withGatewayToken(req.Context(), req, "scoped-gateway-token")

	require.Equal(t, "Bearer scoped-gateway-token", req.Header.Get("Authorization"))
	require.Equal(t, "scoped-gateway-token", nmcp.TokenFromContext(ctx))
}

func TestWithGatewayTokenRemovesInboundBearerWhenAuthenticationIsDisabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://obot.test/mcp-connect/ms1server", nil)
	req.Header.Set("Authorization", "Bearer studio-iat")

	ctx := withGatewayToken(req.Context(), req, "")

	require.Empty(t, req.Header.Get("Authorization"))
	require.Empty(t, nmcp.TokenFromContext(ctx))
}
