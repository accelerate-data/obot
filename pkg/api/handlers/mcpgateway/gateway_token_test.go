package mcpgateway

import (
	"testing"
	"time"

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
		Audiences:     []string{"https://obot.example.test/mcp-connect/ms1server"},
	}

	got := gatewayTokenContext(authenticatedUser, server, now)

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
