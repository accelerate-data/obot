package mcp

// Fork-only guarantee meeting upstream v0.28.0's refresh path (VD-7833): upstream's
// storage-backed token source persists a refreshed token through RefreshTokenConfig,
// which must carry the same catalog credential-generation fence as SetTokenConfig.
// Kept in its own file so an upstream sync cannot drop these tests by merging over
// a shared one.

import (
	"testing"
	"time"

	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func TestTokenStoreRefreshTokenConfigRejectsGrantAfterCatalogCredentialChange(t *testing.T) {
	const (
		entryName = "catalog-entry-1"
		mcpID     = "mcp-instance-1"
		mcpURL    = "https://mcp.example/api"
	)
	client := newCatalogTokenStoreTestClient(t, entryName, mcpID, true)
	require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-1", "MCP_URL": mcpURL, "GENERATION": "generation-1"},
	}))
	oldConfig := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}
	require.NoError(t, client.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1", oldConfig,
		&oauth2.Token{AccessToken: "old-access", RefreshToken: "refresh-1", Expiry: time.Now().Add(-time.Minute)}))

	store := &tokenStore{gatewayClient: client, userID: "user-1", mcpID: mcpID, mcpURL: mcpURL}
	config, previous, err := store.GetTokenConfig(t.Context())
	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotNil(t, previous)

	credentialKey := system.MCPOAuthCredentialName(entryName)
	release, err := client.AcquireCredentialLock(t.Context(), credentialKey)
	require.NoError(t, err)
	require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: credentialKey,
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-2", "MCP_URL": mcpURL, "GENERATION": "generation-2"},
	}))
	require.NoError(t, client.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID))
	release()

	err = store.RefreshTokenConfig(t.Context(), config, previous, &oauth2.Token{AccessToken: "refreshed-access", RefreshToken: "refresh-1"})
	require.ErrorIs(t, err, gateway.ErrMCPOAuthCatalogCredentialChanged)
	_, err = client.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}
