package mcpgateway

import (
	"errors"
	"testing"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/storage/scheme"
	sservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTokenStoreRefreshCannotResurrectCatalogGrantAfterAppChange(t *testing.T) {
	const (
		entryName = "catalog-entry-1"
		mcpID     = "mcp-instance-1"
		mcpURL    = "https://mcp.example/api"
	)
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *gateway.Client)
	}{
		{
			name: "same client ID with new secret",
			change: func(t *testing.T, client *gateway.Client) {
				t.Helper()
				require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
					Context: system.MCPOAuthCredentialName(entryName),
					Name:    "oauth",
					Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-2"},
				}))
			},
		},
		{
			name: "credential cleared",
			change: func(t *testing.T, client *gateway.Client) {
				t.Helper()
				deleted, err := client.DeleteCredential(t.Context(), system.MCPOAuthCredentialName(entryName), "oauth")
				require.NoError(t, err)
				require.True(t, deleted)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newCatalogTokenStoreTestClient(t, entryName, mcpID)
			require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
				Context: system.MCPOAuthCredentialName(entryName),
				Name:    "oauth",
				Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-1"},
			}))
			oldConfig := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}
			require.NoError(t, client.ReplaceMCPOAuthTokenWithCatalogCredentialFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, oldConfig,
				&oauth2.Token{AccessToken: "old-access", RefreshToken: "refresh-1", Expiry: time.Now().Add(-time.Minute)}))

			store := &tokenStore{gatewayClient: client, userID: "user-1", mcpID: mcpID}
			config, _, err := store.GetTokenConfig(t.Context(), mcpURL)
			require.NoError(t, err)
			require.NotNil(t, config)

			credentialKey := system.MCPOAuthCredentialName(entryName)
			release, err := client.AcquireCredentialLock(t.Context(), credentialKey)
			require.NoError(t, err)
			tc.change(t, client)
			require.NoError(t, client.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID))
			release()

			err = store.SetTokenConfig(t.Context(), mcpURL, config, &oauth2.Token{AccessToken: "refreshed-access", RefreshToken: "refresh-1"})
			require.ErrorIs(t, err, gateway.ErrMCPOAuthCatalogCredentialChanged)
			_, err = client.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL)
			require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		})
	}
}

func TestTokenStoreInfersFenceForLegacyCatalogGrant(t *testing.T) {
	const (
		entryName = "catalog-entry-1"
		mcpID     = "mcp-instance-1"
		mcpURL    = "https://mcp.example/api"
	)
	client := newCatalogTokenStoreTestClient(t, entryName, mcpID)
	require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-1"},
	}))
	oldConfig := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}
	require.NoError(t, client.ReplaceMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL, "", oldConfig,
		&oauth2.Token{AccessToken: "old-access", RefreshToken: "refresh-1"}))

	store := &tokenStore{gatewayClient: client, userID: "user-1", mcpID: mcpID}
	config, _, err := store.GetTokenConfig(t.Context(), mcpURL)
	require.NoError(t, err)
	require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-2"},
	}))
	require.NoError(t, client.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID))

	err = store.SetTokenConfig(t.Context(), mcpURL, config, &oauth2.Token{AccessToken: "refreshed-access"})
	require.ErrorIs(t, err, gateway.ErrMCPOAuthCatalogCredentialChanged)
	_, err = client.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL)
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound))
}

func newCatalogTokenStoreTestClient(t *testing.T, entryName, mcpID string) *gateway.Client {
	t.Helper()
	storage := clientfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(
			&v1.MCPServerInstance{
				ObjectMeta: metav1.ObjectMeta{Namespace: system.DefaultNamespace, Name: mcpID},
				Spec:       v1.MCPServerInstanceSpec{MCPServerCatalogEntryName: entryName},
			},
			&v1.MCPServerCatalogEntry{
				ObjectMeta: metav1.ObjectMeta{Namespace: system.DefaultNamespace, Name: entryName},
				Spec: v1.MCPServerCatalogEntrySpec{Manifest: apitypes.MCPServerCatalogEntryManifest{
					RemoteConfig: &apitypes.RemoteCatalogConfig{FixedURL: "https://mcp.example/api"},
				}},
			},
		).
		Build()
	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	client := gateway.New(t.Context(), db, storage, nil, nil, nil, nil, time.Hour, 10, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	return client
}
