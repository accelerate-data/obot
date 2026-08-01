package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestStateManagerFencesCallbackWriteAfterProviderExchange(t *testing.T) {
	const (
		entryName = "catalog-entry-1"
		mcpID     = "mcp-instance-1"
		mcpURL    = "https://mcp.example/api"
	)
	for _, tc := range []struct {
		name       string
		changeApp  func(*testing.T, *gateway.Client)
		wantErr    bool
		wantAccess string
	}{
		{name: "ordinary callback succeeds", wantAccess: "provider-access"},
		{
			name:    "rotation during exchange rejects old app grant",
			wantErr: true,
			changeApp: func(t *testing.T, client *gateway.Client) {
				t.Helper()
				require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
					Context: system.MCPOAuthCredentialName(entryName), Name: "oauth",
					Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-2"},
				}))
				require.NoError(t, client.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID))
			},
		},
		{
			name:    "clear during exchange rejects old app grant",
			wantErr: true,
			changeApp: func(t *testing.T, client *gateway.Client) {
				t.Helper()
				deleted, err := client.DeleteCredential(t.Context(), system.MCPOAuthCredentialName(entryName), "oauth")
				require.NoError(t, err)
				require.True(t, deleted)
				require.NoError(t, client.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newStateManagerTestClient(t, entryName, mcpID)
			require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
				Context: system.MCPOAuthCredentialName(entryName), Name: "oauth",
				Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-1"},
			}))

			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.changeApp != nil {
					release, err := client.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(entryName))
					require.NoError(t, err)
					tc.changeApp(t, client)
					release()
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"access_token":"provider-access","refresh_token":"provider-refresh","token_type":"Bearer"}`)
			}))
			t.Cleanup(provider.Close)

			manager := newStateManager(client)
			config := &oauth2.Config{
				ClientID:     "client-1",
				ClientSecret: "secret-1",
				Endpoint: oauth2.Endpoint{
					AuthURL:  provider.URL + "/authorize",
					TokenURL: provider.URL,
				},
				RedirectURL: "https://obot.example/oauth/mcp/callback",
			}
			require.NoError(t, manager.store(t.Context(), "user-1", mcpID, mcpURL, "request-1", entryName, "state-1", "verifier-1", config))

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, _, err := manager.createToken(ctx, "state-1", "code-1", "", "")
			if tc.wantErr {
				require.ErrorIs(t, err, gateway.ErrMCPOAuthCatalogCredentialChanged)
				_, err = client.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL)
				require.True(t, errors.Is(err, gorm.ErrRecordNotFound))
				_, err = client.GetMCPOAuthPendingState(t.Context(), "state-1")
				require.True(t, errors.Is(err, gorm.ErrRecordNotFound))
				return
			}
			require.NoError(t, err)
			stored, err := client.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL)
			require.NoError(t, err)
			require.Equal(t, tc.wantAccess, stored.AccessToken)
			require.Equal(t, entryName, stored.CatalogEntryName)
		})
	}
}

func TestMCPOAuthHandlerCapturesCatalogEntryOnlyForSelectedStaticApp(t *testing.T) {
	const (
		entryName = "catalog-entry-1"
		mcpID     = "mcp-instance-1"
		mcpURL    = "https://mcp.example/api"
	)
	client := newStateManagerTestClient(t, entryName, mcpID)
	handlerStorage := clientfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(
			&v1.MCPServerInstance{
				ObjectMeta: metav1.ObjectMeta{Namespace: system.DefaultNamespace, Name: mcpID},
				Spec:       v1.MCPServerInstanceSpec{MCPServerCatalogEntryName: entryName},
			},
			&v1.MCPServerCatalogEntry{
				ObjectMeta: metav1.ObjectMeta{Namespace: system.DefaultNamespace, Name: entryName},
				Spec: v1.MCPServerCatalogEntrySpec{Manifest: apitypes.MCPServerCatalogEntryManifest{
					RemoteConfig: &apitypes.RemoteCatalogConfig{FixedURL: mcpURL},
				}},
			},
		).
		Build()
	handler := &mcpOAuthHandler{
		client:        handlerStorage,
		gatewayClient: client,
		stateMgr:      newStateManager(client),
		userID:        "user-1",
		mcpID:         mcpID,
		mcpURL:        mcpURL,
		urlChan:       make(chan string, 1),
	}
	dynamicConfig := &oauth2.Config{ClientID: "dynamic-client", ClientSecret: "dynamic-secret"}
	_, _, err := handler.Lookup(t.Context(), "")
	require.Error(t, err)
	state, _, err := handler.NewState(t.Context(), dynamicConfig, "dynamic-verifier")
	require.NoError(t, err)
	pending, err := client.GetMCPOAuthPendingState(t.Context(), state)
	require.NoError(t, err)
	require.Empty(t, pending.CatalogEntryName)

	require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName), Name: "oauth",
		Secrets: map[string]string{"CLIENT_ID": "static-client", "CLIENT_SECRET": "static-secret"},
	}))
	clientID, clientSecret, err := handler.Lookup(t.Context(), "")
	require.NoError(t, err)
	require.Equal(t, "static-client", clientID)
	require.Equal(t, "static-secret", clientSecret)
	staticConfig := &oauth2.Config{ClientID: clientID, ClientSecret: clientSecret}
	state, _, err = handler.NewState(t.Context(), staticConfig, "static-verifier")
	require.NoError(t, err)
	pending, err = client.GetMCPOAuthPendingState(t.Context(), state)
	require.NoError(t, err)
	require.Equal(t, entryName, pending.CatalogEntryName)
}

func newStateManagerTestClient(t *testing.T, entryName, mcpID string) *gateway.Client {
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
