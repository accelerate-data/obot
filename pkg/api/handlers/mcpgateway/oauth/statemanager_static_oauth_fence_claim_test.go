package oauth

// Fork-only guarantee (fork #37, restored by VD-6903): a downstream OAuth callback
// for a catalog entry's static OAuth application is fenced to the credential
// generation it started with, legacy pending rows cannot bypass that fence, and
// dynamic or CIMD callbacks are stored without a catalog tag. Kept in its own file
// so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
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
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	fenceClaimEntryName = "catalog-entry-1"
	fenceClaimMCPID     = "mcp-instance-1"
	fenceClaimMCPURL    = "https://mcp.example/api"
)

// newFenceClaimGateway backs the gateway with storage holding one catalog-backed
// instance, because the fence resolves an MCP ID to its entry and the entry's
// static OAuth requirement through storage.
func newFenceClaimGateway(t *testing.T, staticOAuthRequired bool) *gateway.Client {
	t.Helper()
	return newFenceClaimGatewayWithObjects(t,
		&v1.MCPServerInstance{
			Namespace: system.DefaultNamespace, Name: fenceClaimMCPID,
			Spec: v1.MCPServerInstanceSpec{MCPServerCatalogEntryName: fenceClaimEntryName},
		},
		&v1.MCPServerCatalogEntry{
			Namespace: system.DefaultNamespace, Name: fenceClaimEntryName,
			Spec: v1.MCPServerCatalogEntrySpec{Manifest: apitypes.MCPServerCatalogEntryManifest{
				RemoteConfig: &apitypes.RemoteCatalogConfig{FixedURL: fenceClaimMCPURL, StaticOAuthRequired: staticOAuthRequired},
			}},
		},
	)
}

func newFenceClaimGatewayWithObjects(t *testing.T, objects ...kclient.Object) *gateway.Client {
	t.Helper()
	storage := clientfake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(objects...).Build()
	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	client := gateway.New(t.Context(), db, storage, staticOAuthTestEncryptionConfig(), nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	return client
}

func upsertFenceClaimCredential(t *testing.T, client *gateway.Client, clientID, clientSecret, generation string) {
	t.Helper()
	require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(fenceClaimEntryName), Name: system.StaticOAuthCredentialName,
		Secrets: map[string]string{
			"CLIENT_ID": clientID, "CLIENT_SECRET": clientSecret,
			"MCP_URL": fenceClaimMCPURL, "GENERATION": generation,
		},
	}))
}

// newFenceClaimProvider answers every token exchange with accessToken, running
// during first so a test can change the application while the exchange is in flight.
func newFenceClaimProvider(t *testing.T, accessToken string, during func()) *httptest.Server {
	t.Helper()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if during != nil {
			during()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"refresh","token_type":"Bearer"}`, accessToken)
	}))
	t.Cleanup(provider.Close)
	return provider
}

func fenceClaimConfig(provider *httptest.Server, clientID, clientSecret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret,
		Endpoint:    oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
	}
}

func requireFenceClaimCallbackRejected(t *testing.T, client *gateway.Client, err error, state string) {
	t.Helper()
	require.ErrorIs(t, err, gateway.ErrMCPOAuthCatalogCredentialChanged)
	_, err = client.GetMCPOAuthToken(t.Context(), "user-1", fenceClaimMCPID, fenceClaimMCPURL)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound, "a fenced callback must not store a grant")
	_, err = client.GetMCPOAuthPendingState(t.Context(), state)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound, "a fenced callback must not leave a replayable state")
}

func TestStateManagerFencesCallbackWriteAfterProviderExchange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		changeApp func(*testing.T, *gateway.Client)
	}{
		{name: "ordinary callback succeeds"},
		{
			name: "rotation during exchange rejects old app grant",
			changeApp: func(t *testing.T, client *gateway.Client) {
				t.Helper()
				upsertFenceClaimCredential(t, client, "client-1", "secret-2", "generation-2")
			},
		},
		{
			name: "clear during exchange rejects old app grant",
			changeApp: func(t *testing.T, client *gateway.Client) {
				t.Helper()
				deleted, err := client.DeleteCredential(t.Context(), system.MCPOAuthCredentialName(fenceClaimEntryName), system.StaticOAuthCredentialName)
				require.NoError(t, err)
				require.True(t, deleted)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newFenceClaimGateway(t, true)
			upsertFenceClaimCredential(t, client, "client-1", "secret-1", "generation-1")
			provider := newFenceClaimProvider(t, "provider-access", func() {
				if tc.changeApp == nil {
					return
				}
				// The API changes the application under the credential lock; taking it here
				// proves the callback does not hold it across the provider round trip.
				release, err := client.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(fenceClaimEntryName))
				require.NoError(t, err)
				defer release()
				tc.changeApp(t, client)
			})
			manager := newStateManager(client)
			require.NoError(t, manager.store(t.Context(), "user-1", fenceClaimMCPID, fenceClaimMCPURL, "request-1", fenceClaimEntryName, "state-1", "verifier-1", "", fenceClaimConfig(provider, "client-1", "secret-1")))

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, _, err := manager.createToken(ctx, "state-1", "code-1", "", "")
			if tc.changeApp != nil {
				requireFenceClaimCallbackRejected(t, client, err, "state-1")
				return
			}
			require.NoError(t, err)
			stored, err := client.GetMCPOAuthToken(t.Context(), "user-1", fenceClaimMCPID, fenceClaimMCPURL)
			require.NoError(t, err)
			require.Equal(t, "provider-access", stored.AccessToken)
			require.Equal(t, fenceClaimEntryName, stored.CatalogEntryName)
			require.Equal(t, "generation-1", stored.CatalogCredentialGeneration)
		})
	}
}

func TestStateManagerRejectsLegacyStaticPendingState(t *testing.T) {
	client := newFenceClaimGateway(t, true)
	upsertFenceClaimCredential(t, client, "client-1", "secret-1", "generation-1")
	provider := newFenceClaimProvider(t, "legacy-access", nil)
	manager := newStateManager(client)
	// An empty catalog entry models a pending row created before the fence columns
	// existed; it carries no generation, so a static-only entry must refuse it.
	require.NoError(t, manager.store(t.Context(), "user-1", fenceClaimMCPID, fenceClaimMCPURL, "request-1", "", "legacy-state", "verifier-1", "", fenceClaimConfig(provider, "client-1", "secret-1")))

	_, _, err := manager.createToken(t.Context(), "legacy-state", "code-1", "", "")
	requireFenceClaimCallbackRejected(t, client, err, "legacy-state")
}

func TestStateManagerPreservesLegacyDynamicPendingState(t *testing.T) {
	client := newFenceClaimGateway(t, false)
	provider := newFenceClaimProvider(t, "dynamic-access", nil)
	manager := newStateManager(client)
	require.NoError(t, manager.store(t.Context(), "user-1", fenceClaimMCPID, fenceClaimMCPURL, "request-1", "", "legacy-dynamic", "verifier-1", "", fenceClaimConfig(provider, "dynamic-client", "dynamic-secret")))

	_, _, err := manager.createToken(t.Context(), "legacy-dynamic", "code-1", "", "")
	require.NoError(t, err)
	stored, err := client.GetMCPOAuthToken(t.Context(), "user-1", fenceClaimMCPID, fenceClaimMCPURL)
	require.NoError(t, err)
	require.Equal(t, "dynamic-access", stored.AccessToken)
	require.Empty(t, stored.CatalogEntryName)
}

func TestStateManagerPersistsDirectDynamicAndCIMDCallbacks(t *testing.T) {
	const (
		mcpID  = "direct-mcp-server"
		mcpURL = "https://direct-mcp.example/api"
	)
	for _, tc := range []struct {
		name         string
		legacy       bool
		clientID     string
		clientSecret string
	}{
		{name: "new dynamic registration", clientID: "dynamic-client", clientSecret: "dynamic-secret"},
		{name: "new CIMD", clientID: "https://obot.example/oauth/client-metadata"},
		{name: "legacy dynamic registration", legacy: true, clientID: "dynamic-client", clientSecret: "dynamic-secret"},
		{name: "legacy CIMD", legacy: true, clientID: "https://obot.example/oauth/client-metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newFenceClaimGatewayWithObjects(t, &v1.MCPServer{Namespace: system.DefaultNamespace, Name: mcpID})
			provider := newFenceClaimProvider(t, "direct-access", nil)
			config := fenceClaimConfig(provider, tc.clientID, tc.clientSecret)
			manager := newStateManager(client)
			state := "legacy-direct-state"
			if tc.legacy {
				require.NoError(t, manager.store(t.Context(), "user-1", mcpID, mcpURL, "request-1", "", state, "verifier-1", "", config))
			} else {
				handler := &mcpOAuthHandler{
					gatewayClient: client, stateMgr: manager,
					userID: "user-1", mcpID: mcpID, mcpURL: mcpURL, urlChan: make(chan string, 1),
				}
				var err error
				state, _, err = handler.NewState(t.Context(), config, "", "verifier-1")
				require.NoError(t, err)
			}

			_, _, err := manager.createToken(t.Context(), state, "code-1", "", "")
			require.NoError(t, err)
			stored, err := client.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL)
			require.NoError(t, err)
			require.Equal(t, "direct-access", stored.AccessToken)
			require.Empty(t, stored.CatalogEntryName)
		})
	}
}

func TestMCPOAuthHandlerCapturesCatalogEntryOnlyForSelectedStaticApp(t *testing.T) {
	client := newFenceClaimGateway(t, true)
	// The factory hands every catalog-backed handler its entry name, so the fence
	// cannot rest on the handler; the pending state must still pin static grants
	// to the application's generation and refuse any other application.
	handler := &mcpOAuthHandler{
		gatewayClient: client, stateMgr: newStateManager(client),
		userID: "user-1", mcpID: fenceClaimMCPID, mcpURL: fenceClaimMCPURL,
		catalogEntryName: fenceClaimEntryName, urlChan: make(chan string, 1),
	}

	_, _, err := handler.Lookup(t.Context())
	require.Error(t, err, "no static application is configured yet")
	_, _, err = handler.NewState(t.Context(), &oauth2.Config{ClientID: "dynamic-client", ClientSecret: "dynamic-secret"}, "", "dynamic-verifier")
	require.ErrorIs(t, err, gateway.ErrMCPOAuthCatalogCredentialChanged, "a static-only entry must not start a grant from another application")

	upsertFenceClaimCredential(t, client, "static-client", "static-secret", "generation-1")
	clientID, clientSecret, err := handler.Lookup(t.Context())
	require.NoError(t, err)
	require.Equal(t, "static-client", clientID)
	require.Equal(t, "static-secret", clientSecret)
	state, _, err := handler.NewState(t.Context(), &oauth2.Config{ClientID: clientID, ClientSecret: clientSecret}, "", "static-verifier")
	require.NoError(t, err)
	pending, err := client.GetMCPOAuthPendingState(t.Context(), state)
	require.NoError(t, err)
	require.Equal(t, fenceClaimEntryName, pending.CatalogEntryName)
	require.Equal(t, "generation-1", pending.CatalogCredentialGeneration)
}
