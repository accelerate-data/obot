package oauth

// Fork-only guarantee (VD-4026, restored by VD-6903): two users who complete the OAuth callback for the same shared container deployment each keep their own grant, so one user's sign-in never overwrites or serves the other's token. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	"github.com/obot-platform/obot/pkg/mcp"
	sservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestContainerOAuthCallbacksStoreSeparateGrantsForTwoUsers(t *testing.T) {
	const (
		mcpID    = "shared-fabric-deployment"
		resource = gatewayclient.ContainerOAuthResourcePrefix + "shared-fabric"
	)

	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	gateway := gatewayclient.New(t.Context(), db, nil, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, gateway.Close()) })

	// The provider echoes the code into the token so each stored grant can be
	// traced back to the user whose callback produced it.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		code := r.Form.Get("code")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"%s-access","refresh_token":"%s-refresh","token_type":"Bearer"}`, code, code)
	}))
	t.Cleanup(provider.Close)

	manager := newStateManager(gateway, provider.Client())
	config := &oauth2.Config{
		ClientID:     "deployment-client",
		ClientSecret: "deployment-secret",
		Endpoint:     oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL},
		RedirectURL:  "https://obot.example/oauth/mcp/callback",
		Scopes:       []string{"api://deployment-client/Mcp.Tools.ReadWrite", "offline_access"},
	}

	users := []struct {
		id    string
		state string
		code  string
	}{
		{
			id:    "user-a",
			state: "state-a",
			code:  "user-a-code",
		},
		{
			id:    "user-b",
			state: "state-b",
			code:  "user-b-code",
		},
	}
	for _, user := range users {
		require.NoError(t, manager.store(t.Context(), user.id, mcpID, resource, "", "", user.state, "verifier-"+user.id, "", config))
		_, gotMCPID, err := manager.createToken(t.Context(), user.state, user.code, "", "")
		require.NoError(t, err)
		require.Equal(t, mcpID, gotMCPID)
	}

	store := mcp.NewGlobalTokenStore(gateway)
	for _, user := range users {
		_, token, err := store.ForUserAndMCP(user.id, mcpID, resource).GetTokenConfig(t.Context())
		require.NoError(t, err)
		require.NotNil(t, token, "user %s has no stored container OAuth grant", user.id)
		require.Equal(t, user.code+"-access", token.AccessToken)
		require.Equal(t, user.code+"-refresh", token.RefreshToken)
	}
}
