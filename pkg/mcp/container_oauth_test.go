package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type perUserContainerTokenStore map[string]*oauth2.Token

func (p perUserContainerTokenStore) ForUserAndMCP(userID, _, _ string) TokenStorage {
	return fixedContainerTokenStore{token: p[userID]}
}

type fixedContainerTokenStore struct{ token *oauth2.Token }

func (f fixedContainerTokenStore) GetTokenConfig(context.Context) (*oauth2.Config, *oauth2.Token, error) {
	return &oauth2.Config{
		ClientID: "client", ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{TokenURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"},
		Scopes:   []string{"api://client/Mcp.Tools.ReadWrite", "offline_access"},
	}, f.token, nil
}
func (fixedContainerTokenStore) SetTokenConfig(context.Context, *oauth2.Config, *oauth2.Token) error {
	return nil
}
func (fixedContainerTokenStore) DeleteTokenConfig(context.Context) error { return nil }

func TestResolveMicrosoftEntraContainerOAuth(t *testing.T) {
	config, resource, err := ResolveContainerOAuth(types.ContainerizedRuntimeConfig{OAuth: &types.ContainerOAuthConfig{
		Provider: types.ContainerOAuthProviderMicrosoftEntra, AuthorityEnv: "INSTANCE", TenantIDEnv: "TENANT",
		ClientIDEnv: "CLIENT", ClientSecretEnv: "SECRET", Scopes: []string{"api://${CLIENT}/Mcp.Tools.ReadWrite"},
	}}, ServerConfig{MCPServerName: "mcp-server-1", Env: []string{
		"INSTANCE=https://login.microsoftonline.com/", "TENANT=e0479cc8-fdd8-464f-82e9-97e93f9917db",
		"CLIENT=e99a4f68-dab9-4c66-bdfa-82aaabd0957c", "SECRET=provider-secret",
	}})
	require.NoError(t, err)
	require.Equal(t, "https://login.microsoftonline.com/e0479cc8-fdd8-464f-82e9-97e93f9917db/oauth2/v2.0/authorize", config.Endpoint.AuthURL)
	require.Equal(t, "https://login.microsoftonline.com/e0479cc8-fdd8-464f-82e9-97e93f9917db/oauth2/v2.0/token", config.Endpoint.TokenURL)
	require.Equal(t, []string{"api://e99a4f68-dab9-4c66-bdfa-82aaabd0957c/Mcp.Tools.ReadWrite", "offline_access"}, config.Scopes)
	require.Equal(t, "urn:obot:container-oauth:mcp-server-1", resource)
}

func TestResolveMicrosoftEntraContainerOAuthRejectsUntrustedAuthority(t *testing.T) {
	descriptor := types.ContainerizedRuntimeConfig{OAuth: &types.ContainerOAuthConfig{
		Provider: types.ContainerOAuthProviderMicrosoftEntra, AuthorityEnv: "INSTANCE", TenantIDEnv: "TENANT",
		ClientIDEnv: "CLIENT", ClientSecretEnv: "SECRET", Scopes: []string{"scope"},
	}}
	for _, authority := range []string{
		"https://attacker.example/",
		"https://login.microsoftonline.com:8443/",
		"https://login.microsoftonline.com/attacker",
	} {
		_, _, err := ResolveContainerOAuth(descriptor, ServerConfig{Env: []string{"INSTANCE=" + authority, "TENANT=tenant", "CLIENT=client", "SECRET=secret"}})
		require.ErrorContains(t, err, "untrusted Microsoft Entra authority")
	}
}

func TestResolveMicrosoftEntraContainerOAuthRejectsUnsafeScopeAndTenant(t *testing.T) {
	descriptor := types.ContainerizedRuntimeConfig{OAuth: &types.ContainerOAuthConfig{
		Provider: types.ContainerOAuthProviderMicrosoftEntra, AuthorityEnv: "INSTANCE", TenantIDEnv: "TENANT",
		ClientIDEnv: "CLIENT", ClientSecretEnv: "SECRET", Scopes: []string{"api://${SECRET}/Mcp.Tools.ReadWrite"},
	}}
	server := ServerConfig{Env: []string{"INSTANCE=https://login.microsoftonline.com/", "TENANT=tenant", "CLIENT=client", "SECRET=secret"}}
	_, _, err := ResolveContainerOAuth(descriptor, server)
	require.ErrorContains(t, err, "may only reference client ID")

	descriptor.OAuth.Scopes = []string{"scope"}
	server.Env[1] = "TENANT=.."
	_, _, err = ResolveContainerOAuth(descriptor, server)
	require.ErrorContains(t, err, "invalid Microsoft Entra tenant ID")
}

func TestContainerOAuthConfigMatchesScopeAndCredentialRotation(t *testing.T) {
	stored := &oauth2.Config{ClientID: "client", ClientSecret: "old", Endpoint: oauth2.Endpoint{TokenURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"}, Scopes: []string{"scope", "offline_access"}}
	current := &oauth2.Config{ClientID: "client", ClientSecret: "new", Endpoint: stored.Endpoint, Scopes: append([]string(nil), stored.Scopes...)}
	require.True(t, ContainerOAuthConfigMatches(stored, current), "client-secret rotation must preserve a user's grant")
	current.Scopes = []string{"different", "offline_access"}
	require.False(t, ContainerOAuthConfigMatches(stored, current), "scope changes must invalidate the stored grant")
}

func TestContainerOAuthAuthorizationIsInjectedPerUser(t *testing.T) {
	descriptor := types.ContainerizedRuntimeConfig{OAuth: &types.ContainerOAuthConfig{
		Provider: types.ContainerOAuthProviderMicrosoftEntra, AuthorityEnv: "INSTANCE", TenantIDEnv: "TENANT",
		ClientIDEnv: "CLIENT", ClientSecretEnv: "SECRET", Scopes: []string{"api://${CLIENT}/Mcp.Tools.ReadWrite"},
	}}
	sm := &SessionManager{globalTokenStore: perUserContainerTokenStore{
		"user-a": {AccessToken: "access-a", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)},
		"user-b": {AccessToken: "access-b", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)},
	}}
	server := func(user string) ServerConfig {
		return ServerConfig{UserID: user, MCPServerName: "shared-fabric", Env: []string{
			"INSTANCE=https://login.microsoftonline.com/", "TENANT=tenant", "CLIENT=client", "SECRET=secret",
		}}
	}
	userA, userB := server("user-a"), server("user-b")
	require.NoError(t, sm.addContainerOAuthAuthorization(t.Context(), descriptor, "instance-a", &userA))
	require.NoError(t, sm.addContainerOAuthAuthorization(t.Context(), descriptor, "instance-b", &userB))
	require.Equal(t, []string{"Authorization"}, userA.PassthroughHeaderNames)
	require.Equal(t, []string{"Bearer access-a"}, userA.PassthroughHeaderValues)
	require.Equal(t, []string{"Bearer access-b"}, userB.PassthroughHeaderValues)
}
