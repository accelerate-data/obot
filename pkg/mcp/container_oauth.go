package mcp

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/obot-platform/obot/apiclient/types"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	"golang.org/x/oauth2"
)

var (
	containerOAuthTemplate = regexp.MustCompile(`\$\{([^}]+)\}`)
	containerOAuthTenant   = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
	trustedEntraHosts      = []string{
		"login.microsoftonline.com",
		"login.microsoftonline.us",
		"login.chinacloudapi.cn",
		"login.microsoftonline.de",
	}
)

func IsContainerOAuthResource(resource string) bool {
	return gateway.IsContainerOAuthResource(resource)
}

func ResolveContainerOAuth(container types.ContainerizedRuntimeConfig, server ServerConfig) (*oauth2.Config, string, error) {
	descriptor := container.OAuth
	if descriptor == nil {
		return nil, "", nil
	}
	if descriptor.Provider != types.ContainerOAuthProviderMicrosoftEntra {
		return nil, "", fmt.Errorf("unsupported container OAuth provider %q", descriptor.Provider)
	}

	env := make(map[string]string, len(server.Env))
	for _, value := range server.Env {
		key, value, ok := strings.Cut(value, "=")
		if ok {
			env[key] = value
		}
	}
	for name, key := range map[string]string{
		"authority": descriptor.AuthorityEnv, "tenant ID": descriptor.TenantIDEnv,
		"client ID": descriptor.ClientIDEnv, "client secret": descriptor.ClientSecretEnv,
	} {
		if strings.TrimSpace(env[key]) == "" {
			return nil, "", fmt.Errorf("container OAuth %s environment value %q is missing", name, key)
		}
	}

	authority, err := url.Parse(env[descriptor.AuthorityEnv])
	if err != nil || authority.Scheme != "https" || authority.User != nil || authority.Port() != "" || (authority.Path != "" && authority.Path != "/") || authority.RawQuery != "" || authority.Fragment != "" || !slices.Contains(trustedEntraHosts, strings.ToLower(authority.Hostname())) {
		return nil, "", fmt.Errorf("untrusted Microsoft Entra authority")
	}
	tenantID := env[descriptor.TenantIDEnv]
	if tenantID == "." || tenantID == ".." || !containerOAuthTenant.MatchString(tenantID) {
		return nil, "", fmt.Errorf("invalid Microsoft Entra tenant ID")
	}
	base := strings.TrimRight(authority.String(), "/") + "/" + tenantID + "/oauth2/v2.0"

	scopes := make([]string, 0, len(descriptor.Scopes)+1)
	for _, scope := range descriptor.Scopes {
		var templateErr error
		expanded := containerOAuthTemplate.ReplaceAllStringFunc(scope, func(match string) string {
			key := containerOAuthTemplate.FindStringSubmatch(match)[1]
			if key != descriptor.ClientIDEnv || strings.TrimSpace(env[key]) == "" {
				templateErr = fmt.Errorf("container OAuth scope %q may only reference client ID environment value %q", scope, descriptor.ClientIDEnv)
				return match
			}
			return env[key]
		})
		if templateErr != nil {
			return nil, "", templateErr
		}
		if strings.TrimSpace(expanded) == "" || strings.Contains(expanded, "${") {
			return nil, "", fmt.Errorf("invalid container OAuth scope %q", scope)
		}
		scopes = append(scopes, expanded)
	}
	if !slices.Contains(scopes, "offline_access") {
		scopes = append(scopes, "offline_access")
	}

	return &oauth2.Config{
		ClientID: env[descriptor.ClientIDEnv], ClientSecret: env[descriptor.ClientSecretEnv],
		Endpoint: oauth2.Endpoint{AuthURL: base + "/authorize", TokenURL: base + "/token"},
		Scopes:   scopes,
	}, gateway.ContainerOAuthResourcePrefix + server.MCPServerName, nil
}

func ContainerOAuthConfigMatches(stored, current *oauth2.Config) bool {
	return stored != nil && current != nil && stored.ClientID == current.ClientID && stored.Endpoint.TokenURL == current.Endpoint.TokenURL && slices.Equal(stored.Scopes, current.Scopes)
}

func (sm *SessionManager) addContainerOAuthAuthorization(ctx context.Context, container types.ContainerizedRuntimeConfig, oauthID string, server *ServerConfig) error {
	conf, resource, err := ResolveContainerOAuth(container, *server)
	if err != nil {
		return err
	}
	release := func() {}
	if sm.gatewayClient != nil {
		release, err = sm.gatewayClient.AcquireCredentialLock(ctx, fmt.Sprintf("container-oauth-refresh:%s:%s", server.UserID, oauthID))
		if err != nil {
			return fmt.Errorf("failed to coordinate container OAuth refresh: %w", err)
		}
	}
	defer release()

	store := sm.globalTokenStore.ForUserAndMCP(server.UserID, oauthID)
	storedConf, token, err := store.GetTokenConfig(ctx, resource)
	if err != nil {
		return fmt.Errorf("failed to load container OAuth grant: %w", err)
	}
	if storedConf == nil || token == nil {
		return types.NewErrBadRequest("MCP server requires OAuth authorization")
	}
	if !ContainerOAuthConfigMatches(storedConf, conf) {
		if err := store.DeleteTokenConfig(ctx, resource); err != nil {
			return fmt.Errorf("failed to discard stale container OAuth grant: %w", err)
		}
		return types.NewErrBadRequest("MCP server requires OAuth authorization")
	}

	refreshed, err := conf.TokenSource(ctx, token).Token()
	if err != nil {
		if deleteErr := store.DeleteTokenConfig(ctx, resource); deleteErr != nil {
			return fmt.Errorf("failed to discard invalid container OAuth grant after refresh failure: %w", deleteErr)
		}
		return types.NewErrBadRequest("MCP server OAuth grant must be reauthorized")
	}
	if refreshed.AccessToken != token.AccessToken || refreshed.RefreshToken != token.RefreshToken || !refreshed.Expiry.Equal(token.Expiry) {
		if err := store.SetTokenConfig(ctx, resource, conf, refreshed); err != nil {
			return fmt.Errorf("failed to persist refreshed container OAuth grant: %w", err)
		}
	}
	tokenType := refreshed.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	server.PassthroughHeaderNames = append(server.PassthroughHeaderNames, "Authorization")
	server.PassthroughHeaderValues = append(server.PassthroughHeaderValues, tokenType+" "+refreshed.AccessToken)
	return nil
}
