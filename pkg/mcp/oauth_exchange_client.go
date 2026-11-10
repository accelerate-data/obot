package mcp

import (
	"context"
	"net/http"

	"github.com/obot-platform/obot/pkg/safehttp"
	"golang.org/x/oauth2"
)

// GlobalTokenStoreOption configures NewGlobalTokenStore.
type GlobalTokenStoreOption func(*globalTokenStore)

// RemoteMCPURLValidationConfigFromOptions is the operator's remote-network
// policy. The session manager and the OAuth token store both read it here so
// MCP traffic and OAuth token traffic cannot drift onto different policies.
func RemoteMCPURLValidationConfigFromOptions(opts Options) RemoteMCPURLValidationConfig {
	return RemoteMCPURLValidationConfig{
		AllowLocalhostMCP: !opts.DisallowLocalhostMCP,
		AllowPrivateIPMCP: !opts.DisallowPrivateIPMCP,
		AllowLinkLocalMCP: !opts.DisallowLinkLocalMCP,
	}
}

// NewOAuthExchangeClient builds the HTTP client every MCP OAuth token exchange
// and refresh runs on. It carries the operator's remote-network policy and
// rejects redirects, because an exchange replays the authorization code, PKCE
// verifier, and client secret, and a refresh replays the refresh token and
// client secret. Metadata discovery uses a separate client that still follows
// redirects.
func NewOAuthExchangeClient(config RemoteMCPURLValidationConfig) *http.Client {
	return safehttp.NoRedirects(safehttp.NewClient(safehttp.Options{
		BlockLoopback:  !config.AllowLocalhostMCP,
		BlockPrivateIP: !config.AllowPrivateIPMCP,
		BlockLinkLocal: !config.AllowLinkLocalMCP,
	}))
}

// WithOAuthHTTPClient binds an HTTP client to the context the oauth2 package
// reads. Without it, oauth2 falls back to http.DefaultClient and bypasses the
// operator's remote-network policy entirely.
func WithOAuthHTTPClient(ctx context.Context, httpClient *http.Client) context.Context {
	if httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, httpClient)
}

// WithTokenRefreshHTTPClient sets the client stored-token refreshes run on. It
// must come from NewOAuthExchangeClient: a refresh replays the refresh token and
// client secret to whatever origin the token endpoint names.
func WithTokenRefreshHTTPClient(httpClient *http.Client) GlobalTokenStoreOption {
	return func(g *globalTokenStore) {
		g.refreshHTTPClient = httpClient
	}
}
