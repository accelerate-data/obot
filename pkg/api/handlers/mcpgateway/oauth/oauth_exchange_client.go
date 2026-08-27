package oauth

import (
	"net/http"

	"github.com/obot-platform/obot/pkg/mcp"
	"github.com/obot-platform/obot/pkg/safehttp"
)

// newOAuthExchangeClient builds the HTTP client every MCP OAuth token exchange
// and refresh runs on. It carries the operator's remote-network policy and
// rejects redirects, because an exchange replays the authorization code, PKCE
// verifier, and client secret, and a refresh replays the refresh token and
// client secret. Metadata discovery uses a separate client that still follows
// redirects.
//
// Both the gateway handler and the MCP OAuth handler factory build their
// exchange client here so neither can drift out of the policy.
func newOAuthExchangeClient(config mcp.RemoteMCPURLValidationConfig) *http.Client {
	return safehttp.NewClient(safehttp.ClientOptions{
		BlockLoopback:  !config.AllowLocalhostMCP,
		BlockPrivateIP: !config.AllowPrivateIPMCP,
		BlockLinkLocal: !config.AllowLinkLocalMCP,
		BlockRedirects: true,
	})
}
