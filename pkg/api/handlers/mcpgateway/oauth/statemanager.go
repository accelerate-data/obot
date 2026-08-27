package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/obot-platform/obot/pkg/gateway/client"
	"github.com/obot-platform/obot/pkg/mcp"
	"golang.org/x/oauth2"
)

type stateManager struct {
	gatewayClient         *client.Client
	staticOAuthHTTPClient *http.Client
}

func newStateManager(gatewayClient *client.Client, staticOAuthHTTPClient ...*http.Client) *stateManager {
	manager := &stateManager{gatewayClient: gatewayClient}
	if len(staticOAuthHTTPClient) > 0 {
		manager.staticOAuthHTTPClient = staticOAuthHTTPClient[0]
	}
	return manager
}

func (sm *stateManager) store(ctx context.Context, userID, mcpID, mcpURL, oauthAuthRequestID, catalogEntryName, state, verifier string, conf *oauth2.Config) error {
	return sm.gatewayClient.CreateMCPOAuthPendingState(ctx, userID, mcpID, mcpURL, oauthAuthRequestID, catalogEntryName, state, verifier, conf)
}

// createToken consumes a dynamic or container pending state exactly once.
//
// The claim is atomic and terminal: whichever concurrent callback wins owns the
// authorization attempt, and no later callback for the same state can exchange a
// code or overwrite the stored token. Every failure path inherits that contract:
//
//   - Provider denial: the provider issued no code, so the attempt is dead. The
//     row is removed and the user must start a new authorization.
//   - Token-exchange failure: the authorization code is single-use at the
//     provider and is already spent, so replaying the same callback cannot
//     succeed. The row is removed and the user must start a new authorization.
//   - Cancellation: the exchange may have completed upstream. The best-effort
//     removal runs on the cancelled context and may not land, but the standing
//     claim still bars a second exchange.
//   - Persistence failure: the token was exchanged but not durably stored.
//     CommitMCPOAuthPendingStateToken removes the row on the failures it can
//     attribute, and the claim bars reuse regardless, so no competing callback
//     can write over the outcome.
func (sm *stateManager) createToken(ctx context.Context, state, code, errorStr, errorDescription string) (string, string, error) {
	ps, err := sm.gatewayClient.ClaimMCPOAuthPendingState(ctx, state)
	if err != nil {
		return "", "", fmt.Errorf("failed to claim oauth state: %w", err)
	}

	if errorStr != "" {
		// Clean up the pending state before returning the error
		_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)
		return "", "", fmt.Errorf("error returned from oauth server: %s, %s", errorStr, errorDescription)
	}

	conf := &oauth2.Config{
		ClientID:     ps.ClientID,
		ClientSecret: ps.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   ps.AuthURL,
			TokenURL:  ps.TokenURL,
			AuthStyle: ps.AuthStyle,
		},
		RedirectURL: ps.RedirectURL,
	}
	if ps.Scopes != "" {
		conf.Scopes = strings.Split(ps.Scopes, " ")
	}

	exchangeContext := ctx
	if (ps.CatalogEntryName != "" || mcp.IsContainerOAuthResource(ps.URL)) && sm.staticOAuthHTTPClient != nil {
		exchangeContext = context.WithValue(ctx, oauth2.HTTPClient, sm.staticOAuthHTTPClient)
	}
	token, err := conf.Exchange(exchangeContext, code, oauth2.SetAuthURLParam("code_verifier", ps.Verifier))
	if err != nil {
		_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)
		return "", "", fmt.Errorf("failed to exchange code: %w", err)
	}

	if err := sm.gatewayClient.CommitMCPOAuthPendingStateToken(ctx, ps, ps.OAuthAuthRequestID, conf, token); err != nil {
		return "", "", err
	}

	return ps.OAuthAuthRequestID, ps.MCPID, nil
}
