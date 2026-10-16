package oauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/obot-platform/obot/pkg/gateway/client"
	"github.com/obot-platform/obot/pkg/mcp"
	"golang.org/x/oauth2"
)

type stateManager struct {
	gatewayClient *client.Client
}

func newStateManager(gatewayClient *client.Client) *stateManager {
	return &stateManager{
		gatewayClient: gatewayClient,
	}
}

func (sm *stateManager) store(ctx context.Context, userID, mcpID, mcpURL, oauthAuthRequestID, catalogEntryName, state, verifier, resourceURL string, conf *oauth2.Config) error {
	return sm.gatewayClient.CreateMCPOAuthPendingState(ctx, userID, mcpID, mcpURL, oauthAuthRequestID, catalogEntryName, state, verifier, resourceURL, conf)
}

// createToken claims the callback state before anything else, so a replayed or
// concurrent callback is rejected without reaching the provider. The claim is
// terminal: a denial, a failed exchange, a cancellation, or a persistence failure
// all leave the state unusable, and the user starts a new sign-in.
func (sm *stateManager) createToken(ctx context.Context, state, code, errorStr, errorDescription string) (string, string, error) {
	ps, err := sm.gatewayClient.ClaimMCPOAuthPendingState(ctx, state)
	if err != nil {
		return "", "", fmt.Errorf("failed to claim oauth state: %w", err)
	}

	if errorStr != "" {
		// Clean up the pending state before returning the error
		_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)
		// A provider that echoes a secret as its error code must not carry it
		// into the URL; such a code says nothing a fixed one does not.
		errCode := errorStr
		if redactKnownValues(errorStr, ps.ClientSecret, ps.Verifier, state, code) != errorStr {
			errCode = "server_error"
		}
		return ps.OAuthAuthRequestID, ps.MCPID, &oauthCallbackError{
			Code: errCode,
			// Exact values first: the pattern passes cannot recognize an unlabeled
			// secret, and later normalization would change its bytes.
			Description: redactKnownValues(errorDescription, ps.ClientSecret, ps.Verifier, state, code),
			Err:         fmt.Errorf("error returned from oauth server: %s, %s", errorStr, errorDescription),
		}
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

	token, err := mcp.ExchangeOAuthToken(ctx, conf, code, ps.Verifier, ps.ResourceURL)
	if err != nil {
		_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)
		// The exchange error can quote the provider's response body, which may
		// echo the client secret or the code, so it never leaves this process.
		return ps.OAuthAuthRequestID, ps.MCPID, &oauthCallbackError{Code: "token_exchange_failed", Err: fmt.Errorf("failed to exchange code: %w", err)}
	}

	if err := sm.gatewayClient.CommitMCPOAuthPendingStateToken(ctx, ps, ps.OAuthAuthRequestID, conf, token); err != nil {
		return ps.OAuthAuthRequestID, ps.MCPID, &oauthCallbackError{Code: "server_error", Err: err}
	}

	return ps.OAuthAuthRequestID, ps.MCPID, nil
}
