package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/obot-platform/obot/pkg/gateway/client"
	"golang.org/x/oauth2"
)

type stateManager struct {
	gatewayClient *client.Client
	// exchangeHTTPClient carries the operator's remote-network policy. Every OAuth
	// token exchange runs through it, not only the static-catalog and container ones.
	exchangeHTTPClient *http.Client
}

func newStateManager(gatewayClient *client.Client, exchangeHTTPClient ...*http.Client) *stateManager {
	manager := &stateManager{gatewayClient: gatewayClient}
	if len(exchangeHTTPClient) > 0 {
		manager.exchangeHTTPClient = exchangeHTTPClient[0]
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
		// error_description is provider-controlled free text that can carry request
		// identifiers and internal details. Only the error code is safe to repeat.
		return "", "", fmt.Errorf("error returned from oauth server: %s", safeOAuthErrorCode(errorStr))
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
	if sm.exchangeHTTPClient != nil {
		exchangeContext = context.WithValue(ctx, oauth2.HTTPClient, sm.exchangeHTTPClient)
	}
	token, err := conf.Exchange(exchangeContext, code, oauth2.SetAuthURLParam("code_verifier", ps.Verifier))
	if err != nil {
		_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)
		return "", "", fmt.Errorf("failed to exchange code: %w", sanitizeTokenExchangeError(err))
	}

	if err := sm.gatewayClient.CommitMCPOAuthPendingStateToken(ctx, ps, ps.OAuthAuthRequestID, conf, token); err != nil {
		return "", "", err
	}

	return ps.OAuthAuthRequestID, ps.MCPID, nil
}

// safeOAuthErrorCode keeps only the characters RFC 6749 allows in an error code,
// so a provider cannot smuggle markup, newlines, or free-form detail through it.
func safeOAuthErrorCode(code string) string {
	if len(code) > 64 {
		code = code[:64]
	}
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			return r
		default:
			return -1
		}
	}, code)
	if cleaned == "" {
		return "unspecified_error"
	}
	return cleaned
}

// sanitizeTokenExchangeError reduces a token-endpoint failure to a stable code or
// status. The oauth2 package embeds the raw upstream response body in
// RetrieveError, and that body carries provider request identifiers, workspace
// identifiers, and echoed request parameters that must never reach a log or an
// API response.
func sanitizeTokenExchangeError(err error) error {
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		if retrieveErr.ErrorCode != "" {
			return fmt.Errorf("token endpoint rejected the exchange: %s", safeOAuthErrorCode(retrieveErr.ErrorCode))
		}
		if retrieveErr.Response != nil {
			return fmt.Errorf("token endpoint rejected the exchange with status %d", retrieveErr.Response.StatusCode)
		}
		return errors.New("token endpoint rejected the exchange")
	}

	// A transport failure names the full request URL, which repeats the token
	// endpoint back to the caller. Keep only the underlying cause.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("could not reach the token endpoint: %w", urlErr.Err)
	}

	return errors.New("token exchange failed")
}
