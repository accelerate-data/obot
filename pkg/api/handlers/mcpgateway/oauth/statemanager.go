package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/obot-platform/obot/pkg/gateway/client"
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

func (sm *stateManager) store(ctx context.Context, userID, mcpID, mcpURL, oauthAuthRequestID, catalogEntryName, state, verifier string, conf *oauth2.Config) error {
	return sm.gatewayClient.CreateMCPOAuthPendingState(ctx, userID, mcpID, mcpURL, oauthAuthRequestID, catalogEntryName, state, verifier, conf)
}

func (sm *stateManager) createToken(ctx context.Context, state, code, errorStr, errorDescription string) (string, string, error) {
	ps, err := sm.gatewayClient.GetMCPOAuthPendingState(ctx, state)
	if err != nil {
		return "", "", fmt.Errorf("failed to get oauth state: %w", err)
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

	token, err := conf.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", ps.Verifier))
	if err != nil {
		_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)
		return "", "", fmt.Errorf("failed to exchange code: %w", err)
	}

	catalogEntryName := ps.CatalogEntryName
	if catalogEntryName == "" {
		catalogEntryName, err = sm.gatewayClient.CatalogEntryForStaticOAuthMCP(ctx, ps.MCPID, ps.URL)
		if err != nil {
			if errors.Is(err, client.ErrMCPOAuthCatalogCredentialChanged) {
				_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)
			}
			return "", "", err
		}
	}

	// Save the completed token
	if err := sm.gatewayClient.ReplaceMCPOAuthTokenWithCatalogCredentialFence(ctx, ps.UserID, ps.MCPID, ps.URL, ps.OAuthAuthRequestID, catalogEntryName, conf, token); err != nil {
		if errors.Is(err, client.ErrMCPOAuthCatalogCredentialChanged) {
			_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)
		}
		return "", "", err
	}

	// Delete the pending state
	_ = sm.gatewayClient.DeleteMCPOAuthPendingState(ctx, ps.HashedState)

	return ps.OAuthAuthRequestID, ps.MCPID, nil
}
