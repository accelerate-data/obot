package mcp

import (
	"context"
	"errors"
	"strings"
	"sync"

	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

type GlobalTokenStore interface {
	ForUserAndMCP(userID, mcpID, mcpURL string) TokenStorage
}

type TokenStorage interface {
	GetTokenConfig(context.Context) (*oauth2.Config, *oauth2.Token, error)
	SetTokenConfig(context.Context, *oauth2.Config, *oauth2.Token) error
	DeleteTokenConfig(context.Context) error
}

func NewGlobalTokenStore(gatewayClient *gateway.Client) GlobalTokenStore {
	return &globalTokenStore{
		gatewayClient: gatewayClient,
	}
}

type globalTokenStore struct {
	gatewayClient *gateway.Client
}

func (g *globalTokenStore) ForUserAndMCP(userID, mcpID, mcpURL string) TokenStorage {
	return &tokenStore{
		gatewayClient: g.gatewayClient,
		mcpID:         mcpID,
		userID:        userID,
		mcpURL:        mcpURL,
	}
}

type tokenStore struct {
	gatewayClient         *gateway.Client
	userID, mcpID, mcpURL string
	mu                    sync.Mutex
	catalogEntry          catalogCredentialFence
	catalogEntryCaptured  bool
}

type catalogCredentialFence struct {
	entryName  string
	generation string
}

func (t *tokenStore) GetTokenConfig(ctx context.Context) (*oauth2.Config, *oauth2.Token, error) {
	mcpToken, err := t.gatewayClient.GetMCPOAuthToken(ctx, t.userID, t.mcpID, t.mcpURL)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	conf := &oauth2.Config{
		ClientID:     mcpToken.ClientID,
		ClientSecret: mcpToken.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   mcpToken.AuthURL,
			TokenURL:  mcpToken.TokenURL,
			AuthStyle: mcpToken.AuthStyle,
		},
		RedirectURL: mcpToken.RedirectURL,
	}
	if mcpToken.Scopes != "" {
		conf.Scopes = strings.Split(mcpToken.Scopes, " ")
	}

	catalogEntryName := mcpToken.CatalogEntryName
	// Container OAuth grants are fenced by their stable deployment resource,
	// not a remote static-OAuth catalog credential.
	if !IsContainerOAuthResource(t.mcpURL) {
		if catalogEntryName == "" {
			catalogEntryName, err = t.gatewayClient.CatalogEntryForCurrentOAuthCredential(ctx, t.userID, t.mcpID, t.mcpURL, conf)
			if err != nil {
				return nil, nil, err
			}
		} else if err := t.gatewayClient.ValidateCatalogOAuthToken(ctx, t.mcpID, t.mcpURL, catalogEntryName, mcpToken.CatalogCredentialGeneration, conf); err != nil {
			return nil, nil, err
		}
	}
	t.mu.Lock()
	t.catalogEntry = catalogCredentialFence{entryName: catalogEntryName, generation: mcpToken.CatalogCredentialGeneration}
	t.catalogEntryCaptured = true
	t.mu.Unlock()

	return conf, &oauth2.Token{
		AccessToken:  mcpToken.AccessToken,
		RefreshToken: mcpToken.RefreshToken,
		TokenType:    mcpToken.TokenType,
		ExpiresIn:    mcpToken.ExpiresIn,
		Expiry:       mcpToken.Expiry,
	}, nil
}

func (t *tokenStore) SetTokenConfig(ctx context.Context, config *oauth2.Config, token *oauth2.Token) error {
	t.mu.Lock()
	fence := t.catalogEntry
	captured := t.catalogEntryCaptured
	t.mu.Unlock()
	if !captured {
		if IsContainerOAuthResource(t.mcpURL) {
			return t.gatewayClient.ReplaceMCPOAuthToken(ctx, t.userID, t.mcpID, t.mcpURL, "", config, token)
		}
		var err error
		fence.entryName, err = t.gatewayClient.CatalogEntryForCurrentOAuthCredential(ctx, t.userID, t.mcpID, t.mcpURL, config)
		if err != nil {
			return err
		}
	}
	return t.gatewayClient.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(ctx, t.userID, t.mcpID, t.mcpURL, "", fence.entryName, fence.generation, config, token)
}

func (t *tokenStore) DeleteTokenConfig(ctx context.Context) error {
	return t.gatewayClient.DeleteMCPOAuthTokenForURL(ctx, t.userID, t.mcpID, t.mcpURL)
}
