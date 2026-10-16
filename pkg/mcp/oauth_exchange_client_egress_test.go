package mcp

// Fork-only guarantee (VD-4887, restored by VD-6903): MCP OAuth token exchange
// and refresh run on the operator's remote-network policy and never follow a
// redirect, because both replay credentials to the token endpoint. Kept in its
// own file so an upstream sync cannot drop these tests by merging over a shared
// one.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

var (
	allowAllRemoteMCP = RemoteMCPURLValidationConfig{
		AllowLocalhostMCP: true,
		AllowPrivateIPMCP: true,
		AllowLinkLocalMCP: true,
	}
)

type countingServer struct {
	*httptest.Server
	hits atomic.Int32
}

func newCountingServer(t *testing.T, handler http.HandlerFunc) *countingServer {
	t.Helper()
	s := &countingServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		s.hits.Add(1)
		handler(rw, req)
	}))
	t.Cleanup(s.Close)
	return s
}

func writeTokenResponse(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write([]byte(`{"access_token":"access-token","refresh_token":"refresh-token","token_type":"Bearer","expires_in":3600}`))
}

// newRedirectingTokenEndpoint returns a token endpoint that redirects every
// request to a second server, and that second server.
func newRedirectingTokenEndpoint(t *testing.T) (endpoint, target *countingServer) {
	t.Helper()
	target = newCountingServer(t, writeTokenResponse)
	endpoint = newCountingServer(t, func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, target.URL+"/token", http.StatusTemporaryRedirect)
	})
	return endpoint, target
}

func exchangeTestConfig(tokenURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://auth.example/authorize",
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func expiredTestToken() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  "old-access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(-time.Hour),
	}
}

func TestRemoteMCPURLValidationConfigFromOptions(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want RemoteMCPURLValidationConfig
	}{
		{
			name: "nothing disallowed",
			opts: Options{},
			want: allowAllRemoteMCP,
		},
		{
			name: "everything disallowed",
			opts: Options{
				DisallowLocalhostMCP: true,
				DisallowPrivateIPMCP: true,
				DisallowLinkLocalMCP: true,
			},
			want: RemoteMCPURLValidationConfig{},
		},
		{
			name: "only localhost disallowed",
			opts: Options{
				DisallowLocalhostMCP: true,
			},
			want: RemoteMCPURLValidationConfig{
				AllowPrivateIPMCP: true,
				AllowLinkLocalMCP: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, RemoteMCPURLValidationConfigFromOptions(tt.opts))
		})
	}
}

func TestExchangeOAuthTokenOnExchangeClientRefusesRedirect(t *testing.T) {
	endpoint, target := newRedirectingTokenEndpoint(t)
	ctx := WithOAuthHTTPClient(t.Context(), NewOAuthExchangeClient(allowAllRemoteMCP))

	_, err := ExchangeOAuthToken(ctx, exchangeTestConfig(endpoint.URL), "auth-code", "pkce-verifier", "")

	require.ErrorContains(t, err, "refusing to follow redirect")
	require.EqualValues(t, 1, endpoint.hits.Load())
	require.Zero(t, target.hits.Load(), "authorization code and client secret were replayed to the redirect target")
}

func TestExchangeOAuthTokenOnExchangeClientEnforcesNetworkPolicy(t *testing.T) {
	endpoint := newCountingServer(t, writeTokenResponse)
	ctx := WithOAuthHTTPClient(t.Context(), NewOAuthExchangeClient(RemoteMCPURLValidationConfig{}))

	_, err := ExchangeOAuthToken(ctx, exchangeTestConfig(endpoint.URL), "auth-code", "pkce-verifier", "")

	require.ErrorContains(t, err, "blocked")
	require.Zero(t, endpoint.hits.Load())
}

// Each class of the operator's policy is enforced on its own; a loopback-only
// assertion would pass with the private and link-local blocks switched off.
func TestExchangeOAuthTokenOnExchangeClientBlocksEachDisallowedAddressClass(t *testing.T) {
	for _, tc := range []struct {
		name, tokenURL, reason string
	}{
		{name: "private", tokenURL: "http://10.255.255.1:9/token", reason: "blocked private IP"},
		{name: "link-local", tokenURL: "http://169.254.169.254:9/token", reason: "blocked link-local IP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A short deadline keeps an unblocked dial from hanging the test;
			// the assertion is on the policy refusal, not on the dial failing.
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			ctx = WithOAuthHTTPClient(ctx, NewOAuthExchangeClient(RemoteMCPURLValidationConfig{}))

			_, err := ExchangeOAuthToken(ctx, exchangeTestConfig(tc.tokenURL), "auth-code", "pkce-verifier", "")

			require.ErrorContains(t, err, tc.reason)
		})
	}
}

func TestStorageBackedRefreshOnExchangeClientRefusesRedirect(t *testing.T) {
	endpoint, target := newRedirectingTokenEndpoint(t)
	storage := &recordingTokenStorage{}

	_, err := newStorageBackedTokenSourceWithClient(storage, exchangeTestConfig(endpoint.URL), expiredTestToken(), NewOAuthExchangeClient(allowAllRemoteMCP)).Token()

	require.ErrorContains(t, err, "refusing to follow redirect")
	require.Zero(t, target.hits.Load(), "refresh token and client secret were replayed to the redirect target")
	require.Zero(t, storage.setCalls)
}

func TestStorageBackedRefreshOnExchangeClientEnforcesNetworkPolicy(t *testing.T) {
	endpoint := newCountingServer(t, writeTokenResponse)
	storage := &recordingTokenStorage{}

	_, err := newStorageBackedTokenSourceWithClient(storage, exchangeTestConfig(endpoint.URL), expiredTestToken(), NewOAuthExchangeClient(RemoteMCPURLValidationConfig{})).Token()

	require.ErrorContains(t, err, "blocked")
	require.Zero(t, endpoint.hits.Load())
	require.Zero(t, storage.setCalls)
}

func TestGlobalTokenStoreCarriesRefreshClientToEveryTokenStore(t *testing.T) {
	refreshClient := NewOAuthExchangeClient(allowAllRemoteMCP)

	storage := NewGlobalTokenStore(nil, WithTokenRefreshHTTPClient(refreshClient)).ForUserAndMCP("user", "mcp", "https://mcp.example/mcp")

	tokenStorage, ok := storage.(*tokenStore)
	require.True(t, ok, "ForUserAndMCP returned %T, want *tokenStore", storage)
	require.Same(t, refreshClient, tokenStorage.refreshHTTPClient)
}

// The token store a request handler actually uses must refresh on the configured
// client; carrying it on the struct is not enough if TokenSource drops it.
func TestGlobalTokenStoreRefreshRunsOnConfiguredClient(t *testing.T) {
	const (
		entryName = "catalog-entry-1"
		mcpID     = "mcp-instance-1"
		mcpURL    = "https://mcp.example/api"
	)
	endpoint, target := newRedirectingTokenEndpoint(t)
	client := newCatalogTokenStoreTestClient(t, entryName, mcpID, false)
	require.NoError(t, client.ReplaceMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL, "", exchangeTestConfig(endpoint.URL), expiredTestToken()))
	store := NewGlobalTokenStore(client, WithTokenRefreshHTTPClient(NewOAuthExchangeClient(allowAllRemoteMCP))).ForUserAndMCP("user-1", mcpID, mcpURL)

	source, err := store.TokenSource(t.Context())
	require.NoError(t, err)
	require.NotNil(t, source)
	_, err = source.Token()

	require.ErrorContains(t, err, "refusing to follow redirect")
	require.Zero(t, target.hits.Load(), "refresh token and client secret were replayed to the redirect target")
}

func TestOAuthAuthorizeExchangeRefusesRedirect(t *testing.T) {
	_, target := newRedirectingTokenEndpoint(t)
	var serverURL string
	callback := &oauthAuthorizeCallbackHandler{}
	storage := &recordingTokenStorage{}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"resource":              serverURL + "/mcp",
				"authorization_servers": []string{serverURL},
			})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL,
				"authorization_endpoint":                serverURL + "/authorize",
				"token_endpoint":                        serverURL + "/token",
				"registration_endpoint":                 serverURL + "/register",
				"response_types_supported":              []string{"code"},
				"token_endpoint_auth_methods_supported": []string{"none"},
			})
		case "/register":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(`{"client_id":"dynamic-client"}`))
		case "/token":
			http.Redirect(rw, req, target.URL+"/token", http.StatusTemporaryRedirect)
		default:
			http.NotFound(rw, req)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	request := httptest.NewRequest(http.MethodGet, server.URL+"/mcp", nil)
	response := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header: http.Header{
			"WWW-Authenticate": []string{fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, server.URL)},
		},
		Body: io.NopCloser(strings.NewReader("")),
	}
	o := newOAuth(server.Client(), callback, &oauthTestClientCredLookup{}, storage, "test-server", "test-client", "https://obot.example.com/callback", "")

	err := o.Authorize(t.Context(), request, response)

	require.ErrorContains(t, err, "refusing to follow redirect")
	require.Zero(t, target.hits.Load(), "authorization code and PKCE verifier were replayed to the redirect target")
	require.Zero(t, storage.setCalls)
}

func TestWithOAuthHTTPClientNilLeavesContextUnchanged(t *testing.T) {
	type markerKey struct{}
	ctx := context.WithValue(t.Context(), markerKey{}, "marker")

	require.Equal(t, ctx, WithOAuthHTTPClient(ctx, nil))
}
