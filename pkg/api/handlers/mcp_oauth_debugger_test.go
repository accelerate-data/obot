package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/mcp"
	"github.com/obot-platform/obot/pkg/safehttp"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/storage/scheme"
	sservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type oauthDebuggerRoundTripFunc func(*http.Request) (*http.Response, error)

func (f oauthDebuggerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestExchangeAndPersistOAuthDebuggerTokenForDirectDynamicAndCIMD(t *testing.T) {
	const (
		mcpID  = "direct-mcp-server"
		mcpURL = "https://direct-mcp.example/api"
	)
	for _, tc := range []struct {
		name   string
		legacy bool
		config *oauth2.Config
	}{
		{name: "new dynamic registration", config: &oauth2.Config{ClientID: "dynamic-client", ClientSecret: "dynamic-secret"}},
		{name: "new CIMD", config: &oauth2.Config{ClientID: "https://obot.example/oauth/client-metadata"}},
		{name: "legacy dynamic registration", legacy: true, config: &oauth2.Config{ClientID: "dynamic-client", ClientSecret: "dynamic-secret"}},
		{name: "legacy CIMD", legacy: true, config: &oauth2.Config{ClientID: "https://obot.example/oauth/client-metadata"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gatewayClient := newDirectOAuthDebuggerTestClient(t, mcpID)
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"access_token":"debugger-access","refresh_token":"debugger-refresh","token_type":"Bearer"}`)
			}))
			t.Cleanup(provider.Close)
			config := *tc.config
			config.Endpoint = oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL}
			var pending *gatewaytypes.MCPOAuthPendingState
			if tc.legacy {
				pending = &gatewaytypes.MCPOAuthPendingState{
					UserID: "user-1", MCPID: mcpID, URL: mcpURL,
					OAuthAuthRequestID: OAuthDebuggerPendingStateMarker,
					ClientID:           config.ClientID, ClientSecret: config.ClientSecret,
					AuthURL: config.Endpoint.AuthURL, TokenURL: config.Endpoint.TokenURL,
				}
			} else {
				if err := gatewayClient.CreateMCPOAuthPendingState(t.Context(), "user-1", mcpID, mcpURL, OAuthDebuggerPendingStateMarker, "", "new-state", "verifier-1", &config); err != nil {
					t.Fatalf("create debugger pending state: %v", err)
				}
				var err error
				pending, err = gatewayClient.GetMCPOAuthPendingState(t.Context(), "new-state")
				if err != nil {
					t.Fatalf("load debugger pending state: %v", err)
				}
			}

			token, err := exchangeAndPersistOAuthDebuggerToken(t.Context(), gatewayClient, pending, "code-1")
			if err != nil {
				t.Fatalf("exchange direct debugger token: %v", err)
			}
			if token.AccessToken != "debugger-access" {
				t.Fatalf("provider token = %q", token.AccessToken)
			}
			stored, err := gatewayClient.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL)
			if err != nil {
				t.Fatalf("load stored debugger token: %v", err)
			}
			if stored.AccessToken != "debugger-access" || stored.CatalogEntryName != "" {
				t.Fatalf("stored debugger token = access %q entry %q", stored.AccessToken, stored.CatalogEntryName)
			}
		})
	}
}

func TestExchangeOAuthDebuggerTokenBlocksStaticCatalogPrivateTokenEndpoint(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("restricted client reached the private token endpoint")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(provider.Close)
	pending := &gatewaytypes.MCPOAuthPendingState{
		UserID: "user-1", MCPID: "mcp-1", URL: "https://mcp.example/api",
		OAuthAuthRequestID: OAuthDebuggerPendingStateMarker,
		CatalogEntryName:   "entry-1",
		ClientID:           "client-1", ClientSecret: "secret-1",
		AuthURL: "https://provider.example/authorize", TokenURL: provider.URL,
	}

	_, err := exchangeAndPersistOAuthDebuggerToken(
		t.Context(),
		newDirectOAuthDebuggerTestClient(t, "mcp-1"),
		pending,
		"code-1",
		safehttp.NewClient(safehttp.ClientOptions{
			BlockLoopback:  true,
			BlockPrivateIP: true,
			BlockLinkLocal: true,
		}),
	)
	if err == nil || !strings.Contains(err.Error(), "failed to exchange OAuth code") {
		t.Fatalf("expected blocked private token exchange, got %v", err)
	}
}

func newDirectOAuthDebuggerTestClient(t *testing.T, mcpID string) *gateway.Client {
	t.Helper()
	storageClient := clientfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(&v1.MCPServer{
			ObjectMeta: metav1.ObjectMeta{Namespace: system.DefaultNamespace, Name: mcpID},
		}).
		Build()
	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	if err != nil {
		t.Fatalf("create storage services: %v", err)
	}
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	if err != nil {
		t.Fatalf("create gateway DB: %v", err)
	}
	if err := db.AutoMigrate(); err != nil {
		t.Fatalf("migrate gateway DB: %v", err)
	}
	gatewayClient := gateway.New(t.Context(), db, storageClient, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { _ = gatewayClient.Close() })
	return gatewayClient
}

func TestOAuthDebuggerMetadata(t *testing.T) {
	authServer := mcp.AuthorizationServerMetadata{
		Issuer:                            "https://auth.example.com",
		AuthorizationEndpoint:             "https://auth.example.com/authorize",
		TokenEndpoint:                     "https://auth.example.com/token",
		RegistrationEndpoint:              "https://auth.example.com/register",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}
	authServerJSON := mustJSON(t, authServer)

	registration := mcp.ClientRegistrationMetadata{Scope: "read write"}
	registrationJSON := mustJSON(t, registration)

	m := &MCPHandler{serverURL: "https://obot.example.com"}
	parsedAuthServer, parsedRegistration, err := m.oauthDebuggerMetadata(v1.MCPServer{
		Status: v1.MCPServerStatus{
			OAuthMetadata: &v1.OAuthMetadata{
				AuthorizationServerURL:      authServer.Issuer,
				AuthorizationServerMetadata: runtime.RawExtension{Raw: authServerJSON},
				ClientRegistration:          runtime.RawExtension{Raw: registrationJSON},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(parsedAuthServer, authServer) {
		t.Fatalf("parsed auth server mismatch:\nexpected: %#v\nactual:   %#v", authServer, parsedAuthServer)
	}

	expectedRegistration := mcp.ClientRegistrationMetadata{
		RedirectURIs:            []string{"https://obot.example.com/oauth/mcp/callback"},
		TokenEndpointAuthMethod: "client_secret_post",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Obot MCP OAuth Debugger",
		Scope:                   "read write",
	}
	if !reflect.DeepEqual(parsedRegistration, expectedRegistration) {
		t.Fatalf("parsed registration mismatch:\nexpected: %#v\nactual:   %#v", expectedRegistration, parsedRegistration)
	}
}

func TestOAuthDebuggerMetadataErrors(t *testing.T) {
	tests := []struct {
		name             string
		oauthMetadata    *v1.OAuthMetadata
		expectedContains string
	}{
		{
			name: "invalid auth server metadata",
			oauthMetadata: &v1.OAuthMetadata{
				AuthorizationServerMetadata: runtime.RawExtension{Raw: json.RawMessage(`{`)},
			},
			expectedContains: "failed to parse OAuth authorization server metadata",
		},
		{
			name: "missing authorization endpoint",
			oauthMetadata: &v1.OAuthMetadata{
				AuthorizationServerMetadata: runtime.RawExtension{Raw: mustJSON(t, mcp.AuthorizationServerMetadata{
					TokenEndpoint: "https://auth.example.com/token",
				})},
			},
			expectedContains: "authorization_endpoint",
		},
		{
			name: "missing token endpoint",
			oauthMetadata: &v1.OAuthMetadata{
				AuthorizationServerMetadata: runtime.RawExtension{Raw: mustJSON(t, mcp.AuthorizationServerMetadata{
					AuthorizationEndpoint: "https://auth.example.com/authorize",
				})},
			},
			expectedContains: "token_endpoint",
		},
		{
			name: "invalid client registration metadata",
			oauthMetadata: &v1.OAuthMetadata{
				AuthorizationServerMetadata: runtime.RawExtension{Raw: mustJSON(t, mcp.AuthorizationServerMetadata{
					AuthorizationEndpoint: "https://auth.example.com/authorize",
					TokenEndpoint:         "https://auth.example.com/token",
				})},
				ClientRegistration: runtime.RawExtension{Raw: json.RawMessage(`{`)},
			},
			expectedContains: "failed to parse OAuth client registration metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := (&MCPHandler{}).oauthDebuggerMetadata(v1.MCPServer{
				Status: v1.MCPServerStatus{OAuthMetadata: tt.oauthMetadata},
			})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectedContains) {
				t.Fatalf("expected error to contain %q, got %q", tt.expectedContains, err.Error())
			}
		})
	}
}

func TestOAuthDebuggerAuthStyle(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		hasClientSecret bool
		expected        oauth2.AuthStyle
	}{
		{name: "public client", method: "client_secret_basic", expected: oauth2.AuthStyleInParams},
		{name: "confidential client basic", method: "client_secret_basic", hasClientSecret: true, expected: oauth2.AuthStyleInHeader},
		{name: "confidential client post", method: "client_secret_post", hasClientSecret: true, expected: oauth2.AuthStyleInParams},
		{name: "confidential client unspecified", hasClientSecret: true, expected: oauth2.AuthStyleAutoDetect},
		{name: "confidential client private key", method: "private_key_jwt", hasClientSecret: true, expected: oauth2.AuthStyleAutoDetect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if actual := oauthDebuggerAuthStyle(tt.method, tt.hasClientSecret); actual != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, actual)
			}
		})
	}
}

func TestOAuthDebuggerStaticClient(t *testing.T) {
	authServer := mcp.AuthorizationServerMetadata{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}

	client := oauthDebuggerStaticClient("client-id", "client-secret", authServer)

	if !client.Static {
		t.Fatal("expected static client")
	}
	if client.ClientID != "client-id" || client.ClientSecret != "client-secret" {
		t.Fatalf("expected static credentials to be set, got %q/%q", client.ClientID, client.ClientSecret)
	}
	if client.AuthorizeURL != authServer.AuthorizationEndpoint || client.TokenURL != authServer.TokenEndpoint {
		t.Fatalf("expected auth server URLs to be set")
	}
}

func TestOAuthDebuggerUsesCIMD(t *testing.T) {
	tests := []struct {
		name         string
		serverURL    string
		oauthMeta    *v1.OAuthMetadata
		clientID     string
		clientSecret string
		forceDynamic bool
		expected     bool
	}{
		{
			name:      "supported without static credentials",
			serverURL: "https://obot.example.com",
			oauthMeta: &v1.OAuthMetadata{
				ClientIDMetadataDocumentSupported: true,
			},
			expected: true,
		},
		{
			name:         "dynamic client registration forced",
			serverURL:    "https://obot.example.com",
			forceDynamic: true,
			oauthMeta: &v1.OAuthMetadata{
				ClientIDMetadataDocumentSupported: true,
			},
		},
		{
			name:      "static credentials win",
			serverURL: "https://obot.example.com",
			oauthMeta: &v1.OAuthMetadata{
				ClientIDMetadataDocumentSupported: true,
			},
			clientID:     "client-id",
			clientSecret: "client-secret",
		},
		{
			name:      "public static client wins",
			serverURL: "https://obot.example.com",
			oauthMeta: &v1.OAuthMetadata{
				ClientIDMetadataDocumentSupported: true,
			},
			clientID: "public-client-id",
		},
		{
			name:      "unsupported by auth server",
			serverURL: "https://obot.example.com",
			oauthMeta: &v1.OAuthMetadata{
				ClientIDMetadataDocumentSupported: false,
			},
		},
		{
			name:      "obot client id must be https",
			serverURL: "http://obot.example.com",
			oauthMeta: &v1.OAuthMetadata{
				ClientIDMetadataDocumentSupported: true,
			},
		},
		{
			name:      "missing metadata",
			serverURL: "https://obot.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := v1.MCPServer{
				Status: v1.MCPServerStatus{OAuthMetadata: tt.oauthMeta},
			}
			got := (&MCPHandler{serverURL: tt.serverURL, forceDynamicClient: tt.forceDynamic}).useOAuthDebuggerCIMD(server, tt.clientID, tt.clientSecret)
			if got != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestOAuthDebuggerCIMDClient(t *testing.T) {
	authServer := mcp.AuthorizationServerMetadata{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}
	registration := mcp.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://obot.example.com/oauth/mcp/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		ClientName:    "Obot MCP OAuth Debugger",
		Scope:         "read write",
	}

	client := (&MCPHandler{serverURL: "https://obot.example.com"}).oauthDebuggerCIMDClient(authServer, registration)

	if client.ClientID != system.OAuthClientIDMetadataURL("https://obot.example.com") {
		t.Fatalf("expected CIMD client ID, got %q", client.ClientID)
	}
	if client.ClientSecret != "" {
		t.Fatalf("expected no client secret, got %q", client.ClientSecret)
	}
	if client.TokenEndpointAuthMethod != "none" {
		t.Fatalf("expected token_endpoint_auth_method none, got %q", client.TokenEndpointAuthMethod)
	}
	if client.AuthorizeURL != authServer.AuthorizationEndpoint || client.TokenURL != authServer.TokenEndpoint {
		t.Fatalf("expected auth server URLs to be set")
	}
	if !reflect.DeepEqual(client.RedirectURIs, registration.RedirectURIs) {
		t.Fatalf("expected redirect URIs %#v, got %#v", registration.RedirectURIs, client.RedirectURIs)
	}
}

func TestRegisterOAuthDebuggerClientUsesProvidedHTTPClient(t *testing.T) {
	registration := mcp.ClientRegistrationMetadata{
		ClientName:   "Obot MCP OAuth Debugger",
		RedirectURIs: []string{"https://obot.example.com/oauth/mcp/callback"},
	}
	expected := types.OAuthClient{
		ClientID:     "registered-client",
		ClientSecret: "registered-secret",
	}
	called := false
	httpClient := &http.Client{Transport: oauthDebuggerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		if request.Method != http.MethodPost || request.URL.String() != "https://auth.internal.test/register" {
			t.Errorf("registration request = %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("registration request headers = %#v", request.Header)
		}
		var actual mcp.ClientRegistrationMetadata
		if err := json.NewDecoder(request.Body).Decode(&actual); err != nil {
			t.Errorf("decode registration request: %v", err)
		} else if !reflect.DeepEqual(actual, registration) {
			t.Errorf("registration request = %#v, want %#v", actual, registration)
		}

		body := strings.NewReader(string(mustJSON(t, expected)))
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     make(http.Header),
			Body:       io.NopCloser(body),
			Request:    request,
		}, nil
	})}

	actual, err := registerOAuthDebuggerClient(t.Context(), httpClient, "https://auth.internal.test/register", registration)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("provided HTTP client was not used")
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("registered client = %#v, want %#v", actual, expected)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExchangeAndPersistOAuthDebuggerTokenRejectsRedirectAndSanitizesError(t *testing.T) {
	const (
		mcpID  = "direct-mcp-server"
		mcpURL = "https://direct-mcp.example/api"
	)

	t.Run("redirect", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Error("redirect target received the debugger exchange credentials")
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(target.Close)
		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		t.Cleanup(redirector.Close)

		pending, gatewayClient := newRedirectDebuggerPendingState(t, mcpID, mcpURL, "redirect-state", redirector.URL)
		_, err := exchangeAndPersistOAuthDebuggerToken(t.Context(), gatewayClient, pending, "code-1", http.DefaultClient)
		if err == nil {
			t.Fatal("expected the redirected debugger exchange to fail")
		}
		if !strings.Contains(err.Error(), "redirect") {
			t.Fatalf("error = %q, want a redirect refusal", err)
		}
		for _, leaked := range []string{"verifier-1", "dynamic-secret"} {
			if strings.Contains(err.Error(), leaked) {
				t.Fatalf("error %q leaked %q", err, leaked)
			}
		}
	})

	t.Run("upstream error body", func(t *testing.T) {
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"code cd-9f2 rejected for workspace ws-internal-7","request_id":"req-abc123"}`)
		}))
		t.Cleanup(provider.Close)

		pending, gatewayClient := newRedirectDebuggerPendingState(t, mcpID, mcpURL, "error-state", provider.URL)
		_, err := exchangeAndPersistOAuthDebuggerToken(t.Context(), gatewayClient, pending, "code-1", http.DefaultClient)
		if err == nil {
			t.Fatal("expected the rejected debugger exchange to fail")
		}
		for _, leaked := range []string{"req-abc123", "ws-internal-7", "cd-9f2"} {
			if strings.Contains(err.Error(), leaked) {
				t.Fatalf("error %q leaked %q", err, leaked)
			}
		}
	})
}

func newRedirectDebuggerPendingState(t *testing.T, mcpID, mcpURL, state, tokenURL string) (*gatewaytypes.MCPOAuthPendingState, *gateway.Client) {
	t.Helper()
	gatewayClient := newDirectOAuthDebuggerTestClient(t, mcpID)
	config := &oauth2.Config{
		ClientID: "dynamic-client", ClientSecret: "dynamic-secret",
		Endpoint: oauth2.Endpoint{AuthURL: tokenURL + "/authorize", TokenURL: tokenURL, AuthStyle: oauth2.AuthStyleInParams},
	}
	if err := gatewayClient.CreateMCPOAuthPendingState(t.Context(), "user-1", mcpID, mcpURL, OAuthDebuggerPendingStateMarker, "", state, "verifier-1", config); err != nil {
		t.Fatalf("create debugger pending state: %v", err)
	}
	pending, err := gatewayClient.GetMCPOAuthPendingState(t.Context(), state)
	if err != nil {
		t.Fatalf("load debugger pending state: %v", err)
	}
	return pending, gatewayClient
}
