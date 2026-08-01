package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	storageservices "github.com/obot-platform/obot/pkg/storage/services"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func TestStaticOAuthCallbackExchangesAndDiscardsTokenBeforeNormalOAuth(t *testing.T) {
	provider := newStaticOAuthCallbackProvider(t)
	gateway := newStaticOAuthCallbackGateway(t)
	conf := provider.config()
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", conf)
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	authorizationResponse, err := http.Get(conf.AuthCodeURL(state, oauth2.S256ChallengeOption("exact-verifier")))
	if err != nil {
		t.Fatalf("authorize static OAuth test: %v", err)
	}
	_ = authorizationResponse.Body.Close()
	if authorizationResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("provider rejected PKCE authorization request: %d", authorizationResponse.StatusCode)
	}

	recorder := httptest.NewRecorder()
	req := api.Context{
		Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state+"&code=valid-code", nil),
		ResponseWriter: recorder,
	}
	h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
	if err := h.oauthCallback(req); err != nil {
		t.Fatalf("handle static OAuth callback: %v", err)
	}

	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state, "user-1", "entry-1")
	if err != nil {
		t.Fatalf("get completed static OAuth test: %v", err)
	}
	if result.Status != types.MCPStaticOAuthTestStatusSucceeded || result.FailureCategory != "" {
		t.Fatalf("callback result = %+v, want succeeded", result)
	}
	if _, err := gateway.GetMCPOAuthToken(t.Context(), "user-1", "entry-1", provider.URL+"/mcp"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("static OAuth callback persisted a user token: %v", err)
	}
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/auth/oauth/complete" {
		t.Fatalf("callback response = %d Location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestStaticOAuthCallbackRecordsOnlySafeFailures(t *testing.T) {
	provider := newStaticOAuthCallbackProvider(t)
	for _, tt := range []struct {
		name         string
		query        string
		wantCategory types.MCPStaticOAuthTestFailureCategory
	}{
		{name: "authorization denied", query: "&error=access_denied&error_description=provider-secret-body", wantCategory: types.MCPStaticOAuthTestFailureAuthorizationDenied},
		{name: "missing code", query: "", wantCategory: types.MCPStaticOAuthTestFailureInvalidCallback},
		{name: "token rejected", query: "&code=rejected-code", wantCategory: types.MCPStaticOAuthTestFailureTokenExchange},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gateway := newStaticOAuthCallbackGateway(t)
			state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
			if err != nil {
				t.Fatalf("create static OAuth test: %v", err)
			}
			recorder := httptest.NewRecorder()
			req := api.Context{
				Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state+tt.query, nil),
				ResponseWriter: recorder,
			}
			h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
			if err := h.oauthCallback(req); err != nil {
				t.Fatalf("handle failed static OAuth callback: %v", err)
			}

			result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state, "user-1", "entry-1")
			if err != nil {
				t.Fatalf("get failed static OAuth test: %v", err)
			}
			if result.Status != types.MCPStaticOAuthTestStatusFailed || result.FailureCategory != tt.wantCategory {
				t.Fatalf("callback result = %+v, want failed/%s", result, tt.wantCategory)
			}
			if _, err := gateway.GetMCPOAuthToken(t.Context(), "user-1", "entry-1", provider.URL+"/mcp"); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("failed static OAuth callback persisted a user token: %v", err)
			}
			for _, sensitive := range []string{"provider-secret-body", "provider body contains secret code and token", "static-secret", "discard-me"} {
				if body := recorder.Body.String(); strings.Contains(body, sensitive) {
					t.Fatalf("callback echoed provider detail %q: %q", sensitive, body)
				}
			}
		})
	}
}

func TestStaticOAuthCallbackClassifiesMismatchedStateAsSafeFailure(t *testing.T) {
	pendingState := &gatewaytypes.MCPOAuthPendingState{State: "expected-state"}

	if got := staticOAuthCallbackInputFailure(pendingState, "different-state", "valid-code", ""); got != types.MCPStaticOAuthTestFailureInvalidCallback {
		t.Fatalf("mismatched state category = %q, want %q", got, types.MCPStaticOAuthTestFailureInvalidCallback)
	}
}

type staticOAuthCallbackProvider struct {
	*httptest.Server
}

func newStaticOAuthCallbackProvider(t *testing.T) staticOAuthCallbackProvider {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/authorize" {
			if req.URL.Query().Get("client_id") != "static-client" ||
				req.URL.Query().Get("code_challenge_method") != "S256" ||
				req.URL.Query().Get("code_challenge") != oauth2.S256ChallengeFromVerifier("exact-verifier") {
				http.Error(w, "invalid authorization request", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if req.URL.Path != "/token" {
			http.NotFound(w, req)
			return
		}
		clientID, clientSecret, ok := req.BasicAuth()
		if !ok || clientID != "static-client" || clientSecret != "static-secret" || req.FormValue("code_verifier") != "exact-verifier" || req.FormValue("code") != "valid-code" {
			http.Error(w, "provider body contains secret code and token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&oauth2.Token{AccessToken: "discard-me", TokenType: "Bearer"})
	}))
	t.Cleanup(server.Close)
	return staticOAuthCallbackProvider{Server: server}
}

func (p staticOAuthCallbackProvider) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "static-client",
		ClientSecret: "static-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.URL + "/authorize",
			TokenURL:  p.URL + "/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
	}
}

func newStaticOAuthCallbackGateway(t *testing.T) *gatewayclient.Client {
	t.Helper()
	services, err := storageservices.New(storageservices.Config{DSN: "sqlite://:memory:"})
	if err != nil {
		t.Fatalf("create storage services: %v", err)
	}
	database, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	if err != nil {
		t.Fatalf("create gateway database: %v", err)
	}
	if err := database.AutoMigrate(); err != nil {
		t.Fatalf("migrate gateway database: %v", err)
	}
	return gatewayclient.New(t.Context(), database, nil, nil, nil, nil, nil, time.Hour, 10, 0, 0, false)
}
