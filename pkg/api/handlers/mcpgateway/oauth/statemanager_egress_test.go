package oauth

// Fork-only guarantee (VD-4887, restored by VD-6903): the gateway's dynamic
// OAuth callback exchanges its code on the operator's remote-network policy and
// never follows a redirect. Kept in its own file so an upstream sync cannot drop
// these tests by merging over a shared one.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/obot-platform/obot/pkg/mcp"
)

var (
	allowAllRemoteMCP = mcp.RemoteMCPURLValidationConfig{
		AllowLocalhostMCP: true,
		AllowPrivateIPMCP: true,
		AllowLinkLocalMCP: true,
	}
)

func TestStateManagerCreateTokenRefusesTokenEndpointRedirect(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
	}))
	defer target.Close()
	endpoint := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, target.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer endpoint.Close()
	gateway := newStaticOAuthCallbackGateway(t)
	storeDynamicCallbackState(t, gateway, endpoint.URL, "state")

	_, _, err := newStateManager(gateway, mcp.NewOAuthExchangeClient(allowAllRemoteMCP)).createToken(t.Context(), "state", "code", "", "")

	if err == nil || !strings.Contains(err.Error(), "refusing to follow redirect") {
		t.Fatalf("createToken returned %v, want redirect refusal", err)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("redirect target hits = %d, want 0: the authorization code and PKCE verifier were replayed", got)
	}
}

func TestStateManagerCreateTokenEnforcesRemoteNetworkPolicy(t *testing.T) {
	var endpointHits atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		endpointHits.Add(1)
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
	}))
	defer endpoint.Close()
	gateway := newStaticOAuthCallbackGateway(t)
	storeDynamicCallbackState(t, gateway, endpoint.URL, "state")

	_, _, err := newStateManager(gateway, mcp.NewOAuthExchangeClient(mcp.RemoteMCPURLValidationConfig{})).createToken(t.Context(), "state", "code", "", "")

	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("createToken returned %v, want the loopback token endpoint blocked", err)
	}
	if got := endpointHits.Load(); got != 0 {
		t.Fatalf("token endpoint hits = %d, want 0", got)
	}
}

func TestMCPOAuthHandlerFactoryExchangesOnRedirectRefusingClient(t *testing.T) {
	factory := NewMCPOAuthHandlerFactory("https://obot.example.com", nil, nil, nil, nil, "", false)

	if factory.stateMgr.exchangeHTTPClient == nil || factory.stateMgr.exchangeHTTPClient.CheckRedirect == nil {
		t.Fatal("dynamic OAuth state manager exchanges on a client that follows redirects")
	}
}
