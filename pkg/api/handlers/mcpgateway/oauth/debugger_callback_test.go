package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/obot/pkg/api"
	"github.com/obot-platform/obot/pkg/api/handlers"
	"golang.org/x/oauth2"
)

// The debugger callback forwards the provider's error to a browser redirect, so
// it is subject to the same rule as the other callback paths: the error code is
// repeated, the provider's free-text description is not.
func TestDebuggerCallbackDoesNotForwardProviderErrorDescription(t *testing.T) {
	gateway := newStaticOAuthCallbackGateway(t)
	const state = "debugger-callback-state"
	if err := gateway.CreateMCPOAuthPendingState(t.Context(), "user-1", "mcp-1", "https://example.com/mcp", handlers.OAuthDebuggerPendingStateMarker, "", state, "verifier", &oauth2.Config{ClientID: "client-1"}); err != nil {
		t.Fatalf("create pending state: %v", err)
	}

	recorder := httptest.NewRecorder()
	req := api.Context{
		Request: httptest.NewRequest(http.MethodGet,
			"/oauth/mcp/callback?state="+state+
				"&error=access_denied%3Cscript%3E"+
				"&error_description=denied+for+workspace+ws-42+request+req-99", nil),
		ResponseWriter: recorder,
	}
	h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}

	handled, err := h.maybeHandleDebuggerCallback(req)
	if err != nil {
		t.Fatalf("handle debugger callback: %v", err)
	}
	if !handled {
		t.Fatal("debugger callback was not handled")
	}

	location := recorder.Header().Get("Location")
	if !strings.Contains(location, "error=access_denied") {
		t.Fatalf("redirect dropped the error code: %q", location)
	}
	// SafeOAuthErrorCode is a charset filter, not a content filter: the provider's
	// error code is repeated with dangerous characters removed, while the
	// description — where providers put request and workspace identifiers — is
	// dropped entirely.
	for _, leaked := range []string{"error_description", "ws-42", "req-99", "%3C", "%3E", "<", ">"} {
		if strings.Contains(location, leaked) {
			t.Fatalf("redirect leaked %q: %q", leaked, location)
		}
	}
}
