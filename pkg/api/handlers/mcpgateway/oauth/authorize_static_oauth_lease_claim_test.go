package oauth

// Fork-only guarantee (VD-4890, restored by VD-6903): a static OAuth credential
// test callback cannot hold its claim past the lease. The provider exchange is
// bounded, the outcome is persisted even after the browser goes away, and a
// completion that arrives after the lease lapsed is rejected rather than
// resurrecting a test already reported as interrupted. Kept in its own file so
// an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"gorm.io/gorm"
)

func newLeaseClaimCallbackRequest(ctx context.Context, callbackState string) api.Context {
	return api.Context{
		Request:        httptest.NewRequestWithContext(ctx, http.MethodGet, "/oauth/mcp/callback?state="+callbackState+"&code=valid-code", nil),
		ResponseWriter: httptest.NewRecorder(),
	}
}

// startLeaseClaimCallback runs a callback in the background and returns once it is
// blocked inside the provider token exchange, with its claim already recorded.
func startLeaseClaimCallback(t *testing.T, gateway *gatewayclient.Client, req api.Context, tokenExchangeStarted <-chan struct{}) <-chan error {
	t.Helper()
	h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
	handled := make(chan error, 1)
	go func() { handled <- h.oauthCallback(req) }()
	select {
	case <-tokenExchangeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not reach the provider token exchange")
	}
	return handled
}

func awaitLeaseClaimCallback(t *testing.T, handled <-chan error) error {
	t.Helper()
	select {
	case err := <-handled:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not return")
		return nil
	}
}

func requireLeaseClaimCallbackResult(t *testing.T, gateway *gatewayclient.Client, provider staticOAuthCallbackProvider, state gatewayclient.MCPStaticOAuthTestStart, wantFailure types.MCPStaticOAuthTestFailureCategory) {
	t.Helper()
	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "entry-1")
	if err != nil {
		t.Fatalf("get static OAuth result: %v", err)
	}
	if result.Status != types.MCPStaticOAuthTestStatusFailed || result.FailureCategory != wantFailure {
		t.Fatalf("callback result = %+v, want failed %q", result, wantFailure)
	}
	if result.Proof != "" {
		t.Fatalf("failed callback minted a save proof: %+v", result)
	}
	if _, err := gateway.GetMCPOAuthToken(t.Context(), "user-1", "entry-1", provider.URL+"/mcp"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("static OAuth callback persisted a user token: %v", err)
	}
}

// A provider that never answers would otherwise hold the claim until its lease lapsed
// and leave the user an interrupted test instead of the real token-exchange failure.
func TestStaticOAuthCallbackBoundsProviderTokenExchange(t *testing.T) {
	provider, tokenExchangeStarted, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
	defer releaseTokenExchange()
	original := staticOAuthTokenExchangeTimeout
	staticOAuthTokenExchangeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { staticOAuthTokenExchangeTimeout = original })
	gateway := newStaticOAuthCallbackGateway(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	handled := startLeaseClaimCallback(t, gateway, newLeaseClaimCallbackRequest(t.Context(), state.CallbackState), tokenExchangeStarted)

	// The provider is never released, so only the exchange bound can end the callback.
	if err := awaitLeaseClaimCallback(t, handled); err != nil {
		t.Fatalf("handle stalled static OAuth callback: %v", err)
	}

	requireLeaseClaimCallbackResult(t, gateway, provider, state, types.MCPStaticOAuthTestFailureTokenExchange)
}

// Closing the popup cancels the request; the outcome must still be persisted so the
// test reaches a terminal result instead of a claim the user has to wait out.
func TestStaticOAuthCallbackRecordsTerminalResultAfterClientDisconnect(t *testing.T) {
	provider, tokenExchangeStarted, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
	defer releaseTokenExchange()
	gateway := newStaticOAuthCallbackGateway(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	requestContext, disconnect := context.WithCancel(t.Context())
	req := newLeaseClaimCallbackRequest(requestContext, state.CallbackState)
	handled := startLeaseClaimCallback(t, gateway, req, tokenExchangeStarted)

	disconnect()
	releaseTokenExchange()

	if err := awaitLeaseClaimCallback(t, handled); err != nil {
		t.Fatalf("disconnected static OAuth callback returned %v, want the detached completion to succeed", err)
	}
	requireLeaseClaimCallbackResult(t, gateway, provider, state, types.MCPStaticOAuthTestFailureTokenExchange)
}

// A completion arriving after the lease lapsed would overwrite a test the user has
// already been told was interrupted, so the gateway refuses it and the callback answers
// with the generic invalid-test message.
func TestStaticOAuthCallbackRejectsCompletionAfterClaimLeaseLapsed(t *testing.T) {
	provider, tokenExchangeStarted, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
	defer releaseTokenExchange()
	gateway, db := newStaticOAuthCallbackGatewayWithDB(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	handled := startLeaseClaimCallback(t, gateway, newLeaseClaimCallbackRequest(t.Context(), state.CallbackState), tokenExchangeStarted)

	if err := db.WithContext(t.Context()).Model(&gatewaytypes.MCPOAuthPendingState{}).
		Where("static_o_auth_test = ?", true).
		Update("static_o_auth_test_claimed_at", time.Now().Add(-24*time.Hour)).Error; err != nil {
		t.Fatalf("age claim: %v", err)
	}
	releaseTokenExchange()

	err = awaitLeaseClaimCallback(t, handled)
	if err == nil || !strings.Contains(err.Error(), invalidStaticOAuthCredentialTestMessage) {
		t.Fatalf("callback error = %v, want the generic invalid-test message", err)
	}
	requireLeaseClaimCallbackResult(t, gateway, provider, state, types.MCPStaticOAuthTestFailureInterrupted)
}

// A failed completion write must not tell the browser about the database: the
// callback answers generically, and the unwritten row stays a claim that later
// reads as interrupted instead of being resurrected.
func TestStaticOAuthCallbackHidesCompletionPersistenceFailure(t *testing.T) {
	provider, tokenExchangeStarted, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
	defer releaseTokenExchange()
	gateway, db := newStaticOAuthCallbackGatewayWithDB(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	handled := startLeaseClaimCallback(t, gateway, newLeaseClaimCallbackRequest(t.Context(), state.CallbackState), tokenExchangeStarted)

	// Fail only the completion write: the claim has already been recorded, so the
	// trigger installed here cannot affect anything but the outcome persistence.
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(&gatewaytypes.MCPOAuthPendingState{}); err != nil {
		t.Fatalf("resolve pending state table: %v", err)
	}
	table := stmt.Schema.Table
	if err := db.WithContext(t.Context()).Exec(`CREATE TRIGGER fail_static_completion BEFORE UPDATE ON ` + table + ` BEGIN SELECT RAISE(FAIL, 'injected completion write failure'); END`).Error; err != nil {
		t.Fatalf("install completion write failure: %v", err)
	}
	releaseTokenExchange()

	err = awaitLeaseClaimCallback(t, handled)
	if err == nil {
		t.Fatal("callback with a failing completion write returned no error")
	}
	for _, leaked := range []string{"injected", "RAISE", table, state.CallbackState} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("callback error exposed %q: %v", leaked, err)
		}
	}
	if err := db.WithContext(t.Context()).Exec(`DROP TRIGGER fail_static_completion`).Error; err != nil {
		t.Fatalf("remove completion write failure: %v", err)
	}
	if err := db.WithContext(t.Context()).Model(&gatewaytypes.MCPOAuthPendingState{}).
		Where("static_o_auth_test = ?", true).
		Update("static_o_auth_test_claimed_at", time.Now().Add(-24*time.Hour)).Error; err != nil {
		t.Fatalf("age claim: %v", err)
	}
	requireLeaseClaimCallbackResult(t, gateway, provider, state, types.MCPStaticOAuthTestFailureInterrupted)
}
