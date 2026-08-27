package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	"github.com/obot-platform/obot/pkg/api/authn"
	"github.com/obot-platform/obot/pkg/api/authz"
	apiserver "github.com/obot-platform/obot/pkg/api/server"
	"github.com/obot-platform/obot/pkg/api/server/audit"
	"github.com/obot-platform/obot/pkg/api/server/ratelimiter"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/license"
	"github.com/obot-platform/obot/pkg/safehttp"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	storageservices "github.com/obot-platform/obot/pkg/storage/services"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestUnauthenticatedStaticOAuthCallbackPassesServerMiddleware(t *testing.T) {
	provider := newStaticOAuthCallbackProvider(t)
	gateway := newStaticOAuthCallbackGateway(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}

	server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state.CallbackState+"&code=valid-code", nil))

	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/auth/oauth/complete" {
		t.Fatalf("callback response = %d Location=%q body=%q, want handler completion redirect", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "entry-1")
	if err != nil {
		t.Fatalf("get completed static OAuth test: %v", err)
	}
	if result.Status != types.MCPStaticOAuthTestStatusSucceeded || result.FailureCategory != "" {
		t.Fatalf("callback result = %+v, want succeeded", result)
	}
}

func TestPublicStaticOAuthCallbackRejectsInvalidState(t *testing.T) {
	provider := newStaticOAuthCallbackProvider(t)

	t.Run("missing state", func(t *testing.T) {
		gateway := newStaticOAuthCallbackGateway(t)
		server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
		assertSafeStaticOAuthCallbackFailure(t, server, "/oauth/mcp/callback", http.StatusBadRequest, "")
	})

	t.Run("unknown state", func(t *testing.T) {
		gateway := newStaticOAuthCallbackGateway(t)
		server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
		assertSafeStaticOAuthCallbackFailure(t, server, "/oauth/mcp/callback?state=attacker-state&error_description=provider-secret", http.StatusBadRequest, "attacker-state", "provider-secret")
	})

	t.Run("expired state", func(t *testing.T) {
		gateway, db := newStaticOAuthCallbackGatewayWithDB(t)
		state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
		if err != nil {
			t.Fatalf("create static OAuth test: %v", err)
		}
		proof, err := gateway.GetMCPOAuthPendingState(t.Context(), state.CallbackState)
		if err != nil {
			t.Fatalf("read pending proof: %v", err)
		}
		if err := db.WithContext(t.Context()).Model(&gatewaytypes.MCPOAuthPendingState{}).
			Where("hashed_state = ?", proof.HashedState).
			Update("created_at", time.Now().Add(-31*time.Minute)).Error; err != nil {
			t.Fatalf("age static OAuth test: %v", err)
		}
		server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
		assertSafeStaticOAuthCallbackFailure(t, server, "/oauth/mcp/callback?state="+state.CallbackState+"&code=valid-code", http.StatusBadRequest, state.CallbackState)
		if got := provider.tokenExchangeCount(); got != 0 {
			t.Fatalf("expired proof provider exchanges = %d, want 0", got)
		}
	})

	t.Run("replayed state", func(t *testing.T) {
		gateway := newStaticOAuthCallbackGateway(t)
		state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
		if err != nil {
			t.Fatalf("create static OAuth test: %v", err)
		}
		server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
		exchangesBefore := provider.tokenExchangeCount()
		first := httptest.NewRecorder()
		server.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state.CallbackState+"&code=valid-code", nil))
		if first.Code != http.StatusFound {
			t.Fatalf("first callback response = %d body=%q, want completion redirect", first.Code, first.Body.String())
		}
		assertSafeStaticOAuthCallbackFailure(t, server, "/oauth/mcp/callback?state="+state.CallbackState+"&code=valid-code", http.StatusBadRequest, state.CallbackState)
		if got := provider.tokenExchangeCount() - exchangesBefore; got != 1 {
			t.Fatalf("replayed callback provider exchanges = %d, want exactly 1", got)
		}
	})
}

func TestStaticOAuthCallbackClaimsProofBeforeProviderExchange(t *testing.T) {
	provider, tokenExchangeStarted, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
	defer releaseTokenExchange()
	gateway := newStaticOAuthCallbackGateway(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
	path := "/oauth/mcp/callback?state=" + state.CallbackState + "&code=valid-code"

	type callbackResponse struct {
		status int
		body   string
	}
	responses := make(chan callbackResponse, 2)
	request := func() {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		responses <- callbackResponse{status: recorder.Code, body: recorder.Body.String()}
	}

	go request()
	select {
	case <-tokenExchangeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first callback did not reach provider token exchange")
	}
	go request()

	select {
	case loser := <-responses:
		if loser.status != http.StatusBadRequest || loser.body != "invalid or expired OAuth callback state\n" {
			t.Fatalf("concurrent loser = %d body=%q, want generic bad request", loser.status, loser.body)
		}
	case <-time.After(2 * time.Second):
		releaseTokenExchange()
		t.Fatal("concurrent callback reached provider instead of failing its claim")
	}

	releaseTokenExchange()
	winner := <-responses
	if winner.status != http.StatusFound {
		t.Fatalf("claim winner = %d body=%q, want completion redirect", winner.status, winner.body)
	}
	if got := provider.tokenExchangeCount(); got != 1 {
		t.Fatalf("provider token exchanges = %d, want exactly 1", got)
	}
}

func TestUnauthenticatedStaticOAuthCallbackDoesNotExposeSiblingRoutes(t *testing.T) {
	gateway := newStaticOAuthCallbackGateway(t)
	server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("protected route response = %d body=%q, want unauthorized", recorder.Code, recorder.Body.String())
	}
}

func newUnauthenticatedStaticOAuthCallbackServer(t *testing.T, gateway *gatewayclient.Client) *apiserver.Server {
	t.Helper()
	storage := clientfake.NewClientBuilder().WithScheme(storagescheme.Scheme).Build()
	limiter, err := ratelimiter.New(ratelimiter.Options{UnauthenticatedRateLimit: 100, AuthenticatedRateLimit: 100})
	if err != nil {
		t.Fatalf("create rate limiter: %v", err)
	}
	licenseProvider, err := license.NewProvider(t.Context(), nil, license.Config{})
	if err != nil {
		t.Fatalf("create license provider: %v", err)
	}
	auditLogger, err := audit.New(t.Context(), audit.Options{AuditLogsMode: audit.ModeOff})
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	server := apiserver.NewServer(
		storage,
		gateway,
		storage,
		"default",
		authn.NewAuthenticator(authn.Anonymous{}),
		authz.NewAuthorizer(gateway, storage, storage, false, nil, nil, nil, false),
		nil,
		auditLogger,
		limiter,
		"https://obot.example",
		nil,
		false,
		licenseProvider,
	)
	h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
	server.HandleFunc("GET /oauth/mcp/callback", h.oauthCallback)
	server.HandleFunc("GET /oauth/userinfo", func(api.Context) error {
		return nil
	})
	return server
}

func assertSafeStaticOAuthCallbackFailure(t *testing.T, server http.Handler, path string, wantStatus int, sensitive ...string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != wantStatus {
		t.Fatalf("callback response = %d body=%q, want %d", recorder.Code, recorder.Body.String(), wantStatus)
	}
	if recorder.Body.String() != "invalid or expired OAuth callback state\n" {
		t.Fatalf("callback response body = %q, want generic invalid-or-expired error", recorder.Body.String())
	}
	for _, value := range sensitive {
		if value != "" && strings.Contains(recorder.Body.String(), value) {
			t.Fatalf("callback response leaked sensitive value %q: %q", value, recorder.Body.String())
		}
	}
}

func TestStaticOAuthCallbackExchangesAndDiscardsTokenBeforeNormalOAuth(t *testing.T) {
	provider := newStaticOAuthCallbackProvider(t)
	gateway := newStaticOAuthCallbackGateway(t)
	conf := provider.config()
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", conf)
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	authorizationResponse, err := http.Get(conf.AuthCodeURL(state.CallbackState, oauth2.S256ChallengeOption("exact-verifier")))
	if err != nil {
		t.Fatalf("authorize static OAuth test: %v", err)
	}
	_ = authorizationResponse.Body.Close()
	if authorizationResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("provider rejected PKCE authorization request: %d", authorizationResponse.StatusCode)
	}

	recorder := httptest.NewRecorder()
	req := api.Context{
		Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state.CallbackState+"&code=valid-code", nil),
		ResponseWriter: recorder,
	}
	h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
	if err := h.oauthCallback(req); err != nil {
		t.Fatalf("handle static OAuth callback: %v", err)
	}

	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "entry-1")
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

func TestStaticOAuthCallbackBlocksPrivateTokenEndpoint(t *testing.T) {
	provider := newStaticOAuthCallbackProvider(t)
	gateway := newStaticOAuthCallbackGateway(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}

	recorder := httptest.NewRecorder()
	req := api.Context{
		Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state.CallbackState+"&code=valid-code", nil),
		ResponseWriter: recorder,
	}
	h := &handler{
		oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)},
		oauthExchangeHTTPClient: safehttp.NewClient(safehttp.ClientOptions{
			BlockLoopback:  true,
			BlockPrivateIP: true,
			BlockLinkLocal: true,
		}),
	}
	if err := h.oauthCallback(req); err != nil {
		t.Fatalf("handle static OAuth callback: %v", err)
	}
	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "entry-1")
	if err != nil {
		t.Fatalf("get static OAuth result: %v", err)
	}
	if result.Status != types.MCPStaticOAuthTestStatusFailed || result.FailureCategory != types.MCPStaticOAuthTestFailureTokenExchange {
		t.Fatalf("callback result = %+v, want failed token exchange", result)
	}
	if got := provider.tokenExchangeCount(); got != 0 {
		t.Fatalf("blocked provider received %d token exchanges, want 0", got)
	}
}

func TestStaticOAuthCallbackRecordsTerminalResultAfterClientDisconnect(t *testing.T) {
	provider, tokenExchangeStarted, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
	defer releaseTokenExchange()
	gateway := newStaticOAuthCallbackGateway(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}

	requestContext, disconnect := context.WithCancel(t.Context())
	req := api.Context{
		Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state.CallbackState+"&code=valid-code", nil).WithContext(requestContext),
		ResponseWriter: httptest.NewRecorder(),
	}
	h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
	handled := make(chan error, 1)
	go func() { handled <- h.oauthCallback(req) }()

	select {
	case <-tokenExchangeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not reach provider token exchange")
	}
	disconnect()
	releaseTokenExchange()
	select {
	case err := <-handled:
		if err != nil {
			t.Fatalf("disconnected static OAuth callback returned %v, want the detached completion to succeed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not return after the client disconnected")
	}
	if recorder, ok := req.ResponseWriter.(*httptest.ResponseRecorder); !ok {
		t.Fatalf("callback response writer = %T, want a recorder", req.ResponseWriter)
	} else if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/auth/oauth/complete" {
		t.Fatalf("callback response after disconnect = %d Location=%q", recorder.Code, recorder.Header().Get("Location"))
	}

	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "entry-1")
	if err != nil {
		t.Fatalf("get static OAuth result: %v", err)
	}
	if result.Status != types.MCPStaticOAuthTestStatusFailed || result.FailureCategory != types.MCPStaticOAuthTestFailureTokenExchange {
		t.Fatalf("callback result after disconnect = %+v, want failed token exchange", result)
	}
	// The completion runs on a context the request no longer owns, so the
	// credential test must still leave the user's OAuth grant untouched.
	if _, err := gateway.GetMCPOAuthToken(t.Context(), "user-1", "entry-1", provider.URL+"/mcp"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("disconnected static OAuth callback persisted a user token: %v", err)
	}
}

// A callback whose completion cannot be persisted must still answer safely, leave no user
// OAuth grant behind, and mint no save proof, whether the gateway rejects the write as
// abandoned or the write itself fails.
func TestStaticOAuthCallbackReportsCompletionPersistenceFailureSafely(t *testing.T) {
	t.Run("gateway rejects the abandoned claim", func(t *testing.T) {
		provider, tokenExchangeStarted, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
		defer releaseTokenExchange()
		gateway, db := newStaticOAuthCallbackGatewayWithDB(t)
		state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
		if err != nil {
			t.Fatalf("create static OAuth test: %v", err)
		}
		handled := staticOAuthCallbackInFlight(t, gateway, state.CallbackState, tokenExchangeStarted)

		// Age the claim well past any lease the gateway can honour, so the completion
		// arrives after the test has already been reported as interrupted.
		if err := db.WithContext(t.Context()).Model(&gatewaytypes.MCPOAuthPendingState{}).
			Where("static_o_auth_test = ?", true).
			Update("static_o_auth_test_claimed_at", time.Now().Add(-24*time.Hour)).Error; err != nil {
			t.Fatalf("age claim: %v", err)
		}
		releaseTokenExchange()

		err = awaitStaticOAuthCallback(t, handled)
		if err == nil || !strings.Contains(err.Error(), invalidOAuthCallbackStateMessage) {
			t.Fatalf("callback error = %v, want the generic invalid-state message", err)
		}
		assertStaticOAuthCallbackLeftNoCredentials(t, gateway, provider, state, types.MCPStaticOAuthTestFailureInterrupted)
	})

	t.Run("completion write fails", func(t *testing.T) {
		provider, tokenExchangeStarted, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
		defer releaseTokenExchange()
		gateway, db := newStaticOAuthCallbackGatewayWithDB(t)
		state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
		if err != nil {
			t.Fatalf("create static OAuth test: %v", err)
		}
		handled := staticOAuthCallbackInFlight(t, gateway, state.CallbackState, tokenExchangeStarted)

		// Fail only the completion write: the claim has already been recorded, so the
		// trigger installed here cannot affect anything but the outcome persistence.
		table := staticOAuthPendingStateTable(t, db)
		if err := db.WithContext(t.Context()).Exec(`CREATE TRIGGER fail_static_completion BEFORE UPDATE ON ` + table + ` BEGIN SELECT RAISE(FAIL, 'injected completion write failure'); END`).Error; err != nil {
			t.Fatalf("install completion write failure: %v", err)
		}
		releaseTokenExchange()

		err = awaitStaticOAuthCallback(t, handled)
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
		// The write never landed, so the row is still a claim the gateway must not
		// resurrect: it reads as interrupted once its lease runs out.
		if err := db.WithContext(t.Context()).Model(&gatewaytypes.MCPOAuthPendingState{}).
			Where("static_o_auth_test = ?", true).
			Update("static_o_auth_test_claimed_at", time.Now().Add(-24*time.Hour)).Error; err != nil {
			t.Fatalf("age claim: %v", err)
		}
		assertStaticOAuthCallbackLeftNoCredentials(t, gateway, provider, state, types.MCPStaticOAuthTestFailureInterrupted)
	})
}

// staticOAuthCallbackInFlight starts a callback and returns once it is blocked inside the
// provider token exchange, with its claim already recorded.
func staticOAuthCallbackInFlight(t *testing.T, gateway *gatewayclient.Client, callbackState string, tokenExchangeStarted <-chan struct{}) <-chan error {
	t.Helper()
	req := api.Context{
		Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+callbackState+"&code=valid-code", nil),
		ResponseWriter: httptest.NewRecorder(),
	}
	h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
	handled := make(chan error, 1)
	go func() { handled <- h.oauthCallback(req) }()
	select {
	case <-tokenExchangeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not reach provider token exchange")
	}
	return handled
}

func awaitStaticOAuthCallback(t *testing.T, handled <-chan error) error {
	t.Helper()
	select {
	case err := <-handled:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not return after the provider responded")
		return nil
	}
}

func assertStaticOAuthCallbackLeftNoCredentials(t *testing.T, gateway *gatewayclient.Client, provider staticOAuthCallbackProvider, state gatewayclient.MCPStaticOAuthTestStart, wantFailure types.MCPStaticOAuthTestFailureCategory) {
	t.Helper()
	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "entry-1")
	if err != nil {
		t.Fatalf("get static OAuth result: %v", err)
	}
	if result.Status != types.MCPStaticOAuthTestStatusFailed || result.FailureCategory != wantFailure {
		t.Fatalf("callback result = %+v, want failed %q", result, wantFailure)
	}
	if result.Proof != "" {
		t.Fatalf("unpersisted completion minted a save proof: %+v", result)
	}
	if _, err := gateway.GetMCPOAuthToken(t.Context(), "user-1", "entry-1", provider.URL+"/mcp"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("static OAuth callback persisted a user token: %v", err)
	}
}

func staticOAuthPendingStateTable(t *testing.T, db *gorm.DB) string {
	t.Helper()
	statement := &gorm.Statement{DB: db}
	if err := statement.Parse(&gatewaytypes.MCPOAuthPendingState{}); err != nil {
		t.Fatalf("resolve pending state table: %v", err)
	}
	return statement.Schema.Table
}

func TestStaticOAuthCallbackBoundsProviderTokenExchange(t *testing.T) {
	provider, _, releaseTokenExchange := newBlockingStaticOAuthCallbackProvider(t)
	defer releaseTokenExchange()
	original := staticOAuthTokenExchangeTimeout
	staticOAuthTokenExchangeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { staticOAuthTokenExchangeTimeout = original })

	gateway := newStaticOAuthCallbackGateway(t)
	state, err := gateway.CreateMCPStaticOAuthTest(t.Context(), "user-1", "entry-1", provider.URL+"/mcp", "exact-verifier", provider.config())
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	req := api.Context{
		Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state.CallbackState+"&code=valid-code", nil),
		ResponseWriter: httptest.NewRecorder(),
	}
	h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
	if err := h.oauthCallback(req); err != nil {
		t.Fatalf("handle stalled static OAuth callback: %v", err)
	}

	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "entry-1")
	if err != nil {
		t.Fatalf("get static OAuth result: %v", err)
	}
	if result.Status != types.MCPStaticOAuthTestStatusFailed || result.FailureCategory != types.MCPStaticOAuthTestFailureTokenExchange {
		t.Fatalf("stalled exchange result = %+v, want failed token exchange", result)
	}
	if _, err := gateway.GetMCPOAuthToken(t.Context(), "user-1", "entry-1", provider.URL+"/mcp"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("timed-out static OAuth callback persisted a user token: %v", err)
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
				Request:        httptest.NewRequest(http.MethodGet, "/oauth/mcp/callback?state="+state.CallbackState+tt.query, nil),
				ResponseWriter: recorder,
			}
			h := &handler{oauthChecker: &MCPOAuthHandlerFactory{stateMgr: newStateManager(gateway)}}
			if err := h.oauthCallback(req); err != nil {
				t.Fatalf("handle failed static OAuth callback: %v", err)
			}

			result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "entry-1")
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
	tokenExchanges *atomic.Int32
}

func newStaticOAuthCallbackProvider(t *testing.T) staticOAuthCallbackProvider {
	t.Helper()
	return newStaticOAuthCallbackProviderWithGate(t, nil, nil)
}

func newBlockingStaticOAuthCallbackProvider(t *testing.T) (staticOAuthCallbackProvider, <-chan struct{}, func()) {
	t.Helper()
	started := make(chan struct{}, 2)
	proceed := make(chan struct{})
	var release sync.Once
	return newStaticOAuthCallbackProviderWithGate(t, started, proceed), started, func() {
		release.Do(func() { close(proceed) })
	}
}

func newStaticOAuthCallbackProviderWithGate(t *testing.T, started chan<- struct{}, proceed <-chan struct{}) staticOAuthCallbackProvider {
	t.Helper()
	tokenExchanges := new(atomic.Int32)
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
		tokenExchanges.Add(1)
		if started != nil {
			started <- struct{}{}
			<-proceed
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
	return staticOAuthCallbackProvider{Server: server, tokenExchanges: tokenExchanges}
}

func (p staticOAuthCallbackProvider) tokenExchangeCount() int32 {
	return p.tokenExchanges.Load()
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
	client, _ := newStaticOAuthCallbackGatewayWithDB(t)
	return client
}

func newStaticOAuthCallbackGatewayWithDB(t *testing.T) (*gatewayclient.Client, *gorm.DB) {
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
	return gatewayclient.New(t.Context(), database, nil, staticOAuthTestEncryptionConfig(), nil, nil, nil, time.Hour, 10, 0, 0, 0, false), services.DB.DB
}

func staticOAuthTestEncryptionConfig() *encryptionconfig.EncryptionConfiguration {
	transformer := staticOAuthTestTransformer{}
	return &encryptionconfig.EncryptionConfiguration{Transformers: map[schema.GroupResource]value.Transformer{
		{Group: "obot.obot.ai", Resource: "credentials"}:           transformer,
		{Group: "obot.obot.ai", Resource: "mcpoauthpendingstates"}: transformer,
		{Group: "obot.obot.ai", Resource: "mcpoauthtokens"}:        transformer,
	}}
}

type staticOAuthTestTransformer struct{}

func (staticOAuthTestTransformer) TransformToStorage(_ context.Context, data []byte, _ value.Context) ([]byte, error) {
	return append([]byte("encrypted:"), data...), nil
}

func (staticOAuthTestTransformer) TransformFromStorage(_ context.Context, data []byte, _ value.Context) ([]byte, bool, error) {
	return []byte(strings.TrimPrefix(string(data), "encrypted:")), false, nil
}
