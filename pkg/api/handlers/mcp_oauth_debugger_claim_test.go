package handlers

// Fork-only guarantee (VD-4888, restored by VD-6886): the OAuth debugger's code
// exchange claims its pending state first, so a replayed or expired state is
// refused before the provider is contacted. Kept in its own file so an upstream
// sync cannot drop these tests by merging over a shared one.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/storage/scheme"
	sservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newOAuthDebuggerClaimTestClient mirrors newDirectOAuthDebuggerTestClient but
// also returns the database, so a test can age a pending state past its TTL.
func newOAuthDebuggerClaimTestClient(t *testing.T, mcpID string) (*gateway.Client, *gorm.DB) {
	t.Helper()
	storageClient := clientfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(&v1.MCPServer{Namespace: system.DefaultNamespace, Name: mcpID}).
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
	return gatewayClient, services.DB.DB
}

func TestClaimAndExchangeOAuthDebuggerTokenIsOneUseAndExpiring(t *testing.T) {
	const (
		mcpID  = "direct-mcp-server"
		mcpURL = "https://direct-mcp.example/api"
		state  = "debugger-state"
	)
	setup := func(t *testing.T) (*gateway.Client, *gorm.DB, *atomic.Int32) {
		t.Helper()
		var exchanges atomic.Int32
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			exchanges.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"access_token":"debugger-access","token_type":"Bearer"}`)
		}))
		t.Cleanup(provider.Close)
		gatewayClient, database := newOAuthDebuggerClaimTestClient(t, mcpID)
		conf := &oauth2.Config{
			ClientID: "dynamic-client",
			Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL},
		}
		if err := gatewayClient.CreateMCPOAuthPendingState(t.Context(), "user-1", mcpID, mcpURL, OAuthDebuggerPendingStateMarker, "", state, "verifier-1", "", conf); err != nil {
			t.Fatalf("create debugger pending state: %v", err)
		}
		return gatewayClient, database, &exchanges
	}
	assertNotFound := func(t *testing.T, err error) {
		t.Helper()
		var httpErr *types.ErrHTTP
		if !errors.As(err, &httpErr) || httpErr.Code != http.StatusNotFound {
			t.Fatalf("exchange returned %v, want 404 not found", err)
		}
	}

	t.Run("replay is refused without a second exchange", func(t *testing.T) {
		gatewayClient, _, exchanges := setup(t)
		if _, err := claimAndExchangeOAuthDebuggerToken(t.Context(), gatewayClient, state, "code-1", http.DefaultClient); err != nil {
			t.Fatalf("first exchange: %v", err)
		}
		_, err := claimAndExchangeOAuthDebuggerToken(t.Context(), gatewayClient, state, "code-1", http.DefaultClient)
		assertNotFound(t, err)
		if got := exchanges.Load(); got != 1 {
			t.Fatalf("provider token exchanges = %d, want exactly 1", got)
		}
	})

	t.Run("expired state is refused without an exchange", func(t *testing.T) {
		gatewayClient, database, exchanges := setup(t)
		hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
		if err := database.WithContext(t.Context()).Model(&gatewaytypes.MCPOAuthPendingState{}).
			Where("hashed_state = ?", hashedState).
			Update("created_at", time.Now().Add(-31*time.Minute)).Error; err != nil {
			t.Fatalf("age pending state: %v", err)
		}
		_, err := claimAndExchangeOAuthDebuggerToken(t.Context(), gatewayClient, state, "code-1", http.DefaultClient)
		assertNotFound(t, err)
		if got := exchanges.Load(); got != 0 {
			t.Fatalf("provider token exchanges = %d, want 0", got)
		}
	})
}

// The handler needs a live MCP session manager, so this pins its wiring
// instead: a merge that reverts it to the unclaimed exchange fails here.
func TestExchangeOAuthDebuggerTokenRoutesThroughTheClaim(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "mcp_oauth_debugger.go", nil, 0)
	if err != nil {
		t.Fatalf("parse handler source: %v", err)
	}
	calls := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ExchangeOAuthDebuggerToken" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok {
					calls[ident.Name] = true
				}
			}
			return true
		})
	}
	if !calls["claimAndExchangeOAuthDebuggerToken"] {
		t.Fatal("ExchangeOAuthDebuggerToken no longer calls claimAndExchangeOAuthDebuggerToken")
	}
	if calls["exchangeAndPersistOAuthDebuggerToken"] {
		t.Fatal("ExchangeOAuthDebuggerToken exchanges the code without claiming the state")
	}
}
