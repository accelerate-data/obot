package handlers

// Fork-only guarantee (VD-4888, restored by VD-6886): the OAuth debugger's code
// exchange claims its pending state first, so a replayed or expired state is
// refused before the provider is contacted. Kept in its own file so an upstream
// sync cannot drop these tests by merging over a shared one.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	sservices "github.com/obot-platform/obot/pkg/storage/services"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newOAuthDebuggerClaimTestClient also returns the database, so a test can age
// a pending state past its TTL without waiting for it.
func newOAuthDebuggerClaimTestClient(t *testing.T) (*gateway.Client, *gorm.DB) {
	t.Helper()
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
	gatewayClient := gateway.New(t.Context(), db, clientfake.NewClientBuilder().Build(), nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { _ = gatewayClient.Close() })
	return gatewayClient, services.DB.DB
}

func TestClaimOAuthDebuggerPendingStateIsOneUseAndExpiring(t *testing.T) {
	const mcpID = "direct-mcp-server"
	conf := &oauth2.Config{
		ClientID: "dynamic-client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token"},
	}
	assertNotFound := func(t *testing.T, err error) {
		t.Helper()
		var httpErr *types.ErrHTTP
		if !errors.As(err, &httpErr) || httpErr.Code != 404 {
			t.Fatalf("claim returned %v, want 404 not found", err)
		}
	}

	t.Run("replay is refused", func(t *testing.T) {
		gatewayClient, _ := newOAuthDebuggerClaimTestClient(t)
		if err := gatewayClient.CreateMCPOAuthPendingState(t.Context(), "user-1", mcpID, "https://direct-mcp.example/api", OAuthDebuggerPendingStateMarker, "", "debugger-state", "verifier-1", "", conf); err != nil {
			t.Fatalf("create debugger pending state: %v", err)
		}
		pending, err := claimOAuthDebuggerPendingState(t.Context(), gatewayClient, "debugger-state")
		if err != nil {
			t.Fatalf("first claim: %v", err)
		}
		if pending.Verifier != "verifier-1" {
			t.Fatalf("claimed verifier = %q", pending.Verifier)
		}
		_, err = claimOAuthDebuggerPendingState(t.Context(), gatewayClient, "debugger-state")
		assertNotFound(t, err)
	})

	t.Run("expired state is refused", func(t *testing.T) {
		gatewayClient, database := newOAuthDebuggerClaimTestClient(t)
		if err := gatewayClient.CreateMCPOAuthPendingState(t.Context(), "user-1", mcpID, "https://direct-mcp.example/api", OAuthDebuggerPendingStateMarker, "", "debugger-state", "verifier-1", "", conf); err != nil {
			t.Fatalf("create debugger pending state: %v", err)
		}
		hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte("debugger-state")))
		if err := database.WithContext(t.Context()).Model(&gatewaytypes.MCPOAuthPendingState{}).
			Where("hashed_state = ?", hashedState).
			Update("created_at", time.Now().Add(-31*time.Minute)).Error; err != nil {
			t.Fatalf("age pending state: %v", err)
		}
		_, err := claimOAuthDebuggerPendingState(t.Context(), gatewayClient, "debugger-state")
		assertNotFound(t, err)
	})
}
