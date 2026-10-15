package oauth

// Fork-only guarantee (VD-4888, restored by VD-6886): a downstream OAuth
// callback state is claimed before its code is exchanged, so a replayed,
// concurrent, or expired callback never reaches the provider. Kept in its own
// file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

type blockingTokenServer struct {
	*httptest.Server
	exchanges atomic.Int32
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
}

// newBlockingTokenServer holds every token request until release is closed, so
// a test can keep the first exchange in flight while a second callback races it.
func newBlockingTokenServer(t *testing.T) *blockingTokenServer {
	t.Helper()
	s := &blockingTokenServer{started: make(chan struct{}, 8), release: make(chan struct{})}
	s.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		s.exchanges.Add(1)
		s.started <- struct{}{}
		<-s.release
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
	}))
	t.Cleanup(func() {
		s.releaseAll()
		s.Close()
	})
	return s
}

func (s *blockingTokenServer) releaseAll() { s.once.Do(func() { close(s.release) }) }

func storeDynamicCallbackState(t *testing.T, gateway *gatewayclient.Client, tokenURL, state string) {
	t.Helper()
	conf := &oauth2.Config{
		ClientID:    "dynamic-client",
		RedirectURL: "https://obot.example/oauth/mcp/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://auth.example/authorize",
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	if err := newStateManager(gateway).store(t.Context(), "user", "mcp", "https://mcp.example/mcp", "", "", state, "pkce-verifier", "", conf); err != nil {
		t.Fatalf("store pending state: %v", err)
	}
}

func ageDynamicCallbackState(t *testing.T, database *gorm.DB, state string) {
	t.Helper()
	hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	if err := database.WithContext(t.Context()).Model(&gatewaytypes.MCPOAuthPendingState{}).
		Where("hashed_state = ?", hashedState).
		Update("created_at", time.Now().Add(-31*time.Minute)).Error; err != nil {
		t.Fatalf("age pending state: %v", err)
	}
}

func TestStateManagerCreateTokenConsumesStateExactlyOnce(t *testing.T) {
	t.Run("concurrent callbacks exchange the code once", func(t *testing.T) {
		provider := newBlockingTokenServer(t)
		gateway := newStaticOAuthCallbackGateway(t)
		storeDynamicCallbackState(t, gateway, provider.URL, "state")
		sm := newStateManager(gateway)

		winner := make(chan error, 1)
		go func() {
			_, _, err := sm.createToken(t.Context(), "state", "code", "", "")
			winner <- err
		}()
		select {
		case <-provider.started:
		case <-time.After(2 * time.Second):
			t.Fatal("first callback did not reach the provider token exchange")
		}

		// The first exchange is still in flight, so its row has not been deleted:
		// only the claim can stop this callback. The deadline makes a missing claim
		// fail fast instead of hanging on the held token server.
		raceCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		if _, _, err := sm.createToken(raceCtx, "state", "code", "", ""); !errors.Is(err, gatewayclient.ErrMCPOAuthPendingStateInvalid) {
			provider.releaseAll()
			t.Fatalf("concurrent callback returned %v, want invalid state", err)
		}

		provider.releaseAll()
		if err := <-winner; err != nil {
			t.Fatalf("claim winner: %v", err)
		}
		if got := provider.exchanges.Load(); got != 1 {
			t.Fatalf("provider token exchanges = %d, want exactly 1", got)
		}
	})

	t.Run("replay after success is rejected without an exchange", func(t *testing.T) {
		provider := newBlockingTokenServer(t)
		provider.releaseAll()
		gateway := newStaticOAuthCallbackGateway(t)
		storeDynamicCallbackState(t, gateway, provider.URL, "state")
		sm := newStateManager(gateway)

		if _, _, err := sm.createToken(t.Context(), "state", "code", "", ""); err != nil {
			t.Fatalf("first callback: %v", err)
		}
		if _, _, err := sm.createToken(t.Context(), "state", "code", "", ""); err == nil {
			t.Fatal("replayed callback succeeded, want rejection")
		}
		if got := provider.exchanges.Load(); got != 1 {
			t.Fatalf("provider token exchanges = %d, want exactly 1", got)
		}
	})

	t.Run("expired state is rejected before cleanup runs", func(t *testing.T) {
		provider := newBlockingTokenServer(t)
		provider.releaseAll()
		gateway, database := newStaticOAuthCallbackGatewayWithDB(t)
		storeDynamicCallbackState(t, gateway, provider.URL, "state")
		ageDynamicCallbackState(t, database, "state")

		if _, _, err := newStateManager(gateway).createToken(t.Context(), "state", "code", "", ""); !errors.Is(err, gatewayclient.ErrMCPOAuthPendingStateInvalid) {
			t.Fatalf("expired callback returned %v, want invalid state", err)
		}
		if got := provider.exchanges.Load(); got != 0 {
			t.Fatalf("provider token exchanges = %d, want 0", got)
		}
	})
}

func TestPublicDynamicOAuthCallbackRejectsUnusableState(t *testing.T) {
	for _, tc := range []struct {
		name     string
		unusable func(t *testing.T, gateway *gatewayclient.Client, database *gorm.DB)
	}{
		{name: "expired", unusable: func(t *testing.T, _ *gatewayclient.Client, database *gorm.DB) {
			t.Helper()
			ageDynamicCallbackState(t, database, "callback-state")
		}},
		{name: "already claimed", unusable: func(t *testing.T, gateway *gatewayclient.Client, _ *gorm.DB) {
			t.Helper()
			if _, err := gateway.ClaimMCPOAuthPendingState(t.Context(), "callback-state"); err != nil {
				t.Fatalf("claim pending state: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := newBlockingTokenServer(t)
			provider.releaseAll()
			gateway, database := newStaticOAuthCallbackGatewayWithDB(t)
			storeDynamicCallbackState(t, gateway, provider.URL, "callback-state")
			tc.unusable(t, gateway, database)

			server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
			assertSafeStaticOAuthCallbackFailure(t, server, "/oauth/mcp/callback?state=callback-state&code=valid-code", http.StatusBadRequest, "callback-state", "valid-code")
			if got := provider.exchanges.Load(); got != 0 {
				t.Fatalf("provider token exchanges = %d, want 0", got)
			}
		})
	}
}
