package client

// Fork-only guarantee (VD-4888, restored by VD-6886): an OAuth callback state is
// one-use and expiring. These tests live in their own file, not in
// mcpoauthtoken_test.go, because upstream edits that file and an upstream sync
// once dropped the claim together with its tests.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/obot-platform/obot/pkg/gateway/types"
	"golang.org/x/oauth2"
)

func createDynamicOAuthPendingState(t *testing.T, c *Client, mcpURL, state string) *oauth2.Config {
	t.Helper()
	conf := &oauth2.Config{
		ClientID:     "dynamic-client-id",
		ClientSecret: "dynamic-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://provider.example/authorize",
			TokenURL:  "https://provider.example/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
	}
	if err := c.CreateMCPOAuthPendingState(t.Context(), "user-1", "mcp-instance-1", mcpURL, "request-1", "", state, "pkce-verifier", "", conf); err != nil {
		t.Fatalf("create pending state: %v", err)
	}
	return conf
}

func TestClaimMCPOAuthPendingStateEnforcesTTLAndExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mcpURL string
	}{
		{name: "dynamic", mcpURL: "https://mcp.example/api"},
		{name: "container", mcpURL: ContainerOAuthResourcePrefix + "deployment-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("exactly once", func(t *testing.T) {
				c := newTestClient(t)
				conf := createDynamicOAuthPendingState(t, c, tc.mcpURL, "callback-state")

				const attempts = 8
				start := make(chan struct{})
				results := make(chan error, attempts)
				var wg sync.WaitGroup
				for range attempts {
					wg.Go(func() {
						<-start
						ps, err := c.ClaimMCPOAuthPendingState(t.Context(), "callback-state")
						if err == nil && (ps.ClientID != conf.ClientID || ps.Verifier != "pkce-verifier") {
							err = errors.New("claimed state did not contain the stored exchange material")
						}
						results <- err
					})
				}
				close(start)
				wg.Wait()
				close(results)

				var claimed int
				for err := range results {
					if err == nil {
						claimed++
					} else if !errors.Is(err, ErrMCPOAuthPendingStateInvalid) {
						t.Fatalf("claim pending state: %v", err)
					}
				}
				if claimed != 1 {
					t.Fatalf("successful claims = %d, want exactly 1", claimed)
				}
			})

			t.Run("replay after a claim is rejected", func(t *testing.T) {
				c := newTestClient(t)
				createDynamicOAuthPendingState(t, c, tc.mcpURL, "callback-state")
				if _, err := c.ClaimMCPOAuthPendingState(t.Context(), "callback-state"); err != nil {
					t.Fatalf("first claim: %v", err)
				}
				if _, err := c.ClaimMCPOAuthPendingState(t.Context(), "callback-state"); !errors.Is(err, ErrMCPOAuthPendingStateInvalid) {
					t.Fatalf("replayed claim returned %v, want invalid state", err)
				}
			})

			t.Run("expired row is rejected and left for cleanup", func(t *testing.T) {
				c := newTestClient(t)
				createDynamicOAuthPendingState(t, c, tc.mcpURL, "callback-state")
				hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte("callback-state")))
				if err := c.db.WithContext(t.Context()).Model(&types.MCPOAuthPendingState{}).
					Where("hashed_state = ?", hashedState).
					Update("created_at", time.Now().Add(-pendingStateTTL-time.Second)).Error; err != nil {
					t.Fatalf("age pending state: %v", err)
				}

				// Background cleanup has deliberately not run: the cutoff must be
				// enforced by the claim itself.
				if _, err := c.ClaimMCPOAuthPendingState(t.Context(), "callback-state"); !errors.Is(err, ErrMCPOAuthPendingStateInvalid) {
					t.Fatalf("claim expired state returned %v, want invalid state", err)
				}
				ps, err := c.GetMCPOAuthPendingState(t.Context(), "callback-state")
				if err != nil {
					t.Fatalf("expired state should remain until cleanup: %v", err)
				}
				if ps.ClaimedAt != nil {
					t.Fatalf("expired state was claimed at %v, want unclaimed", *ps.ClaimedAt)
				}
			})

			t.Run("unknown state is rejected", func(t *testing.T) {
				c := newTestClient(t)
				if _, err := c.ClaimMCPOAuthPendingState(t.Context(), "never-issued"); !errors.Is(err, ErrMCPOAuthPendingStateInvalid) {
					t.Fatalf("claim unknown state returned %v, want invalid state", err)
				}
			})
		})
	}
}
