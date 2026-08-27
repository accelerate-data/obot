package oauth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

// TestPublicDynamicOAuthCallbackRejectsUnusableState covers the HTTP surface of the
// one-use claim: a dynamic state that is stale or already claimed must be refused
// with the same body as an unknown state, so the callback cannot be used to probe
// which states exist. The stale case never runs background cleanup — consumption
// itself has to enforce the creation-time cutoff.
func TestPublicDynamicOAuthCallbackRejectsUnusableState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		state   string
		degrade func(*testing.T, *gorm.DB, string)
	}{
		{
			name:  "stale state with cleanup never run",
			state: "stale-dynamic-state",
			degrade: func(t *testing.T, db *gorm.DB, hashedState string) {
				t.Helper()
				updateDynamicPendingState(t, db, hashedState, map[string]any{"created_at": time.Now().Add(-24 * time.Hour)})
			},
		},
		{
			name:  "state already claimed by an earlier callback",
			state: "claimed-dynamic-state",
			degrade: func(t *testing.T, db *gorm.DB, hashedState string) {
				t.Helper()
				updateDynamicPendingState(t, db, hashedState, map[string]any{"claimed_at": time.Now()})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway, db := newStaticOAuthCallbackGatewayWithDB(t)
			conf := &oauth2.Config{
				ClientID:     "dynamic-client-id",
				ClientSecret: "dynamic-client-secret",
				Endpoint:     oauth2.Endpoint{AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token"},
				RedirectURL:  "https://obot.example/oauth/mcp/callback",
			}
			if err := gateway.CreateMCPOAuthPendingState(t.Context(), "user-1", "mcp-instance-1", "https://provider.example/mcp", "request-1", "", tc.state, "pkce-verifier", conf); err != nil {
				t.Fatalf("create pending state: %v", err)
			}
			hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.state)))
			tc.degrade(t, db, hashedState)

			server := newUnauthenticatedStaticOAuthCallbackServer(t, gateway)
			assertSafeStaticOAuthCallbackFailure(t, server,
				"/oauth/mcp/callback?state="+tc.state+"&code=some-code",
				http.StatusBadRequest,
				tc.state, conf.ClientSecret, "pkce-verifier")

			if _, err := gateway.ClaimMCPOAuthPendingState(t.Context(), tc.state); err == nil {
				t.Fatal("refused callback left the state claimable")
			} else if !errors.Is(err, gatewayclient.ErrMCPOAuthPendingStateInvalid) {
				t.Fatalf("claim after refused callback = %v, want invalid pending state", err)
			}
		})
	}
}

func updateDynamicPendingState(t *testing.T, db *gorm.DB, hashedState string, values map[string]any) {
	t.Helper()
	result := db.WithContext(t.Context()).
		Model(&gatewaytypes.MCPOAuthPendingState{}).
		Where("hashed_state = ?", hashedState).
		Updates(values)
	if result.Error != nil {
		t.Fatalf("degrade pending state: %v", result.Error)
	}
	if result.RowsAffected != 1 {
		t.Fatalf("degrade pending state affected %d rows, want 1", result.RowsAffected)
	}
}
