package client

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gwtypes "github.com/obot-platform/obot/pkg/gateway/types"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
)

func TestCreateMCPStaticOAuthTestStoresEncryptedPendingProof(t *testing.T) {
	c := newTestClient(t)
	c.encryptionConfig = &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			mcpOAuthPendingStateGroupResource: staticOAuthTestTransformer{},
		},
	}
	ctx := t.Context()
	conf := &oauth2.Config{
		ClientID:     "normalized-client-id",
		ClientSecret: "normalized-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://provider.example/authorize",
			TokenURL:  "https://provider.example/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
		Scopes:      []string{"channels:read", "chat:write"},
	}

	before := time.Now()
	state, err := c.CreateMCPStaticOAuthTest(ctx, "user-1", "catalog-entry-1", "https://mcp.example/api", "pkce-verifier", conf)
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	after := time.Now()
	if state == "" {
		t.Fatal("expected a random state")
	}
	secondState, err := c.CreateMCPStaticOAuthTest(ctx, "user-1", "catalog-entry-1", "https://mcp.example/api", "second-verifier", conf)
	if err != nil {
		t.Fatalf("create second static OAuth test: %v", err)
	}
	if secondState == state {
		t.Fatal("expected independently generated states")
	}

	hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	var stored gwtypes.MCPOAuthPendingState
	if err := c.db.WithContext(ctx).First(&stored, "hashed_state = ?", hashedState).Error; err != nil {
		t.Fatalf("load stored pending proof: %v", err)
	}
	if stored.HashedState != hashedState {
		t.Fatalf("stored hash = %q, want %q", stored.HashedState, hashedState)
	}
	if stored.State == state || stored.Verifier == "pkce-verifier" || stored.ClientID == conf.ClientID || stored.ClientSecret == conf.ClientSecret {
		t.Fatal("candidate proof data was stored in plaintext")
	}
	if stored.URL == "https://mcp.example/api" || stored.AuthURL == conf.Endpoint.AuthURL || stored.TokenURL == conf.Endpoint.TokenURL || stored.RedirectURL == conf.RedirectURL || stored.Scopes == "channels:read chat:write" {
		t.Fatal("provider-sensitive proof data was stored in plaintext")
	}
	if !stored.Encrypted {
		t.Fatal("expected pending proof to be marked encrypted")
	}

	proof, err := c.GetMCPOAuthPendingState(ctx, state)
	if err != nil {
		t.Fatalf("decrypt stored pending proof: %v", err)
	}
	if proof.State != state || proof.UserID != "user-1" || proof.MCPID != "catalog-entry-1" || proof.URL != "https://mcp.example/api" {
		t.Fatalf("stored proof identity = state %q user %q MCP %q URL %q", proof.State, proof.UserID, proof.MCPID, proof.URL)
	}
	if !proof.StaticOAuthTest {
		t.Fatal("expected static OAuth test marker")
	}
	if proof.Verifier != "pkce-verifier" || proof.ClientID != conf.ClientID || proof.ClientSecret != conf.ClientSecret {
		t.Fatalf("stored proof candidates = verifier %q client ID %q client secret %q", proof.Verifier, proof.ClientID, proof.ClientSecret)
	}
	if proof.AuthURL != conf.Endpoint.AuthURL || proof.TokenURL != conf.Endpoint.TokenURL || proof.AuthStyle != conf.Endpoint.AuthStyle || proof.RedirectURL != conf.RedirectURL || proof.Scopes != "channels:read chat:write" {
		t.Fatalf("stored OAuth config = %+v", proof)
	}
	if proof.StaticOAuthTestStatus != apitypes.MCPStaticOAuthTestStatusPending {
		t.Fatalf("stored status = %q, want pending", proof.StaticOAuthTestStatus)
	}
	if proof.CreatedAt.Before(before) || proof.CreatedAt.After(after) {
		t.Fatalf("created at = %s, want between %s and %s", proof.CreatedAt, before, after)
	}
}

func TestMCPStaticOAuthTestLifecycleReturnsOnlySafeStatus(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)

		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read pending status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusPending, "")
	})

	for _, tt := range []struct {
		name   string
		userID string
		mcpID  string
	}{
		{name: "wrong caller", userID: "user-2", mcpID: "catalog-entry-1"},
		{name: "wrong entry", userID: "user-1", mcpID: "catalog-entry-2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			state, _ := createStaticOAuthTest(t, c)

			result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state, tt.userID, tt.mcpID)
			if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("read status returned result %+v and error %v, want invalid proof", result, err)
			}
		})
	}

	t.Run("succeeded", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)

		if err := c.CompleteMCPStaticOAuthTest(t.Context(), state, apitypes.MCPStaticOAuthTestStatusSucceeded, ""); err != nil {
			t.Fatalf("complete successful test: %v", err)
		}
		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read succeeded status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusSucceeded, "")

		proof, err := c.GetMCPOAuthPendingState(t.Context(), state)
		if err != nil {
			t.Fatalf("read completed proof: %v", err)
		}
		if proof.StaticOAuthTestCompletedAt.IsZero() {
			t.Fatal("expected successful test completion time")
		}
	})

	t.Run("failed", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)

		if err := c.CompleteMCPStaticOAuthTest(t.Context(), state, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureTokenExchange); err != nil {
			t.Fatalf("complete failed test: %v", err)
		}
		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read failed status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureTokenExchange)
	})

	t.Run("expired", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)
		hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
		if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
			Where("hashed_state = ?", hashedState).
			Update("created_at", time.Now().Add(-pendingStateTTL-time.Second)).Error; err != nil {
			t.Fatalf("age pending proof: %v", err)
		}

		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read expired status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureExpired)
	})
}

func TestCompleteMCPStaticOAuthTestRejectsUnsafeFailureCategoryWithoutEchoingIt(t *testing.T) {
	c := newTestClient(t)
	state, conf := createStaticOAuthTest(t, c)
	unsafe := apitypes.MCPStaticOAuthTestFailureCategory("provider body=invalid_grant code=secret-code token=secret-token " + conf.ClientSecret)

	err := c.CompleteMCPStaticOAuthTest(t.Context(), state, apitypes.MCPStaticOAuthTestStatusFailed, unsafe)
	if err == nil {
		t.Fatal("expected unsafe failure category to be rejected")
	}
	for _, sensitive := range []string{conf.ClientID, conf.ClientSecret, "provider body", "secret-code", "secret-token"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("completion error exposed sensitive value %q: %q", sensitive, err)
		}
	}

	result, readErr := c.GetMCPStaticOAuthTestStatus(t.Context(), state, "user-1", "catalog-entry-1")
	if readErr != nil {
		t.Fatalf("read status after rejected completion: %v", readErr)
	}
	assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusPending, "")
}

func TestConsumeMCPStaticOAuthTestSucceedsExactlyOnce(t *testing.T) {
	c := newTestClient(t)
	state, conf := createStaticOAuthTest(t, c)
	if err := c.CompleteMCPStaticOAuthTest(t.Context(), state, apitypes.MCPStaticOAuthTestStatusSucceeded, ""); err != nil {
		t.Fatalf("complete successful test: %v", err)
	}

	const attempts = 8
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- c.ConsumeMCPStaticOAuthTest(t.Context(), state, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded int
	for err := range results {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("consume proof: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful consumptions = %d, want exactly 1", succeeded)
	}
	if _, err := c.GetMCPOAuthPendingState(t.Context(), state); err == nil {
		t.Fatal("expected consumed proof to be deleted")
	}
}

func TestConsumeMCPStaticOAuthTestRejectsMismatchedOrInvalidProof(t *testing.T) {
	tests := []struct {
		name     string
		prepare  func(t *testing.T, c *Client, state string)
		state    func(string) string
		userID   string
		mcpID    string
		mcpURL   string
		clientID string
		secret   string
	}{
		{name: "wrong state", state: func(string) string { return "wrong-state" }, userID: "user-1", mcpID: "catalog-entry-1", mcpURL: "https://mcp.example/api", clientID: "candidate-client-id", secret: "candidate-client-secret"},
		{name: "wrong caller", userID: "user-2", mcpID: "catalog-entry-1", mcpURL: "https://mcp.example/api", clientID: "candidate-client-id", secret: "candidate-client-secret"},
		{name: "wrong entry", userID: "user-1", mcpID: "catalog-entry-2", mcpURL: "https://mcp.example/api", clientID: "candidate-client-id", secret: "candidate-client-secret"},
		{name: "wrong fixed URL", userID: "user-1", mcpID: "catalog-entry-1", mcpURL: "https://other.example/api", clientID: "candidate-client-id", secret: "candidate-client-secret"},
		{name: "changed client ID", userID: "user-1", mcpID: "catalog-entry-1", mcpURL: "https://mcp.example/api", clientID: "changed-client-id", secret: "candidate-client-secret"},
		{name: "changed client secret", userID: "user-1", mcpID: "catalog-entry-1", mcpURL: "https://mcp.example/api", clientID: "candidate-client-id", secret: "changed-client-secret"},
		{
			name: "pending",
			prepare: func(t *testing.T, _ *Client, _ string) {
				t.Helper()
			},
			userID: "user-1", mcpID: "catalog-entry-1", mcpURL: "https://mcp.example/api", clientID: "candidate-client-id", secret: "candidate-client-secret",
		},
		{
			name: "failed",
			prepare: func(t *testing.T, c *Client, state string) {
				t.Helper()
				if err := c.CompleteMCPStaticOAuthTest(t.Context(), state, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureAuthorizationDenied); err != nil {
					t.Fatalf("complete failed test: %v", err)
				}
			},
			userID: "user-1", mcpID: "catalog-entry-1", mcpURL: "https://mcp.example/api", clientID: "candidate-client-id", secret: "candidate-client-secret",
		},
		{
			name: "expired",
			prepare: func(t *testing.T, c *Client, state string) {
				t.Helper()
				completeSuccessfulStaticOAuthTest(t, c, state)
				hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
				if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
					Where("hashed_state = ?", hashedState).
					Update("created_at", time.Now().Add(-pendingStateTTL-time.Second)).Error; err != nil {
					t.Fatalf("age completed proof: %v", err)
				}
			},
			userID: "user-1", mcpID: "catalog-entry-1", mcpURL: "https://mcp.example/api", clientID: "candidate-client-id", secret: "candidate-client-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			state, _ := createStaticOAuthTest(t, c)
			if tt.prepare == nil {
				completeSuccessfulStaticOAuthTest(t, c, state)
			} else {
				tt.prepare(t, c, state)
			}
			consumeState := state
			if tt.state != nil {
				consumeState = tt.state(state)
			}

			err := c.ConsumeMCPStaticOAuthTest(t.Context(), consumeState, tt.userID, tt.mcpID, tt.mcpURL, tt.clientID, tt.secret)
			if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("consume returned %v, want invalid proof", err)
			}

			if tt.name != "pending" && tt.name != "failed" && tt.name != "expired" {
				if err := c.ConsumeMCPStaticOAuthTest(t.Context(), state, "user-1", "catalog-entry-1", "https://mcp.example/api", "candidate-client-id", "candidate-client-secret"); err != nil {
					t.Fatalf("mismatched attempt consumed valid proof: %v", err)
				}
			}
		})
	}
}

func TestCleanupExpiredMCPOAuthPendingStatesRemovesPendingAndCompletedStaticOAuthTests(t *testing.T) {
	c := newTestClient(t)
	pendingState, _ := createStaticOAuthTest(t, c)
	completedState, _ := createStaticOAuthTest(t, c)
	completeSuccessfulStaticOAuthTest(t, c, completedState)

	cutoff := time.Now().Add(-pendingStateTTL - time.Second)
	for _, state := range []string{pendingState, completedState} {
		hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
		if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
			Where("hashed_state = ?", hashedState).
			Update("created_at", cutoff).Error; err != nil {
			t.Fatalf("age static OAuth test %q: %v", state, err)
		}
	}

	if err := c.CleanupExpiredMCPOAuthPendingStates(t.Context(), pendingStateTTL); err != nil {
		t.Fatalf("clean up expired pending states: %v", err)
	}
	for _, state := range []string{pendingState, completedState} {
		if _, err := c.GetMCPOAuthPendingState(t.Context(), state); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("read cleaned up static OAuth test %q: %v", state, err)
		}
	}
}

func TestDeleteMCPOAuthTokenForAllUsersTriggersServerReconciliation(t *testing.T) {
	c := newTestClient(t)
	triggered := 0
	c.mcpOAuthTokenTrigger = func(context.Context, string) error {
		triggered++
		return nil
	}
	conf := &oauth2.Config{ClientID: "client", ClientSecret: "secret"}
	if err := c.ReplaceMCPOAuthToken(t.Context(), "user-1", "server-1", "https://mcp.example/api", "", conf, &oauth2.Token{AccessToken: "token"}); err != nil {
		t.Fatalf("seed OAuth token: %v", err)
	}
	if triggered != 1 {
		t.Fatalf("Replace trigger count = %d, want 1", triggered)
	}
	triggered = 0

	if err := c.DeleteMCPOAuthTokenForAllUsers(t.Context(), "server-1"); err != nil {
		t.Fatalf("delete OAuth tokens: %v", err)
	}
	if triggered != 1 {
		t.Fatalf("Delete trigger count = %d, want 1", triggered)
	}
}

func completeSuccessfulStaticOAuthTest(t *testing.T, c *Client, state string) {
	t.Helper()
	if err := c.CompleteMCPStaticOAuthTest(t.Context(), state, apitypes.MCPStaticOAuthTestStatusSucceeded, ""); err != nil {
		t.Fatalf("complete successful test: %v", err)
	}
}

func createStaticOAuthTest(t *testing.T, c *Client) (string, *oauth2.Config) {
	t.Helper()
	conf := &oauth2.Config{
		ClientID:     "candidate-client-id",
		ClientSecret: "candidate-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://provider.example/authorize",
			TokenURL:  "https://provider.example/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
	}
	state, err := c.CreateMCPStaticOAuthTest(t.Context(), "user-1", "catalog-entry-1", "https://mcp.example/api", "pkce-verifier", conf)
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	return state, conf
}

func assertStaticOAuthTestResult(t *testing.T, result apitypes.MCPStaticOAuthTestResult, wantStatus apitypes.MCPStaticOAuthTestStatus, wantFailure apitypes.MCPStaticOAuthTestFailureCategory) {
	t.Helper()
	if result.Status != wantStatus || result.FailureCategory != wantFailure {
		t.Fatalf("result = %+v, want status %q failure %q", result, wantStatus, wantFailure)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, sensitive := range []string{"candidate-client-id", "candidate-client-secret", "pkce-verifier", "provider.example", "mcp.example", "secret-code", "secret-token"} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatalf("status result exposed sensitive value %q: %s", sensitive, encoded)
		}
	}
}

var _ value.Transformer = staticOAuthTestTransformer{}

type staticOAuthTestTransformer struct{}

func (staticOAuthTestTransformer) TransformToStorage(_ context.Context, data []byte, _ value.Context) ([]byte, error) {
	return append([]byte("encrypted:"), data...), nil
}

func (staticOAuthTestTransformer) TransformFromStorage(_ context.Context, data []byte, _ value.Context) ([]byte, bool, error) {
	return data[len("encrypted:"):], false, nil
}
