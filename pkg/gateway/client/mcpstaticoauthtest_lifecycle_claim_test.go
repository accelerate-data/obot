package client

// Fork-only guarantee (fork #37, restored by VD-6903): a static OAuth credential
// test reports only a safe status to its owner, its callback is claimed exactly
// once inside the pending TTL, and expired or consumed tests leave nothing behind.
// Kept in its own file so an upstream sync cannot drop these tests by merging over
// a shared one.

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gwtypes "github.com/obot-platform/obot/pkg/gateway/types"
	"gorm.io/gorm"
)

func ageStaticOAuthTest(t *testing.T, c *Client, started MCPStaticOAuthTestStart) {
	t.Helper()
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
		Where("hashed_state = ?", hashMCPStaticOAuthValue(started.CallbackState)).
		Update("created_at", time.Now().Add(-pendingStateTTL-time.Second)).Error; err != nil {
		t.Fatalf("age static OAuth test: %v", err)
	}
}

func requireStaticOAuthTestExpiry(t *testing.T, c *Client, started MCPStaticOAuthTestStart, result apitypes.MCPStaticOAuthTestResult) {
	t.Helper()
	proof, err := c.GetMCPOAuthPendingState(t.Context(), started.CallbackState)
	if err != nil {
		t.Fatalf("read static OAuth test: %v", err)
	}
	if want := proof.CreatedAt.Add(pendingStateTTL); !result.ExpiresAt.Time.Equal(want) {
		t.Fatalf("expiry = %s, want %s", result.ExpiresAt, want)
	}
}

func TestMCPStaticOAuthTestLifecycleReturnsOnlySafeStatus(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		c := newTestClient(t)
		started, _ := createStaticOAuthTest(t, c)
		result := readLeaseTestStatus(t, c, started)
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusPending, "")
		requireStaticOAuthTestExpiry(t, c, started, result)
	})

	for _, tt := range []struct{ name, userID, mcpID string }{
		{name: "wrong caller", userID: "user-2", mcpID: leaseTestEntry},
		{name: "wrong entry", userID: leaseTestUser, mcpID: "catalog-entry-2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			started, _ := createStaticOAuthTest(t, c)
			result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), started.TestState, tt.userID, tt.mcpID)
			if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("read status returned %+v, %v; want invalid test", result, err)
			}
		})
	}

	t.Run("succeeded", func(t *testing.T) {
		c := newTestClient(t)
		started, _ := createStaticOAuthTest(t, c)
		completeSuccessfulStaticOAuthTest(t, c, started)
		result := readLeaseTestStatus(t, c, started)
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusSucceeded, "")
		requireStaticOAuthTestExpiry(t, c, started, result)
		proof, err := c.GetMCPOAuthPendingState(t.Context(), started.CallbackState)
		if err != nil {
			t.Fatalf("read completed test: %v", err)
		}
		if proof.StaticOAuthTestCompletedAt.IsZero() {
			t.Fatal("expected successful test completion time")
		}
	})

	t.Run("failed", func(t *testing.T) {
		c := newTestClient(t)
		started, _ := createStaticOAuthTest(t, c)
		if err := c.CompleteMCPStaticOAuthTest(t.Context(), started.CallbackState, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureTokenExchange); err != nil {
			t.Fatalf("complete failed test: %v", err)
		}
		result := readLeaseTestStatus(t, c, started)
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureTokenExchange)
		requireStaticOAuthTestExpiry(t, c, started, result)
		if result.Proof != "" {
			t.Fatalf("failed test minted a save proof: %+v", result)
		}
	})

	t.Run("expired", func(t *testing.T) {
		c := newTestClient(t)
		started, _ := createStaticOAuthTest(t, c)
		ageStaticOAuthTest(t, c, started)
		result := readLeaseTestStatus(t, c, started)
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureExpired)
		if result.ExpiresAt.IsZero() || !result.ExpiresAt.Time.Before(time.Now()) {
			t.Fatalf("expired test expiry = %s, want an authoritative past timestamp", result.ExpiresAt)
		}
	})
}

func TestGetMCPStaticOAuthTestStatusTreatsUnknownConsumedAndCleanedProofsAsInvalid(t *testing.T) {
	for _, tt := range []struct {
		name    string
		prepare func(t *testing.T, c *Client) string
	}{
		{name: "unknown", prepare: func(*testing.T, *Client) string { return "unknown-proof" }},
		{name: "consumed", prepare: func(t *testing.T, c *Client) string {
			t.Helper()
			started, conf := createStaticOAuthTest(t, c)
			proof := completeSuccessfulStaticOAuthTest(t, c, started)
			if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, false); err != nil {
				t.Fatalf("commit proof: %v", err)
			}
			return started.TestState
		}},
		{name: "cleaned", prepare: func(t *testing.T, c *Client) string {
			t.Helper()
			started, _ := createStaticOAuthTest(t, c)
			if err := c.CleanupExpiredMCPOAuthPendingStates(t.Context(), 0); err != nil {
				t.Fatalf("clean up test: %v", err)
			}
			return started.TestState
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			testState := tt.prepare(t, c)
			result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), testState, leaseTestUser, leaseTestEntry)
			if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("status = %+v, %v; want invalid test", result, err)
			}
		})
	}
}

func TestClaimMCPStaticOAuthTestEnforcesTTLAndExactlyOnce(t *testing.T) {
	t.Run("exactly once", func(t *testing.T) {
		c := newTestClient(t)
		started, conf := createStaticOAuthTest(t, c)

		const attempts = 8
		start := make(chan struct{})
		results := make(chan error, attempts)
		var wg sync.WaitGroup
		for range attempts {
			wg.Go(func() {
				<-start
				claimed, err := c.ClaimMCPStaticOAuthTest(t.Context(), started.CallbackState)
				if err == nil && (claimed.ClientID != conf.ClientID || claimed.ClientSecret != conf.ClientSecret) {
					err = errors.New("claimed test did not carry the candidate credentials")
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
			} else if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("claim test: %v", err)
			}
		}
		if claimed != 1 {
			t.Fatalf("successful claims = %d, want exactly 1", claimed)
		}
		assertStaticOAuthTestResult(t, readLeaseTestStatus(t, c, started), apitypes.MCPStaticOAuthTestStatusPending, "")
	})

	t.Run("expired row remains unclaimed", func(t *testing.T) {
		c := newTestClient(t)
		started, _ := createStaticOAuthTest(t, c)
		ageStaticOAuthTest(t, c, started)

		if _, err := c.ClaimMCPStaticOAuthTest(t.Context(), started.CallbackState); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("claim expired test returned %v, want invalid test", err)
		}
		if _, err := c.GetMCPOAuthPendingState(t.Context(), started.CallbackState); err != nil {
			t.Fatalf("expired test should remain until cleanup: %v", err)
		}
	})
}

// A provider error body can carry the authorization code, a token, or the client
// secret, so only the fixed failure categories may be recorded and the rejection
// must not repeat what it rejected.
func TestCompleteMCPStaticOAuthTestRejectsUnsafeFailureCategoryWithoutEchoingIt(t *testing.T) {
	c := newTestClient(t)
	started, conf := createStaticOAuthTest(t, c)
	unsafe := apitypes.MCPStaticOAuthTestFailureCategory("provider body=invalid_grant code=secret-code token=secret-token " + conf.ClientSecret)

	err := c.CompleteMCPStaticOAuthTest(t.Context(), started.CallbackState, apitypes.MCPStaticOAuthTestStatusFailed, unsafe)
	if err == nil {
		t.Fatal("expected unsafe failure category to be rejected")
	}
	for _, sensitive := range []string{conf.ClientID, conf.ClientSecret, "provider body", "secret-code", "secret-token"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("completion error exposed sensitive value %q: %q", sensitive, err)
		}
	}
	assertStaticOAuthTestResult(t, readLeaseTestStatus(t, c, started), apitypes.MCPStaticOAuthTestStatusPending, "")
}

func TestCleanupExpiredMCPOAuthPendingStatesRemovesPendingAndCompletedStaticOAuthTests(t *testing.T) {
	c := newTestClient(t)
	pending, _ := createStaticOAuthTest(t, c)
	completed, _ := createStaticOAuthTest(t, c)
	completeSuccessfulStaticOAuthTest(t, c, completed)
	live, _ := createStaticOAuthTest(t, c)
	for _, started := range []MCPStaticOAuthTestStart{pending, completed} {
		ageStaticOAuthTest(t, c, started)
	}

	if err := c.CleanupExpiredMCPOAuthPendingStates(t.Context(), pendingStateTTL); err != nil {
		t.Fatalf("clean up expired pending states: %v", err)
	}
	for _, started := range []MCPStaticOAuthTestStart{pending, completed} {
		if _, err := c.GetMCPOAuthPendingState(t.Context(), started.CallbackState); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("read cleaned up static OAuth test: %v", err)
		}
	}
	if _, err := c.GetMCPOAuthPendingState(t.Context(), live.CallbackState); err != nil {
		t.Fatalf("cleanup removed a live static OAuth test: %v", err)
	}
}

// Credential replacement and clearing delete by catalog entry on every save, so
// those lookups must stay index-backed rather than scanning every grant and test.
func TestStaticOAuthCleanupQueriesUseTargetedIndexes(t *testing.T) {
	c := newTestClient(t)
	for _, tt := range []struct {
		name, query, wantIndex string
		args                   []any
	}{
		{
			name:      "catalog grants",
			query:     "EXPLAIN QUERY PLAN SELECT mcp_id FROM mcpo_auth_tokens WHERE catalog_entry_name = ?",
			args:      []any{"entry-1"},
			wantIndex: "idx_mcp_oauth_token_catalog_entry",
		},
		{
			name:      "entry tests",
			query:     "EXPLAIN QUERY PLAN SELECT hashed_state FROM mcpo_auth_pending_states WHERE mcp_id = ? AND static_o_auth_test = ?",
			args:      []any{"entry-1", true},
			wantIndex: "idx_pending_mcp_static_test",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var plan []struct{ Detail string }
			if err := c.db.WithContext(t.Context()).Raw(tt.query, tt.args...).Scan(&plan).Error; err != nil {
				t.Fatalf("explain cleanup query: %v", err)
			}
			if !slices.ContainsFunc(plan, func(row struct{ Detail string }) bool { return strings.Contains(row.Detail, tt.wantIndex) }) {
				t.Fatalf("query plan %#v did not use %s", plan, tt.wantIndex)
			}
		})
	}
}
