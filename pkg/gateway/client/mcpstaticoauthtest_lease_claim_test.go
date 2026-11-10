package client

// Fork-only guarantee (VD-4890, restored by VD-6903): an admitted static OAuth credential
// test callback holds its claim for a bounded lease. A lapsed claim is reported as
// an interrupted failure the user can retry at once, and a very late callback
// cannot complete it. Kept in its own file so an upstream sync cannot drop these
// tests by merging over a shared one.

import (
	"context"
	"errors"
	"testing"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/gateway/types"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
)

const (
	leaseTestUser  = "user-1"
	leaseTestEntry = "catalog-entry-1"
)

type leaseTestTransformer struct{}

func (leaseTestTransformer) TransformToStorage(_ context.Context, data []byte, _ value.Context) ([]byte, error) {
	return append([]byte("encrypted:"), data...), nil
}

func (leaseTestTransformer) TransformFromStorage(_ context.Context, data []byte, _ value.Context) ([]byte, bool, error) {
	return data[len("encrypted:"):], false, nil
}

func createLeaseTestStaticOAuthTest(t *testing.T, c *Client) MCPStaticOAuthTestStart {
	t.Helper()
	c.encryptionConfig = &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			mcpOAuthPendingStateGroupResource: leaseTestTransformer{},
		},
	}
	started, err := c.CreateMCPStaticOAuthTest(t.Context(), leaseTestUser, leaseTestEntry, "https://mcp.example/api", "pkce-verifier", &oauth2.Config{
		ClientID:     "candidate-client-id",
		ClientSecret: "candidate-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://provider.example/authorize",
			TokenURL:  "https://provider.example/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
	})
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	return started
}

func claimLeaseTestStaticOAuthTest(t *testing.T, c *Client, started MCPStaticOAuthTestStart) {
	t.Helper()
	if _, err := c.ClaimMCPStaticOAuthTest(t.Context(), started.CallbackState); err != nil {
		t.Fatalf("claim static OAuth test: %v", err)
	}
}

func setLeaseTestClaimedAt(t *testing.T, c *Client, started MCPStaticOAuthTestStart, claimedAt any) {
	t.Helper()
	if err := c.db.WithContext(t.Context()).Model(&types.MCPOAuthPendingState{}).
		Where("hashed_state = ?", hashMCPStaticOAuthValue(started.CallbackState)).
		Update("static_o_auth_test_claimed_at", claimedAt).Error; err != nil {
		t.Fatalf("rewrite claim time: %v", err)
	}
}

func readLeaseTestStatus(t *testing.T, c *Client, started MCPStaticOAuthTestStart) apitypes.MCPStaticOAuthTestResult {
	t.Helper()
	result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), started.TestState, leaseTestUser, leaseTestEntry)
	if err != nil {
		t.Fatalf("read static OAuth test status: %v", err)
	}
	return result
}

func requireLeaseTestResult(t *testing.T, result apitypes.MCPStaticOAuthTestResult, wantStatus apitypes.MCPStaticOAuthTestStatus, wantFailure apitypes.MCPStaticOAuthTestFailureCategory) {
	t.Helper()
	if result.Status != wantStatus || result.FailureCategory != wantFailure {
		t.Fatalf("result = %+v, want status %q failure %q", result, wantStatus, wantFailure)
	}
}

// The read side reports a claim with no recorded time as interrupted, so the claim
// must stamp status and lease timestamp in the same statement.
func TestClaimMCPStaticOAuthTestStampsLiveLease(t *testing.T) {
	c := newTestClient(t)
	started := createLeaseTestStaticOAuthTest(t, c)

	claimLeaseTestStaticOAuthTest(t, c, started)

	var pending types.MCPOAuthPendingState
	if err := c.db.WithContext(t.Context()).
		First(&pending, "hashed_state = ?", hashMCPStaticOAuthValue(started.CallbackState)).Error; err != nil {
		t.Fatalf("read claimed pending state: %v", err)
	}
	if pending.StaticOAuthTestClaimedAt == nil {
		t.Fatal("claim recorded no lease timestamp")
	}
	if age := time.Since(*pending.StaticOAuthTestClaimedAt); age < 0 || age > staticOAuthTestClaimLease {
		t.Fatalf("claim stamp age = %s, want a live stamp within the %s lease", age, staticOAuthTestClaimLease)
	}
	requireLeaseTestResult(t, readLeaseTestStatus(t, c, started), apitypes.MCPStaticOAuthTestStatusPending, "")
}

// The read and the write side share one lease, so a claim still inside it must
// remain completable while one aged past it is already interrupted and must not be
// completable. Wall-clock cannot pin the instant the lease expires, so the cases
// bracket it instead.
func TestStaticOAuthTestClaimLeaseFencesStatusAndCompletion(t *testing.T) {
	tests := []struct {
		name          string
		claimedAt     any
		wantStatus    apitypes.MCPStaticOAuthTestStatus
		wantFailure   apitypes.MCPStaticOAuthTestFailureCategory
		wantCompletes bool
	}{
		{
			name:          "claim inside the lease",
			claimedAt:     time.Now().Add(-staticOAuthTestClaimLease / 2),
			wantStatus:    apitypes.MCPStaticOAuthTestStatusPending,
			wantCompletes: true,
		},
		{
			name:        "claim aged past the lease",
			claimedAt:   time.Now().Add(-staticOAuthTestClaimLease - time.Second),
			wantStatus:  apitypes.MCPStaticOAuthTestStatusFailed,
			wantFailure: apitypes.MCPStaticOAuthTestFailureInterrupted,
		},
		{
			// A claim recorded before this column existed, or by a process that died
			// before it could stamp one, is by definition abandoned.
			name:        "claim without a recorded claim time",
			claimedAt:   nil,
			wantStatus:  apitypes.MCPStaticOAuthTestStatusFailed,
			wantFailure: apitypes.MCPStaticOAuthTestFailureInterrupted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			started := createLeaseTestStaticOAuthTest(t, c)
			claimLeaseTestStaticOAuthTest(t, c, started)
			setLeaseTestClaimedAt(t, c, started, tt.claimedAt)

			requireLeaseTestResult(t, readLeaseTestStatus(t, c, started), tt.wantStatus, tt.wantFailure)

			err := c.CompleteMCPStaticOAuthTest(t.Context(), started.CallbackState, apitypes.MCPStaticOAuthTestStatusSucceeded, "")
			if tt.wantCompletes {
				if err != nil {
					t.Fatalf("complete claim inside the lease: %v", err)
				}
				result := readLeaseTestStatus(t, c, started)
				requireLeaseTestResult(t, result, apitypes.MCPStaticOAuthTestStatusSucceeded, "")
				if result.Proof == "" {
					t.Fatal("completion inside the lease produced no save proof")
				}
				return
			}
			if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("complete abandoned claim returned %v, want invalid test", err)
			}
			result := readLeaseTestStatus(t, c, started)
			requireLeaseTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureInterrupted)
			if result.Proof != "" {
				t.Fatalf("rejected completion minted a save proof: %+v", result)
			}
		})
	}
}

// An interrupted test is terminal, so the user retries immediately with a fresh
// test rather than waiting out the pending-state TTL.
func TestStaticOAuthTestRetryAfterInterruptedClaimSucceeds(t *testing.T) {
	c := newTestClient(t)
	interrupted := createLeaseTestStaticOAuthTest(t, c)
	claimLeaseTestStaticOAuthTest(t, c, interrupted)
	setLeaseTestClaimedAt(t, c, interrupted, time.Now().Add(-staticOAuthTestClaimLease-time.Second))
	requireLeaseTestResult(t, readLeaseTestStatus(t, c, interrupted), apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureInterrupted)

	retry := createLeaseTestStaticOAuthTest(t, c)
	claimLeaseTestStaticOAuthTest(t, c, retry)

	if err := c.CompleteMCPStaticOAuthTest(t.Context(), retry.CallbackState, apitypes.MCPStaticOAuthTestStatusSucceeded, ""); err != nil {
		t.Fatalf("complete retried test: %v", err)
	}
	result := readLeaseTestStatus(t, c, retry)
	requireLeaseTestResult(t, result, apitypes.MCPStaticOAuthTestStatusSucceeded, "")
	if result.Proof == "" {
		t.Fatal("retried static OAuth test produced no save proof")
	}
}

// A lease reaching the pending-state TTL would leave an abandoned claim pending
// for as long as the row lives, which is the stuck state the lease removes.
func TestStaticOAuthTestClaimLeaseStaysBelowPendingTTL(t *testing.T) {
	if staticOAuthTestClaimLease >= pendingStateTTL {
		t.Fatalf("claim lease %s must be far below the pending-state TTL %s", staticOAuthTestClaimLease, pendingStateTTL)
	}
}
