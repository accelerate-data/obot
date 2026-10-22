package client

// Fork-only guarantee (fork #37, restored by VD-6903): a static OAuth save proof is
// spent exactly once, its credential lands with the exact tested application and a
// generation receipt, a failed mutation leaves the active application untouched,
// and a clear only removes the generation the caller reviewed. Kept in its own file
// so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	gwtypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/system"
	"gorm.io/gorm"
)

const (
	staticOAuthCommitInstance = "instance-1"
)

var (
	staticOAuthTestCredentialContext = system.MCPOAuthCredentialName(leaseTestEntry)
)

func newStaticOAuthCommitClient(t *testing.T) *Client {
	t.Helper()
	c := newTestClient(t)
	c.encryptionConfig = staticOAuthTestEncryption()
	return c
}

func seedActiveStaticOAuthCredential(t *testing.T, c *Client, generation string) {
	t.Helper()
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: staticOAuthTestCredentialContext,
		Name:    system.StaticOAuthCredentialName,
		Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret", "MCP_URL": staticOAuthTestURL, "GENERATION": generation},
	}); err != nil {
		t.Fatalf("seed active credential: %v", err)
	}
}

func seedStaticOAuthGrant(t *testing.T, c *Client) {
	t.Helper()
	if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: staticOAuthCommitInstance, UserID: leaseTestUser, URL: staticOAuthTestURL, CatalogEntryName: leaseTestEntry, AccessToken: "active-token",
	}).Error; err != nil {
		t.Fatalf("seed static OAuth grant: %v", err)
	}
}

func revealStaticOAuthTestCredential(t *testing.T, c *Client) map[string]string {
	t.Helper()
	credential, err := c.RevealCredential(t.Context(), []string{staticOAuthTestCredentialContext}, system.StaticOAuthCredentialName)
	if err != nil {
		t.Fatalf("reveal static OAuth credential: %v", err)
	}
	return credential.Secrets
}

func requireActiveStaticOAuthCredential(t *testing.T, c *Client) {
	t.Helper()
	if secrets := revealStaticOAuthTestCredential(t, c); secrets["CLIENT_ID"] != "active-client" || secrets["CLIENT_SECRET"] != "active-secret" {
		t.Fatalf("active credential changed: %#v", secrets)
	}
}

func execStaticOAuthSQL(t *testing.T, c *Client, statement string) {
	t.Helper()
	if err := c.db.WithContext(t.Context()).Exec(statement).Error; err != nil {
		t.Fatalf("exec %q: %v", statement, err)
	}
}

func TestCommitMCPStaticOAuthCredentialAtomicallyStoresAndConsumesExactProof(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	started, conf := createStaticOAuthTest(t, c)
	proof := completeSuccessfulStaticOAuthTest(t, c, started)

	if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, false); err != nil {
		t.Fatalf("commit initial static OAuth credential: %v", err)
	}
	secrets := revealStaticOAuthTestCredential(t, c)
	if secrets["CLIENT_ID"] != conf.ClientID || secrets["CLIENT_SECRET"] != conf.ClientSecret || secrets["MCP_URL"] != staticOAuthTestURL {
		t.Fatalf("committed credential = %#v", secrets)
	}
	if secrets["GENERATION"] != hashMCPStaticOAuthValue(proof) {
		t.Fatalf("committed credential generation = %q, want the proof receipt", secrets["GENERATION"])
	}
	if _, err := c.GetMCPOAuthPendingState(t.Context(), started.CallbackState); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("committed proof remained usable: %v", err)
	}
}

// Claim and commit run in separate transactions: the claim spends the proof
// whatever happens next, so a mismatched or failed save can never be replayed,
// and the commit either lands whole or leaves the active application as it was.
func TestCommitMCPStaticOAuthCredentialConsumesProofBeforeAtomicMutation(t *testing.T) {
	t.Run("mismatched proof never writes", func(t *testing.T) {
		c := newStaticOAuthCommitClient(t)
		proof, conf := createStaticOAuthProof(t, c)

		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, "changed-client", conf.ClientSecret, false); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("mismatched proof error = %v, want invalid test", err)
		}
		if _, err := c.RevealCredential(t.Context(), []string{staticOAuthTestCredentialContext}, system.StaticOAuthCredentialName); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("mismatched proof wrote credential: %v", err)
		}
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, false); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("mismatched attempt left proof reusable: %v", err)
		}
	})

	t.Run("initial commit rejects existing credential and consumes proof", func(t *testing.T) {
		c := newStaticOAuthCommitClient(t)
		seedActiveStaticOAuthCredential(t, c, "generation-1")
		proof, conf := createStaticOAuthProof(t, c)

		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, false); !errors.Is(err, ErrMCPStaticOAuthCredentialExists) {
			t.Fatalf("initial commit error = %v, want credential exists", err)
		}
		requireActiveStaticOAuthCredential(t, c)
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("existing-credential rejection left proof reusable: %v", err)
		}
	})

	t.Run("replacement upsert failure preserves old credential and consumes proof", func(t *testing.T) {
		c := newStaticOAuthCommitClient(t)
		seedActiveStaticOAuthCredential(t, c, "generation-1")
		proof, conf := createStaticOAuthProof(t, c)
		execStaticOAuthSQL(t, c, `CREATE TRIGGER fail_oauth_credential_update BEFORE UPDATE ON credentials BEGIN SELECT RAISE(FAIL, 'injected credential write failure'); END`)

		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true); err == nil {
			t.Fatal("replacement succeeded despite injected upsert failure")
		}
		execStaticOAuthSQL(t, c, `DROP TRIGGER fail_oauth_credential_update`)
		requireActiveStaticOAuthCredential(t, c)
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("failed upsert left proof reusable: %v", err)
		}
	})

	// The proof is spent in the claim transaction, so a failure to delete it aborts
	// the save before any credential write and leaves the proof for a retry.
	t.Run("proof delete failure aborts before any write", func(t *testing.T) {
		c := newStaticOAuthCommitClient(t)
		seedActiveStaticOAuthCredential(t, c, "generation-1")
		proof, conf := createStaticOAuthProof(t, c)
		execStaticOAuthSQL(t, c, `CREATE TRIGGER fail_static_proof_delete BEFORE DELETE ON mcpo_auth_pending_states BEGIN SELECT RAISE(FAIL, 'injected proof delete failure'); END`)

		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true); err == nil {
			t.Fatal("replacement succeeded despite injected proof delete failure")
		}
		execStaticOAuthSQL(t, c, `DROP TRIGGER fail_static_proof_delete`)
		requireActiveStaticOAuthCredential(t, c)
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true); err != nil {
			t.Fatalf("aborted claim consumed the proof: %v", err)
		}
	})

	t.Run("token delete failure rolls back replacement and consumes proof", func(t *testing.T) {
		c := newStaticOAuthCommitClient(t)
		seedActiveStaticOAuthCredential(t, c, "generation-1")
		seedStaticOAuthGrant(t, c)
		proof, conf := createStaticOAuthProof(t, c)
		execStaticOAuthSQL(t, c, `CREATE TRIGGER fail_static_token_delete BEFORE DELETE ON mcpo_auth_tokens BEGIN SELECT RAISE(FAIL, 'injected token delete failure'); END`)

		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true, staticOAuthCommitInstance); err == nil {
			t.Fatal("replacement succeeded despite injected token delete failure")
		}
		execStaticOAuthSQL(t, c, `DROP TRIGGER fail_static_token_delete`)
		requireActiveStaticOAuthCredential(t, c)
		if _, err := c.GetMCPOAuthToken(t.Context(), leaseTestUser, staticOAuthCommitInstance, staticOAuthTestURL); err != nil {
			t.Fatalf("active grant was deleted despite rollback: %v", err)
		}
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true, staticOAuthCommitInstance); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("token-delete rollback left proof reusable: %v", err)
		}
	})
}

// A second successful test for the same entry was approved against the
// application that has just been replaced, so it must not be saveable afterwards.
func TestCommitMCPStaticOAuthCredentialInvalidatesSiblingProofs(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	seedActiveStaticOAuthCredential(t, c, "generation-1")
	first, conf := createStaticOAuthTest(t, c)
	second, _ := createStaticOAuthTest(t, c)
	firstProof := completeSuccessfulStaticOAuthTest(t, c, first)
	secondProof := completeSuccessfulStaticOAuthTest(t, c, second)

	if err := c.commitMCPStaticOAuthCredential(t.Context(), firstProof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true); err != nil {
		t.Fatalf("commit replacement: %v", err)
	}
	if _, err := c.GetMCPStaticOAuthTestStatus(t.Context(), second.TestState, leaseTestUser, leaseTestEntry); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
		t.Fatalf("sibling test status error = %v, want invalid", err)
	}
	if err := c.commitMCPStaticOAuthCredential(t.Context(), secondProof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
		t.Fatalf("sibling proof saved after replacement: %v", err)
	}
}

func TestCommitMCPStaticOAuthCredentialAllowsOneConcurrentWinner(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	proof, conf := createStaticOAuthProof(t, c)

	const attempts = 8
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			<-start
			release, err := c.AcquireCredentialLock(t.Context(), staticOAuthTestCredentialContext)
			if err != nil {
				results <- err
				return
			}
			defer release()
			results <- c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, false)
		})
	}
	close(start)
	wg.Wait()
	close(results)

	var successes int
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("concurrent commit error = %v, want invalid test", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent commit successes = %d, want exactly 1", successes)
	}
	if secrets := revealStaticOAuthTestCredential(t, c); secrets["CLIENT_ID"] != conf.ClientID || secrets["CLIENT_SECRET"] != conf.ClientSecret {
		t.Fatalf("winning credential = %#v", secrets)
	}
}

func TestDeleteMCPStaticOAuthCredentialGenerationRejectsStaleClear(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	seedActiveStaticOAuthCredential(t, c, "generation-2")
	seedStaticOAuthGrant(t, c)

	if _, err := c.DeleteMCPStaticOAuthCredentialGeneration(t.Context(), leaseTestEntry, "generation-1", staticOAuthCommitInstance); !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
		t.Fatalf("stale clear error = %v, want catalog credential changed", err)
	}
	if secrets := revealStaticOAuthTestCredential(t, c); secrets["GENERATION"] != "generation-2" {
		t.Fatalf("stale clear changed the current credential: %#v", secrets)
	}
	if _, err := c.GetMCPOAuthToken(t.Context(), leaseTestUser, staticOAuthCommitInstance, staticOAuthTestURL); err != nil {
		t.Fatalf("stale clear removed the current grant: %v", err)
	}
}

// The first clear removes the rows before its notification fails, so the retry
// finds nothing to delete and must still notify the deployment it was given.
func TestDeleteMCPStaticOAuthCredentialRetriesCleanupNotificationsAfterRowsAreGone(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	seedActiveStaticOAuthCredential(t, c, "generation-1")
	seedStaticOAuthGrant(t, c)

	var triggered []string
	failNotification := true
	c.mcpOAuthTokenTrigger = func(_ context.Context, mcpID string) error {
		triggered = append(triggered, mcpID)
		if failNotification {
			failNotification = false
			return errors.New("injected notification failure")
		}
		return nil
	}

	if _, err := c.DeleteMCPStaticOAuthCredentialGeneration(t.Context(), leaseTestEntry, "generation-1", staticOAuthCommitInstance); err == nil {
		t.Fatal("first clear succeeded despite injected notification failure")
	}
	if _, err := c.DeleteMCPStaticOAuthCredentialGeneration(t.Context(), leaseTestEntry, "generation-1", staticOAuthCommitInstance); err != nil {
		t.Fatalf("retry static OAuth clear: %v", err)
	}
	if !slices.Equal(triggered, []string{staticOAuthCommitInstance, staticOAuthCommitInstance}) {
		t.Fatalf("cleanup notifications = %v, want a retry for %q", triggered, staticOAuthCommitInstance)
	}
}
