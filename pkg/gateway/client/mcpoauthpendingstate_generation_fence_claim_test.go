package client

// Fork-only guarantee (fork #37, restored by VD-6903): an authorization for a
// static-OAuth-only catalog entry starts only against a complete, current credential
// and records its generation, and a callback for such an entry never commits a grant
// that lacks that generation. Kept in its own file so an upstream sync cannot drop
// these tests by merging over a shared one.

import (
	"errors"
	"testing"

	"github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestCreateMCPOAuthPendingStateRejectsIncompleteStaticCredential(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secrets map[string]string
	}{
		{name: "credential bound to another catalog URL", secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-1", "MCP_URL": "https://old-mcp.example/api", "GENERATION": "generation-1"}},
		{name: "credential without catalog URL", secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-1", "GENERATION": "generation-1"}},
		{name: "credential without generation", secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-1", "MCP_URL": fenceTestURL}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFenceTestClient(t, true)
			seedFenceTestCredential(t, c, fenceTestEntry, tc.secrets)

			err := c.CreateMCPOAuthPendingState(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL, "request-1", fenceTestEntry, "state-1", "verifier-1", "", &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"})
			if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
				t.Fatalf("create pending state error = %v, want catalog credential changed", err)
			}
			if _, err := c.GetMCPOAuthPendingState(t.Context(), "state-1"); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("pending state was stored for an incomplete credential: %v", err)
			}
		})
	}
}

func createFenceTestPendingState(t *testing.T, c *Client, catalogEntryName, state string) (*types.MCPOAuthPendingState, *oauth2.Config) {
	t.Helper()
	conf := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}
	if err := c.CreateMCPOAuthPendingState(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL, "request-1", catalogEntryName, state, "verifier", "", conf); err != nil {
		t.Fatalf("create pending state: %v", err)
	}
	pending, err := c.GetMCPOAuthPendingState(t.Context(), state)
	if err != nil {
		t.Fatalf("load pending state: %v", err)
	}
	return pending, conf
}

func setFenceTestStaticOAuthRequired(t *testing.T, c *Client, required bool) {
	t.Helper()
	var entry v1.MCPServerCatalogEntry
	if err := c.storageClient.Get(t.Context(), kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: fenceTestEntry}, &entry); err != nil {
		t.Fatalf("get catalog entry: %v", err)
	}
	entry.Spec.Manifest.RemoteConfig.StaticOAuthRequired = required
	if err := c.storageClient.Update(t.Context(), &entry); err != nil {
		t.Fatalf("update catalog entry: %v", err)
	}
}

func requireRejectedPendingCommit(t *testing.T, c *Client, pending *types.MCPOAuthPendingState, conf *oauth2.Config, state string) {
	t.Helper()
	err := c.CommitMCPOAuthPendingStateToken(t.Context(), pending, pending.OAuthAuthRequestID, conf, &oauth2.Token{AccessToken: "stale-access"})
	if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
		t.Fatalf("commit error = %v, want catalog credential changed", err)
	}
	requireNoFenceTestGrant(t, c)
	if _, err := c.GetMCPOAuthPendingState(t.Context(), state); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("rejected pending state remains: %v", err)
	}
}

func TestCommitMCPOAuthPendingStateTokenFencesStaticOnlyEntries(t *testing.T) {
	t.Run("legacy pending state without an entry is rejected and deleted", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))
		pending, conf := createFenceTestPendingState(t, c, "", "legacy-state")
		requireRejectedPendingCommit(t, c, pending, conf, "legacy-state")
	})

	// A pending row written before entries were recorded must still complete for an
	// entry that allows dynamic OAuth, even when the user holds no grant yet to
	// recover the entry from.
	t.Run("legacy pending state for an optional entry commits without an existing grant", func(t *testing.T) {
		c := newFenceTestClient(t, false)
		pending, conf := createFenceTestPendingState(t, c, "", "legacy-dynamic")
		requireNoFenceTestGrant(t, c)
		if err := c.CommitMCPOAuthPendingStateToken(t.Context(), pending, pending.OAuthAuthRequestID, conf, &oauth2.Token{AccessToken: "legacy-access"}); err != nil {
			t.Fatalf("commit legacy dynamic grant: %v", err)
		}
		stored, err := c.GetMCPOAuthToken(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL)
		if err != nil {
			t.Fatalf("load legacy dynamic grant: %v", err)
		}
		if stored.AccessToken != "legacy-access" || stored.CatalogEntryName != "" || stored.CatalogCredentialGeneration != "" {
			t.Fatalf("legacy dynamic grant = access %q entry %q generation %q", stored.AccessToken, stored.CatalogEntryName, stored.CatalogCredentialGeneration)
		}
	})

	// An authorization started while the entry allowed dynamic OAuth carries the
	// entry but no generation; once the entry requires static OAuth that grant could
	// not be revoked by any credential change, so the callback must refuse it.
	t.Run("dynamic pending state is rejected after the entry becomes static-only", func(t *testing.T) {
		c := newFenceTestClient(t, false)
		pending, conf := createFenceTestPendingState(t, c, fenceTestEntry, "dynamic-state")
		if pending.CatalogEntryName != fenceTestEntry || pending.CatalogCredentialGeneration != "" {
			t.Fatalf("dynamic pending state = entry %q generation %q", pending.CatalogEntryName, pending.CatalogCredentialGeneration)
		}
		setFenceTestStaticOAuthRequired(t, c, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))
		requireRejectedPendingCommit(t, c, pending, conf, "dynamic-state")
	})

	t.Run("dynamic pending state for an optional entry commits", func(t *testing.T) {
		c := newFenceTestClient(t, false)
		pending, conf := createFenceTestPendingState(t, c, fenceTestEntry, "dynamic-state")
		if err := c.CommitMCPOAuthPendingStateToken(t.Context(), pending, pending.OAuthAuthRequestID, conf, &oauth2.Token{AccessToken: "dynamic-access"}); err != nil {
			t.Fatalf("commit dynamic grant: %v", err)
		}
		stored, err := c.GetMCPOAuthToken(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL)
		if err != nil {
			t.Fatalf("load dynamic grant: %v", err)
		}
		if stored.AccessToken != "dynamic-access" || stored.CatalogCredentialGeneration != "" {
			t.Fatalf("dynamic grant = access %q generation %q", stored.AccessToken, stored.CatalogCredentialGeneration)
		}
		if _, err := c.GetMCPOAuthPendingState(t.Context(), "dynamic-state"); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("committed pending state remains: %v", err)
		}
	})

	t.Run("static pending state commits with its generation", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))
		pending, conf := createFenceTestPendingState(t, c, fenceTestEntry, "static-state")
		if err := c.CommitMCPOAuthPendingStateToken(t.Context(), pending, pending.OAuthAuthRequestID, conf, &oauth2.Token{AccessToken: "static-access"}); err != nil {
			t.Fatalf("commit static grant: %v", err)
		}
		stored, err := c.GetMCPOAuthToken(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL)
		if err != nil {
			t.Fatalf("load static grant: %v", err)
		}
		if stored.CatalogEntryName != fenceTestEntry || stored.CatalogCredentialGeneration != "generation-1" {
			t.Fatalf("static grant = entry %q generation %q", stored.CatalogEntryName, stored.CatalogCredentialGeneration)
		}
	})
}
