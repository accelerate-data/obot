package client

// Fork-only guarantee (fork #37, restored by VD-6903): removing a catalog entry's
// static OAuth application without a reviewed generation revokes only the grants
// that application issued and every pending static OAuth test, while deleting the
// catalog entry itself also purges every grant on the entry's deployments and
// reconciles their owning servers. Kept in its own file so an upstream sync
// cannot drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"slices"
	"testing"

	gwtypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func countStaticOAuthDeleteTestRows(t *testing.T, c *Client, model any, query string, args ...any) int64 {
	t.Helper()
	var count int64
	require.NoError(t, c.db.WithContext(t.Context()).Model(model).Where(query, args...).Count(&count).Error)
	return count
}

func seedDynamicStaticOAuthDeleteTestGrant(t *testing.T, c *Client) {
	t.Helper()
	require.NoError(t, c.ReplaceMCPOAuthToken(t.Context(), "dynamic-user", staticOAuthCommitInstance, staticOAuthTestURL, "", &oauth2.Config{}, &oauth2.Token{AccessToken: "dynamic-token"}))
}

func TestDeleteMCPStaticOAuthCredentialRevokesOnlyOwnedState(t *testing.T) {
	for _, withCredential := range []bool{true, false} {
		name := "without static credential"
		if withCredential {
			name = "with static credential"
		}
		t.Run(name, func(t *testing.T) {
			c := newStaticOAuthCommitClient(t)
			if withCredential {
				seedActiveStaticOAuthCredential(t, c, "generation-1")
			}
			seedStaticOAuthGrant(t, c)
			seedDynamicStaticOAuthDeleteTestGrant(t, c)
			createStaticOAuthTest(t, c)
			var triggered []string
			c.mcpOAuthTokenTrigger = func(_ context.Context, mcpID string) error {
				triggered = append(triggered, mcpID)
				return nil
			}

			deleted, err := c.DeleteMCPStaticOAuthCredential(t.Context(), leaseTestEntry, staticOAuthCommitInstance)

			require.NoError(t, err)
			require.Equal(t, withCredential, deleted, "deleted must report whether an application row existed")
			require.Zero(t, countStaticOAuthDeleteTestRows(t, c, &gwtypes.Credential{}, "context = ?", staticOAuthTestCredentialContext))
			require.Zero(t, countStaticOAuthDeleteTestRows(t, c, &gwtypes.MCPOAuthToken{}, "catalog_entry_name = ?", leaseTestEntry))
			require.Zero(t, countStaticOAuthDeleteTestRows(t, c, &gwtypes.MCPOAuthPendingState{}, "mcp_id = ? AND static_o_auth_test = ?", leaseTestEntry, true))
			_, err = c.GetMCPOAuthToken(t.Context(), "dynamic-user", staticOAuthCommitInstance, staticOAuthTestURL)
			require.NoError(t, err, "the user's own dynamic grant must survive static cleanup")
			require.Contains(t, triggered, staticOAuthCommitInstance)
		})
	}
}

// Without a generation there is nothing to compare, so the delete must not need
// to read the application: a row this server can no longer decrypt still has to
// be removable.
func TestDeleteMCPStaticOAuthCredentialRemovesUndecryptableApplication(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	seedActiveStaticOAuthCredential(t, c, "generation-1")
	c.encryptionConfig = nil

	deleted, err := c.DeleteMCPStaticOAuthCredential(t.Context(), leaseTestEntry)

	require.NoError(t, err)
	require.True(t, deleted)
	require.Zero(t, countStaticOAuthDeleteTestRows(t, c, &gwtypes.Credential{}, "context = ?", staticOAuthTestCredentialContext))
}

// The first delete removes the rows before its notification fails, so the retry
// finds nothing to delete and must still notify the deployment it was given.
func TestDeleteMCPStaticOAuthCredentialWithoutGenerationRetriesCleanupNotifications(t *testing.T) {
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

	_, err := c.DeleteMCPStaticOAuthCredential(t.Context(), leaseTestEntry, staticOAuthCommitInstance)
	require.Error(t, err, "first delete succeeded despite injected notification failure")
	_, err = c.DeleteMCPStaticOAuthCredential(t.Context(), leaseTestEntry, staticOAuthCommitInstance)
	require.NoError(t, err)
	require.Equal(t, []string{staticOAuthCommitInstance, staticOAuthCommitInstance}, triggered)
}

func TestDeleteMCPStaticOAuthStateForDeletedCatalogEntryPurgesDeploymentGrants(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	seedActiveStaticOAuthCredential(t, c, "generation-1")
	createStaticOAuthTest(t, c)
	require.NoError(t, c.db.WithContext(t.Context()).Create(&[]gwtypes.MCPOAuthToken{
		{MCPID: "fenced-grant", UserID: "static-user", CatalogEntryName: leaseTestEntry},
		{MCPID: "server-1", UserID: "dynamic-user"},
		{MCPID: "instance-1", UserID: "container-user"},
		{MCPID: "unrelated", UserID: "other-user", CatalogEntryName: "other-entry"},
	}).Error)
	var triggered []string
	c.mcpOAuthTokenTrigger = func(_ context.Context, mcpID string) error {
		triggered = append(triggered, mcpID)
		return nil
	}

	deleted, err := c.DeleteMCPStaticOAuthStateForDeletedCatalogEntry(t.Context(), leaseTestEntry, "server-1", "instance-1")

	require.NoError(t, err)
	require.True(t, deleted)
	require.Zero(t, countStaticOAuthDeleteTestRows(t, c, &gwtypes.MCPOAuthToken{}, "catalog_entry_name = ? OR mcp_id IN ?", leaseTestEntry, []string{"server-1", "instance-1"}))
	require.Equal(t, int64(1), countStaticOAuthDeleteTestRows(t, c, &gwtypes.MCPOAuthToken{}, "mcp_id = ?", "unrelated"))
	require.Zero(t, countStaticOAuthDeleteTestRows(t, c, &gwtypes.MCPOAuthPendingState{}, "mcp_id = ? AND static_o_auth_test = ?", leaseTestEntry, true))
	for _, mcpID := range []string{"fenced-grant", "server-1", "instance-1"} {
		require.True(t, slices.Contains(triggered, mcpID), "reconciliation triggers = %v, missing %q", triggered, mcpID)
	}
	require.NotContains(t, triggered, "unrelated")
}

// Catalog-entry deletion notifies the deployment identifiers it purged, and for
// a multi-user deployment those are MCPServerInstance IDs. They have to resolve
// to their owning server, or the reconcile lands on a kind with no OAuth
// handlers.
func TestDeletedCatalogEntryCleanupTriggersTheOwningServerOfAnInstanceGrant(t *testing.T) {
	const entryName = "catalog-entry-1"
	backend := &recordingControllerBackend{}
	c := newTriggerTestClient(t, backend)
	require.NoError(t, c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    system.StaticOAuthCredentialName,
		Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret"},
	}))
	require.NoError(t, c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: triggerTestInstance, UserID: triggerTestUser, CatalogEntryName: entryName,
	}).Error)

	deleted, err := c.DeleteMCPStaticOAuthStateForDeletedCatalogEntry(t.Context(), entryName, triggerTestInstance)

	require.NoError(t, err)
	require.True(t, deleted)
	wantOwningServerTriggers(t, backend.triggers, triggerTestServer)
}
