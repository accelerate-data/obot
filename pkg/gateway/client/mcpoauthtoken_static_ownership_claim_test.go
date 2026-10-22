package client

// Fork-only guarantee (VD-4883, restored by VD-6903): replacing or clearing a
// catalog entry's static OAuth application revokes only the grants that
// application issued. The deployment IDs the caller passes are reconciled, but
// they never widen the deletion, so a user's own dynamic grant on the same
// deployment survives. Kept in its own file so an upstream sync cannot drop
// these tests by merging over a shared one.

import (
	"context"
	"errors"
	"testing"

	"github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
)

const (
	ownershipTestEntry      = "catalog-entry-1"
	ownershipTestGeneration = "generation-1"
)

func newOwnershipTestClient(t *testing.T, backend *recordingControllerBackend) *Client {
	t.Helper()
	c := newTriggerTestClient(t, backend)
	c.encryptionConfig = &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			credentialGroupResource: leaseTestTransformer{},
		},
	}
	require.NoError(t, c.CommitClaimedMCPStaticOAuthCredential(t.Context(), ownershipTestClaim("previous-client"), false))
	return c
}

func ownershipTestClaim(clientID string) *MCPStaticOAuthCredentialClaim {
	return &MCPStaticOAuthCredentialClaim{
		mcpID:        ownershipTestEntry,
		mcpURL:       triggerTestURL,
		clientID:     clientID,
		clientSecret: clientID + "-secret",
		generation:   ownershipTestGeneration,
	}
}

func createOwnershipTestGrant(t *testing.T, c *Client, userID, catalogEntryName string) {
	t.Helper()
	require.NoError(t, c.db.WithContext(t.Context()).Create(&types.MCPOAuthToken{
		MCPID:            triggerTestInstance,
		UserID:           userID,
		URL:              triggerTestURL,
		CatalogEntryName: catalogEntryName,
	}).Error)
}

func requireOwnershipTestGrant(t *testing.T, c *Client, userID string, wantPresent bool) {
	t.Helper()
	var token types.MCPOAuthToken
	err := c.db.WithContext(t.Context()).Where("user_id = ? AND mcp_id = ?", userID, triggerTestInstance).First(&token).Error
	if wantPresent {
		require.NoError(t, err, "grant for %s was deleted", userID)
		return
	}
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound), "grant for %s survived: %v", userID, err)
}

func TestStaticOAuthCredentialChangeRevokesOnlyOwnedGrants(t *testing.T) {
	tests := []struct {
		name   string
		change func(ctx context.Context, c *Client) error
	}{
		{
			name: "replace",
			change: func(ctx context.Context, c *Client) error {
				return c.CommitClaimedMCPStaticOAuthCredential(ctx, ownershipTestClaim("replacement-client"), true, triggerTestInstance)
			},
		},
		{
			name: "clear",
			change: func(ctx context.Context, c *Client) error {
				_, err := c.DeleteMCPStaticOAuthCredentialGeneration(ctx, ownershipTestEntry, ownershipTestGeneration, triggerTestInstance)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &recordingControllerBackend{}
			c := newOwnershipTestClient(t, backend)
			createOwnershipTestGrant(t, c, "static-user", ownershipTestEntry)
			createOwnershipTestGrant(t, c, "dynamic-user", "")
			backend.triggers = nil

			require.NoError(t, tt.change(t.Context(), c))

			requireOwnershipTestGrant(t, c, "static-user", false)
			requireOwnershipTestGrant(t, c, "dynamic-user", true)
			wantOwningServerTriggers(t, backend.triggers, triggerTestServer)
		})
	}
}
