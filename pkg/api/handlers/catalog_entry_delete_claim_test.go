package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/storage"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/stretchr/testify/require"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type conflictingCatalogEntryDeleteClient struct {
	storage.Client
	deleteCalls int
	change      func(*v1.MCPServerCatalogEntry)
}

func (c *conflictingCatalogEntryDeleteClient) Delete(ctx context.Context, obj kclient.Object, opts ...kclient.DeleteOption) error {
	c.deleteCalls++
	if c.deleteCalls == 1 {
		var latest v1.MCPServerCatalogEntry
		if err := c.Get(ctx, kclient.ObjectKeyFromObject(obj), &latest); err != nil {
			return err
		}
		c.change(&latest)
		if err := c.Update(ctx, &latest); err != nil {
			return err
		}
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestDeleteEntryPreservesChangedEntryBetweenReadAndDelete(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*v1.MCPServerCatalogEntry)
	}{
		{name: "catalog ownership", change: func(e *v1.MCPServerCatalogEntry) { e.Spec.MCPCatalogName = "other" }},
		{name: "workspace ownership", change: func(e *v1.MCPServerCatalogEntry) { e.Spec.PowerUserWorkspaceID = "other" }},
		{name: "editable ownership", change: func(e *v1.MCPServerCatalogEntry) { e.Spec.Editable = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := newOAuthCredentialTestGatewayClient(t)
			entry := staticOAuthTestEntry("entry-1", "default", "https://example.com/mcp")
			entry.Spec.Editable = true
			req := newEditableEntryRequest(t, gateway, http.MethodDelete, "", entry)
			client := &conflictingCatalogEntryDeleteClient{Client: req.Storage, change: tc.change}
			req.Storage = client
			err := (&MCPCatalogHandler{}).DeleteEntry(req)
			var httpErr *types.ErrHTTP
			require.ErrorAs(t, err, &httpErr)
			require.Equal(t, http.StatusBadRequest, httpErr.Code)
			require.Equal(t, 1, client.deleteCalls)
			var remaining v1.MCPServerCatalogEntry
			require.NoError(t, client.Get(t.Context(), kclient.ObjectKeyFromObject(entry), &remaining))
			expected := entry.DeepCopy()
			tc.change(expected)
			require.Equal(t, expected.Spec, remaining.Spec)
		})
	}
}

func TestDeleteEntryRetriesConflictAfterConcurrentUpdate(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://example.com/mcp")
	entry.Spec.Editable = true
	req := newEditableEntryRequest(t, gateway, http.MethodDelete, "", entry)
	client := &conflictingCatalogEntryDeleteClient{Client: req.Storage, change: func(e *v1.MCPServerCatalogEntry) { e.Annotations = map[string]string{"controller": "updated"} }}
	req.Storage = client
	require.NoError(t, (&MCPCatalogHandler{}).DeleteEntry(req))
	require.Equal(t, 2, client.deleteCalls)
}
