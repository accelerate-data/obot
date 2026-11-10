package mcp

import (
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/stretchr/testify/require"
)

func TestStudioCompatibilityAllowsMultiUserRemoteCatalogEntries(t *testing.T) {
	manifest := types.MCPServerCatalogEntryManifest{
		Runtime: types.RuntimeRemote,
		RemoteConfig: &types.RemoteCatalogConfig{
			FixedURL: "https://8.8.8.8/mcp",
		},
		Config: []types.MCPConfig{
			{Name: "API Key", Key: "X-API-Key", Required: true, Sensitive: true, Usage: types.Header},
		},
	}

	require.NoError(t, ValidateCatalogEntryManifest(t.Context(), manifest, true, ValidationOptions{}))
}
