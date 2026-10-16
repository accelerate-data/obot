package mcpcatalog

// Fork-only guarantee (VD-4886, restored by VD-6903): a strict catalog decode accepts upgradeNote and per-field configuration options on env vars and remote headers, keeps their values, and carries the options into the migrated Config. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/stretchr/testify/require"
)

func TestDecodeCatalogFileAcceptsConfigurationOptionsAndUpgradeNote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`name: Region Aware
runtime: remote
upgradeNote: Re-select a region after upgrading.
remoteConfig:
  fixedURL: https://example.com/mcp
  headers:
    - name: Region Header
      key: X-Region
      required: true
      options:
        - name: United States
          value: us
        - name: Europe
          value: eu
env:
  - name: Region
    key: REGION
    required: true
    options:
      - name: United States
        value: us
        description: US data residency
`), 0o600))

	entries, _, err := DecodeCatalogFile[types.MCPServerCatalogEntryManifest](path, true)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Strict decode succeeding is not enough: an ignored field would also produce
	// no error under a non-strict decoder, so assert the values round-tripped.
	entry := entries[0]
	require.Equal(t, "Re-select a region after upgrading.", entry.UpgradeNote)
	require.Len(t, entry.DeprecatedEnv[0].Options, 1)                                    //nolint:staticcheck // The legacy env field is what this catalog schema decodes into.
	require.Equal(t, "US data residency", entry.DeprecatedEnv[0].Options[0].Description) //nolint:staticcheck // The legacy env field is what this catalog schema decodes into.
	require.Len(t, entry.RemoteConfig.DeprecatedHeaders[0].Options, 2)                   //nolint:staticcheck // The legacy headers field is what this catalog schema decodes into.

	// Deployment reads Config, so options dropped by the migration would leave
	// the field unconstrained at runtime.
	require.Len(t, entry.Config, 2)
	require.Equal(t, "REGION", entry.Config[0].Key)
	require.Equal(t, []types.MCPConfigurationOption{
		{Name: "United States", Value: "us", Description: "US data residency"},
	}, entry.Config[0].Options)
	require.Equal(t, "X-Region", entry.Config[1].Key)
	require.Equal(t, []types.MCPConfigurationOption{
		{Name: "United States", Value: "us"},
		{Name: "Europe", Value: "eu"},
	}, entry.Config[1].Options)
}
