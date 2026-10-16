package mcp

// Fork-only guarantee (VD-4886, restored by VD-6903): ValidateServerManifest rejects a malformed configuration-options declaration, independently of the catalog-entry validator that upstream's configurationoptions_test.go covers. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/stretchr/testify/require"
)

// ValidateServerManifest is a second, independently wired call site for the same
// checks; a malformed declaration must fail there too.
func TestValidateServerManifestConfigurationOptions(t *testing.T) {
	base := types.MCPServerManifest{
		Runtime:   types.RuntimeNPX,
		NPXConfig: &types.NPXRuntimeConfig{Package: "test-server"},
		Config: []types.MCPConfig{{
			Key:      "REGION",
			Name:     "Region",
			Usage:    types.Env,
			Required: true,
			Options: []types.MCPConfigurationOption{
				{Name: "United States", Value: "us"},
				{Name: "Europe", Value: "eu"},
			},
		}},
	}

	require.NoError(t, ValidateServerManifest(t.Context(), base, false, ValidationOptions{}))

	manifest := *base.DeepCopy()
	manifest.Config[0].Options[1].Value = "us"
	require.ErrorContains(t, ValidateServerManifest(t.Context(), manifest, false, ValidationOptions{}), "duplicate value")
}
