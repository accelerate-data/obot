package mcp

import (
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/stretchr/testify/require"
)

func testConfigurationOptions() []types.MCPConfigurationOption {
	return []types.MCPConfigurationOption{
		{Name: "United States", Value: "us", Description: "US endpoint"},
		{Name: "Europe", Value: "eu"},
	}
}

func TestValidateCatalogEntryManifestConfigurationOptions(t *testing.T) {
	base := types.MCPServerCatalogEntryManifest{
		ServerUserType: types.ServerUserTypeSingleUser,
		Runtime:        types.RuntimeNPX,
		NPXConfig:      &types.NPXRuntimeConfig{Package: "test-server"},
		Env: []types.MCPEnv{{
			Key: "REGION", Name: "Region", Required: true, Options: testConfigurationOptions()}},
	}

	require.NoError(t, ValidateCatalogEntryManifest(t.Context(), base, true, ValidationOptions{}))
	require.NoError(t, ValidateCatalogEntryManifest(t.Context(), base, false, ValidationOptions{}))

	tests := []struct {
		name    string
		mutate  func(*types.MCPServerCatalogEntryManifest)
		wantErr string
	}{
		{
			name:    "static value",
			mutate:  func(m *types.MCPServerCatalogEntryManifest) { m.Env[0].Value = "us" },
			wantErr: "value and options are mutually exclusive",
		},
		{
			name: "secret binding",
			mutate: func(m *types.MCPServerCatalogEntryManifest) {
				m.Env[0].SecretBinding = &types.MCPSecretBinding{Name: "secret", Key: "region"}
			},
			wantErr: "secretBinding and options are mutually exclusive",
		},
		{
			name:    "blank name",
			mutate:  func(m *types.MCPServerCatalogEntryManifest) { m.Env[0].Options[0].Name = " " },
			wantErr: "name cannot be empty",
		},
		{
			name:    "blank value",
			mutate:  func(m *types.MCPServerCatalogEntryManifest) { m.Env[0].Options[0].Value = " " },
			wantErr: "value cannot be empty",
		},
		{
			name:    "duplicate value",
			mutate:  func(m *types.MCPServerCatalogEntryManifest) { m.Env[0].Options[1].Value = "us" },
			wantErr: "duplicate value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := *base.DeepCopy()
			tt.mutate(&manifest)
			require.ErrorContains(t, ValidateCatalogEntryManifest(t.Context(), manifest, false, ValidationOptions{}), tt.wantErr)
		})
	}
}

// ValidateServerManifest is a second, independently wired call site for the same
// checks; a malformed declaration must fail there too.
func TestValidateServerManifestConfigurationOptions(t *testing.T) {
	base := types.MCPServerManifest{
		Runtime:   types.RuntimeNPX,
		NPXConfig: &types.NPXRuntimeConfig{Package: "test-server"},
		Env: []types.MCPEnv{{
			Key: "REGION", Name: "Region", Required: true, Options: testConfigurationOptions()}},
	}

	require.NoError(t, ValidateServerManifest(t.Context(), base, false, ValidationOptions{}))

	manifest := *base.DeepCopy()
	manifest.Env[0].Options[1].Value = "us"
	require.ErrorContains(t, ValidateServerManifest(t.Context(), manifest, false, ValidationOptions{}), "duplicate value")
}

// A composite component's configuration fields are validated through the
// recursive descent, not only the top-level manifest's own fields.
func TestValidateCatalogEntryManifestCompositeConfigurationOptions(t *testing.T) {
	manifest := types.MCPServerCatalogEntryManifest{
		ServerUserType: types.ServerUserTypeSingleUser,
		Runtime:        types.RuntimeComposite,
		CompositeConfig: &types.CompositeCatalogConfig{
			ComponentServers: []types.CatalogComponentServer{{
				CatalogEntryID: "component-entry",
				Manifest: types.MCPServerCatalogEntryManifest{
					ServerUserType: types.ServerUserTypeSingleUser,
					Runtime:        types.RuntimeNPX,
					NPXConfig:      &types.NPXRuntimeConfig{Package: "test-server"},
					Env: []types.MCPEnv{{
						Key: "REGION", Name: "Region", Required: true, Options: []types.MCPConfigurationOption{
							{Name: "United States", Value: "us"},
							{Name: "Europe", Value: "us"},
						}}},
				},
			}},
		},
	}

	err := ValidateCatalogEntryManifest(t.Context(), manifest, false, ValidationOptions{})
	require.ErrorContains(t, err, "duplicate value")
	require.ErrorContains(t, err, "compositeConfig.componentServers[0].manifest.env[0].options")
}
