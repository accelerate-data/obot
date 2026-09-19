package mcpcatalog

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/stretchr/testify/require"
)

func TestWalkCatalogFilesSkipsSymlinksAndIgnoredFiles(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yaml")
	require.NoError(t, os.WriteFile(validPath, []byte("name: Valid\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ignored.yaml"), []byte("name: Ignored\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".ignoreobotcatalogs"), []byte("ignored.yaml\n"), 0o600))
	require.NoError(t, os.Symlink(validPath, filepath.Join(dir, "linked.yaml")))

	files, _, err := WalkCatalogFiles(dir)
	require.NoError(t, err)
	var paths []string
	for path, err := range files {
		require.NoError(t, err)
		paths = append(paths, path)
	}
	require.Equal(t, []string{validPath}, paths)
}

func TestWalkCatalogFilesSkipsHiddenDirectories(t *testing.T) {
	for _, customPatterns := range []bool{false, true} {
		t.Run(fmt.Sprintf("customPatterns=%t", customPatterns), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), ".catalog")
			for _, name := range []string{
				"valid.yaml", "nested/valid.yml", "nested/deeper/valid.json",
				".github/workflows/ci.yml", ".git/config.yaml", ".config/entry.json",
				"nested/.hidden/entry.yaml", ".pre-commit-config.yaml",
			} {
				path := filepath.Join(dir, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
				require.NoError(t, os.WriteFile(path, []byte("name: Test\n"), 0o600))
			}

			if customPatterns {
				require.NoError(t, os.WriteFile(filepath.Join(dir, ".obotcatalogs"), []byte("*.yaml\n*.yml\n*.json\n"), 0o600))
			}

			t.Chdir(dir)
			for _, root := range []string{dir, "."} {
				files, usingPatterns, err := WalkCatalogFiles(root)
				require.NoError(t, err)
				require.Equal(t, customPatterns, usingPatterns)

				var paths []string
				for path, err := range files {
					require.NoError(t, err)

					rel, err := filepath.Rel(root, path)
					require.NoError(t, err)
					paths = append(paths, filepath.ToSlash(rel))
				}

				require.ElementsMatch(t, []string{"valid.yaml", "nested/valid.yml", "nested/deeper/valid.json", ".pre-commit-config.yaml"}, paths)
			}
		})
	}
}

func TestWalkCatalogFilesPatternSemantics(t *testing.T) {
	for _, tt := range []struct {
		name     string
		includes string
		ignores  string
		want     []string
	}{
		{
			name:    "default patterns and directory exclusions",
			ignores: "# Repository metadata\n\n scripts \nrenovate.json\n.pre-commit-config.yaml\n",
			want:    []string{"entry.mcp.yaml", "nested/entry.mcp.yaml", "other.yml"},
		},
		{
			name:     "includes replace defaults and match basenames",
			includes: "# Catalog manifests\n\n *.mcp.yaml \n",
			ignores:  "scripts\nnested/entry.mcp.yaml\n",
			want:     []string{"entry.mcp.yaml"},
		},
		{
			name:     "root-relative directory glob",
			includes: "nested/*.yaml\n",
			want:     []string{"nested/entry.mcp.yaml"},
		},
		{
			name:     "exact nested file",
			includes: "scripts/deep/more/entry.mcp.yaml\n",
			want:     []string{"scripts/deep/more/entry.mcp.yaml"},
		},
		{
			name:     "mixed basename and path patterns",
			includes: "*.yml\nnested/*.yaml\n",
			want:     []string{"other.yml", "nested/entry.mcp.yaml"},
		},
		{
			name:     "exclusions override path includes",
			includes: "nested/*.yaml\nscripts/deep/more/*.yaml\n",
			ignores:  "nested/entry.mcp.yaml\nscripts\n",
		},
		{
			name:     "root-relative directory exclusion",
			includes: "*.mcp.yaml\n",
			ignores:  "scripts/deep\n",
			want:     []string{"entry.mcp.yaml", "nested/entry.mcp.yaml"},
		},
		{
			name:     "root-relative file glob exclusion",
			includes: "*.mcp.yaml\n",
			ignores:  "nested/*.yaml\nscripts/deep/more/*.yaml\n",
			want:     []string{"entry.mcp.yaml"},
		},
		{
			name:     "include wildcards do not cross separators",
			includes: "scripts/*.yaml\nscripts/**/entry.mcp.yaml\n",
		},
		{
			name:     "double star does not cross separators",
			includes: "*.mcp.yaml\n",
			ignores:  "scripts/**/entry.mcp.yaml\n",
			want:     []string{"entry.mcp.yaml", "nested/entry.mcp.yaml", "scripts/deep/more/entry.mcp.yaml"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"entry.mcp.yaml", "nested/entry.mcp.yaml", "scripts/deep/more/entry.mcp.yaml", "other.yml", "renovate.json", ".pre-commit-config.yaml"} {
				path := filepath.Join(dir, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
				require.NoError(t, os.WriteFile(path, nil, 0o600))
			}

			if tt.includes != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, ".obotcatalogs"), []byte(tt.includes), 0o600))
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, ".ignoreobotcatalogs"), []byte(tt.ignores), 0o600))

			files, _, err := WalkCatalogFiles(dir)
			require.NoError(t, err)

			var paths []string
			for path, err := range files {
				require.NoError(t, err)

				rel, err := filepath.Rel(dir, path)
				require.NoError(t, err)
				paths = append(paths, filepath.ToSlash(rel))
			}

			require.ElementsMatch(t, tt.want, paths)
		})
	}
}

func TestWalkCatalogFilesFallsBackWhenPatternFilesCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yaml")
	require.NoError(t, os.WriteFile(validPath, []byte("name: Valid\n"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".obotcatalogs"), 0o700))
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".ignoreobotcatalogs"), 0o700))

	files, usingObotCatalogsFile, err := WalkCatalogFiles(dir)
	require.NoError(t, err)
	require.False(t, usingObotCatalogsFile)

	var paths []string
	for path, err := range files {
		require.NoError(t, err)
		paths = append(paths, path)
	}
	require.Equal(t, []string{validPath}, paths)
}

func TestWalkCatalogFilesFallsBackWhenPatternLineIsTooLong(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yaml")
	require.NoError(t, os.WriteFile(validPath, []byte("name: Valid\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".obotcatalogs"), []byte(strings.Repeat("x", bufio.MaxScanTokenSize+1)), 0o600))

	files, usingObotCatalogsFile, err := WalkCatalogFiles(dir)
	require.NoError(t, err)
	require.True(t, usingObotCatalogsFile)

	var paths []string
	for path, err := range files {
		require.NoError(t, err)
		paths = append(paths, path)
	}
	require.Equal(t, []string{validPath}, paths)
}

func TestDecodeCatalogFileStrictness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`name: First
name: Second
runtime: npx
npxConfig:
  package: test
`), 0o600))

	entries, isArray, err := DecodeCatalogFile[types.MCPServerCatalogEntryManifest](path, false)
	require.NoError(t, err)
	require.False(t, isArray)
	require.Len(t, entries, 1)
	require.Equal(t, "Second", entries[0].Name)

	_, _, err = DecodeCatalogFile[types.MCPServerCatalogEntryManifest](path, true)
	require.ErrorContains(t, err, `key "name" already set`)
}

func TestNormalizeManifest(t *testing.T) {
	entry := types.MCPServerCatalogEntryManifest{
		Runtime: types.RuntimeRemote,
		Config: []types.MCPConfig{
			{Name: "config-file.json", Usage: types.File},
			{Name: "api_key", Usage: types.Header},
		},
	}

	NormalizeManifest(&entry)

	require.Equal(t, "CONFIG_FILE_JSON", entry.Config[0].Key)
	require.Equal(t, "API-KEY", entry.Config[1].Key)
}

func TestNormalizeSystemManifest(t *testing.T) {
	entry := types.SystemMCPServerCatalogEntryManifest{
		Runtime: types.RuntimeRemote,
		Config: []types.MCPConfig{
			{Name: "config-file.json", Usage: types.File},
			{Name: "api_key", Usage: types.Header},
		},
		RemoteConfig: &types.RemoteCatalogConfig{},
	}

	NormalizeSystemManifest(&entry)

	require.Equal(t, "CONFIG_FILE_JSON", entry.Config[0].Key)
	require.Equal(t, types.File, entry.Config[0].Usage)
	require.Equal(t, "API-KEY", entry.Config[1].Key)
	require.Equal(t, types.Header, entry.Config[1].Usage)
}

// The pre-vMCP catalog schema put per-user and deployment inputs in env,
// remoteConfig.headers, and multiUserConfig.userDefinedHeaders. Those fields no
// longer exist on the catalog-entry manifest, so DecodeCatalogFile must both
// accept them (Deprecated* fields) and fold them into Config (equal to
// flattenStoredMCPConfig's server=false conversion) or MapCatalogEntryToServer
// would deploy an entry with no configuration.
func TestDecodeCatalogFileMigratesDeprecatedCatalogSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`name: Legacy
shortDescription: Legacy entry
description: Legacy entry
icon: https://example.test/legacy.png
runtime: remote
serverUserType: multiUser
remoteConfig:
  fixedURL: https://example.com/mcp
  headers:
    - key: AUTHORIZATION
      required: true
      sensitive: true
env:
  - key: WORKSPACE
    required: true
multiUserConfig:
  userDefinedHeaders:
    - key: X-USER
      prefix: "Bearer "
`), 0o600))

	entries, isArray, err := DecodeCatalogFile[types.MCPServerCatalogEntryManifest](path, true)
	require.NoError(t, err)
	require.False(t, isArray)
	require.Len(t, entries, 1)

	entry := entries[0]
	require.Equal(t, []types.MCPConfig{
		{Key: "WORKSPACE", Required: true, Usage: types.Env},
		{Key: "AUTHORIZATION", Required: true, Sensitive: true, Usage: types.Header},
		{Key: "X-USER", Prefix: "Bearer ", Usage: types.Header},
	}, entry.Config)
	for _, config := range entry.Config {
		require.False(t, config.UserAllowed, "catalog entries never carry deployment-policy UserAllowed")
	}
	// Existing API consumers still read the deprecated fields, so they stay populated.
	require.Equal(t, types.ServerUserTypeMultiUser, entry.DeprecatedServerUserType) //nolint:staticcheck // Assert the deprecated decode fields stay populated for API consumers.
	require.Len(t, entry.DeprecatedEnv, 1)                                          //nolint:staticcheck // Assert the deprecated decode fields stay populated for API consumers.
	require.Len(t, entry.RemoteConfig.DeprecatedHeaders, 1)                         //nolint:staticcheck // Assert the deprecated decode fields stay populated for API consumers.
	require.Len(t, entry.DeprecatedMultiUserConfig.UserDefinedHeaders, 1)           //nolint:staticcheck // Assert the deprecated decode fields stay populated for API consumers.

	require.NoError(t, entry.ValidateConfig())
}

func TestDecodeCatalogFileMigratesDeprecatedSystemCatalogSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-system.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`name: Filter
shortDescription: Filter
description: Filter
icon: icon
systemMCPServerType: filter
filterConfig:
  toolName: filter
runtime: remote
serverUserType: singleUser
env:
  - key: TOKEN
    required: true
remoteConfig:
  fixedURL: https://example.com/mcp
  headers:
    - key: Authorization
      prefix: 'Bearer '
`), 0o600))

	entries, _, err := DecodeCatalogFile[types.SystemMCPServerCatalogEntryManifest](path, true)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, []types.MCPConfig{
		{Key: "TOKEN", Required: true, Usage: types.Env},
		{Key: "Authorization", Prefix: "Bearer ", Usage: types.Header},
	}, entries[0].Config)
}

func TestDecodeCatalogFileLeavesConfigSchemaUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modern.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`name: Modern
shortDescription: Modern entry
description: Modern entry
icon: https://example.test/modern.png
runtime: remote
remoteConfig:
  fixedURL: https://example.com/mcp
config:
  - key: AUTHORIZATION
    usage: header
    required: true
    sensitive: true
`), 0o600))

	entries, _, err := DecodeCatalogFile[types.MCPServerCatalogEntryManifest](path, true)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, []types.MCPConfig{
		{Key: "AUTHORIZATION", Required: true, Sensitive: true, Usage: types.Header},
	}, entries[0].Config)
}

func TestMigrateDeprecatedCatalogFieldsIsNoOpForNewSchema(t *testing.T) {
	entry := types.MCPServerCatalogEntryManifest{
		Config: []types.MCPConfig{{Key: "AUTHORIZATION", Usage: types.Header}},
	}
	entry.MigrateDeprecatedCatalogFields()
	require.Equal(t, []types.MCPConfig{{Key: "AUTHORIZATION", Usage: types.Header}}, entry.Config)
}
