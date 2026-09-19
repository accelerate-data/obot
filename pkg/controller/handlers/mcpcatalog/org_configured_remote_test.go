package mcpcatalog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/stretchr/testify/require"
)

func TestReadMCPCatalogAcceptsOrgConfiguredRemoteEntries(t *testing.T) {
	dir := t.TempDir()
	manifests := map[string]string{
		"github.yaml": `name: GitHub
entryKey: obot-github
shortDescription: GitHub
description: GitHub
runtime: remote
remoteConfig:
  hostname: api.githubcopilot.com
config:
  - name: Personal Access Token
    key: Authorization
    required: true
    sensitive: true
    usage: header
`,
		"databricks.yaml": `name: Databricks Genie Spaces
entryKey: obot-databricks-genie-spaces
shortDescription: Databricks
description: Databricks
metadata:
  allow-multiple: "true"
runtime: remote
remoteConfig:
  URLTemplate: ${DATABRICKS_WORKSPACE_URL}/api/2.0/mcp/genie/${DATABRICKS_GENIE_SPACE_ID}
config:
  - name: Personal Access Token
    key: Authorization
    required: true
    sensitive: true
    prefix: "Bearer "
    usage: header
  - name: Databricks workspace hostname
    key: DATABRICKS_WORKSPACE_URL
    required: true
    usage: env
  - name: Genie space ID
    key: DATABRICKS_GENIE_SPACE_ID
    required: true
    usage: env
`,
		"google-maps.yaml": `name: Google Maps Grounding Lite
entryKey: obot-google-maps-grounding-lite
shortDescription: Google Maps
description: Google Maps
metadata:
  allow-multiple: "true"
runtime: remote
remoteConfig:
  fixedURL: https://mapstools.googleapis.com/mcp
config:
  - name: API Key
    key: X-Goog-Api-Key
    required: true
    sensitive: true
    usage: header
`,
	}

	for name, manifest := range manifests {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(manifest), 0o600))
	}

	objects, err := (&Handler{}).readMCPCatalog(t.Context(), "default", dir, "")
	require.NoError(t, err)
	require.Len(t, objects, len(manifests))

	entries := make(map[string]types.MCPServerCatalogEntryManifest, len(objects))
	for _, object := range objects {
		entry, ok := object.(*v1.MCPServerCatalogEntry)
		require.True(t, ok, "unexpected catalog object %T", object)
		entries[entry.Spec.Manifest.EntryKey] = entry.Spec.Manifest
	}

	github := entries["obot-github"]
	require.Equal(t, "api.githubcopilot.com", github.RemoteConfig.Hostname)
	githubConfig := configByKey(github.Config)
	require.Equal(t, types.Header, githubConfig["AUTHORIZATION"].Usage)
	require.True(t, githubConfig["AUTHORIZATION"].Required)
	require.True(t, githubConfig["AUTHORIZATION"].Sensitive)

	databricks := entries["obot-databricks-genie-spaces"]
	require.Equal(t, "true", databricks.Metadata["allow-multiple"])
	require.Equal(
		t,
		"${DATABRICKS_WORKSPACE_URL}/api/2.0/mcp/genie/${DATABRICKS_GENIE_SPACE_ID}",
		databricks.RemoteConfig.URLTemplate,
	)
	databricksConfig := configByKey(databricks.Config)
	require.Equal(t, types.Header, databricksConfig["AUTHORIZATION"].Usage)
	require.True(t, databricksConfig["AUTHORIZATION"].Required)
	require.True(t, databricksConfig["AUTHORIZATION"].Sensitive)
	require.Equal(t, "Bearer ", databricksConfig["AUTHORIZATION"].Prefix)
	require.Equal(t, types.Env, databricksConfig["DATABRICKS_WORKSPACE_URL"].Usage)
	require.Equal(t, types.Env, databricksConfig["DATABRICKS_GENIE_SPACE_ID"].Usage)

	googleMaps := entries["obot-google-maps-grounding-lite"]
	require.Equal(t, "true", googleMaps.Metadata["allow-multiple"])
	require.Equal(t, "https://mapstools.googleapis.com/mcp", googleMaps.RemoteConfig.FixedURL)
	googleMapsConfig := configByKey(googleMaps.Config)
	require.Equal(t, types.Header, googleMapsConfig["X-GOOG-API-KEY"].Usage)
	require.True(t, googleMapsConfig["X-GOOG-API-KEY"].Required)
	require.True(t, googleMapsConfig["X-GOOG-API-KEY"].Sensitive)
}

func configByKey(config []types.MCPConfig) map[string]types.MCPConfig {
	result := make(map[string]types.MCPConfig, len(config))
	for _, item := range config {
		result[item.Key] = item
	}
	return result
}
