package mcpcatalog

// Fork-only guarantee (VD-3960 / fork #35, restored by VD-6903): an org-configured catalog that still ships the pre-vMCP remote shape (serverUserType, remoteConfig.headers, env) is accepted and its headers and env keep their requirements once folded into config. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/stretchr/testify/require"
)

func TestReadMCPCatalogAcceptsOrgConfiguredLegacyRemoteShapes(t *testing.T) {
	dir := t.TempDir()
	// These manifests use the schema org catalogs were written against before
	// config replaced remoteConfig.headers and env; a sync that drops the
	// migration would reject or silently empty every one of them.
	manifests := map[string]string{
		"github.yaml": `name: GitHub
entryKey: obot-github
serverUserType: multiUser
shortDescription: GitHub
description: GitHub
runtime: remote
remoteConfig:
  hostname: api.githubcopilot.com
  headers:
    - name: Personal Access Token
      key: Authorization
      required: true
      sensitive: true
`,
		"databricks.yaml": `name: Databricks Genie Spaces
entryKey: obot-databricks-genie-spaces
serverUserType: multiUser
shortDescription: Databricks
description: Databricks
metadata:
  allow-multiple: "true"
runtime: remote
remoteConfig:
  URLTemplate: ${DATABRICKS_WORKSPACE_URL}/api/2.0/mcp/genie/${DATABRICKS_GENIE_SPACE_ID}
  headers:
    - name: Personal Access Token
      key: Authorization
      required: true
      sensitive: true
      prefix: "Bearer "
env:
  - name: Databricks workspace hostname
    key: DATABRICKS_WORKSPACE_URL
    required: true
  - name: Genie space ID
    key: DATABRICKS_GENIE_SPACE_ID
    required: true
`,
		"google-maps.yaml": `name: Google Maps Grounding Lite
entryKey: obot-google-maps-grounding-lite
serverUserType: multiUser
shortDescription: Google Maps
description: Google Maps
metadata:
  allow-multiple: "true"
runtime: remote
remoteConfig:
  fixedURL: https://mapstools.googleapis.com/mcp
  headers:
    - name: API Key
      key: X-Goog-Api-Key
      required: true
      sensitive: true
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
	require.True(t, databricksConfig["DATABRICKS_WORKSPACE_URL"].Required)
	require.Equal(t, types.Env, databricksConfig["DATABRICKS_GENIE_SPACE_ID"].Usage)
	require.True(t, databricksConfig["DATABRICKS_GENIE_SPACE_ID"].Required)

	googleMaps := entries["obot-google-maps-grounding-lite"]
	require.Equal(t, "true", googleMaps.Metadata["allow-multiple"])
	require.Equal(t, "https://mapstools.googleapis.com/mcp", googleMaps.RemoteConfig.FixedURL)
	googleMapsConfig := configByKey(googleMaps.Config)
	require.Equal(t, types.Header, googleMapsConfig["X-GOOG-API-KEY"].Usage)
	require.True(t, googleMapsConfig["X-GOOG-API-KEY"].Required)
	require.True(t, googleMapsConfig["X-GOOG-API-KEY"].Sensitive)
}
