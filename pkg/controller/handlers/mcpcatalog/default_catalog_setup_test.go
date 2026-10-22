package mcpcatalog

import (
	"context"
	"testing"

	"github.com/obot-platform/nah/pkg/router"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	upstreamCatalogURL   = "https://github.com/obot-platform/mcp-catalog"
	deploymentCatalogURL = "https://github.com/accelerate-data/mcp-catalog"
)

func existingDefaultCatalog(sourceURLs ...string) *v1.MCPCatalog {
	return &v1.MCPCatalog{
		APIVersion: v1.SchemeGroupVersion.String(),
		Kind:       "MCPCatalog",
		Name:       system.DefaultCatalog,
		Namespace:  system.DefaultNamespace,
		Spec: v1.MCPCatalogSpec{
			DisplayName: "Default",
			SourceURLs:  sourceURLs,
		},
	}
}

func defaultCatalogSourceURLs(ctx context.Context, t *testing.T, c kclient.Client) []string {
	t.Helper()

	var catalog v1.MCPCatalog
	require.NoError(t, c.Get(ctx, router.Key(system.DefaultNamespace, system.DefaultCatalog), &catalog))
	return catalog.Spec.SourceURLs
}

// Canary: green with and without the migration fix, so a red here is a broken
// harness rather than a behaviour change.
func TestSetUpDefaultMCPCatalogCreatesCatalogFromConfiguredPath(t *testing.T) {
	ctx := context.Background()
	storageClient := newCatalogFakeClient()
	handler := &Handler{defaultCatalogPath: deploymentCatalogURL}

	require.NoError(t, handler.SetUpDefaultMCPCatalog(ctx, storageClient))

	require.Equal(t, []string{deploymentCatalogURL}, defaultCatalogSourceURLs(ctx, t, storageClient))
}

func TestSetUpDefaultMCPCatalogMigratesPreviousDefaultSourceURL(t *testing.T) {
	ctx := context.Background()
	storageClient := newCatalogFakeClient(existingDefaultCatalog(upstreamCatalogURL))
	handler := &Handler{defaultCatalogPath: deploymentCatalogURL}

	require.NoError(t, handler.SetUpDefaultMCPCatalog(ctx, storageClient))

	require.Equal(t, []string{deploymentCatalogURL}, defaultCatalogSourceURLs(ctx, t, storageClient),
		"an upgraded deployment still on the previous default catalog source must be migrated to the configured one")
}

func TestSetUpDefaultMCPCatalogMigratesLegacyLocalPath(t *testing.T) {
	for _, legacyPath := range []string{"catalog", "./catalog", "/catalog"} {
		t.Run(legacyPath, func(t *testing.T) {
			ctx := context.Background()
			storageClient := newCatalogFakeClient(existingDefaultCatalog(legacyPath))
			handler := &Handler{defaultCatalogPath: deploymentCatalogURL}

			require.NoError(t, handler.SetUpDefaultMCPCatalog(ctx, storageClient))

			require.Equal(t, []string{deploymentCatalogURL}, defaultCatalogSourceURLs(ctx, t, storageClient))
		})
	}
}

// The guard that keeps migration from overwriting a customer's own catalog.
func TestSetUpDefaultMCPCatalogPreservesOperatorConfiguredSourceURL(t *testing.T) {
	ctx := context.Background()
	const operatorURL = "https://github.com/example-customer/their-own-catalog"
	storageClient := newCatalogFakeClient(existingDefaultCatalog(operatorURL))
	handler := &Handler{defaultCatalogPath: deploymentCatalogURL}

	require.NoError(t, handler.SetUpDefaultMCPCatalog(ctx, storageClient))

	require.Equal(t, []string{operatorURL}, defaultCatalogSourceURLs(ctx, t, storageClient),
		"a deliberately configured catalog source must survive an upgrade untouched")
}

func TestSetUpDefaultMCPCatalogMigratesOnlyThePreviousDefaultAmongSeveralSources(t *testing.T) {
	ctx := context.Background()
	const operatorURL = "https://github.com/example-customer/their-own-catalog"
	storageClient := newCatalogFakeClient(existingDefaultCatalog(upstreamCatalogURL, operatorURL))
	handler := &Handler{defaultCatalogPath: deploymentCatalogURL}

	require.NoError(t, handler.SetUpDefaultMCPCatalog(ctx, storageClient))

	require.Equal(t, []string{deploymentCatalogURL, operatorURL}, defaultCatalogSourceURLs(ctx, t, storageClient))
}
