package mcpcatalog

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/obot-platform/nah/pkg/router"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	storageservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSyncSkipsRecentCatalogAndForceSyncPrunesRemovedEntries(t *testing.T) {
	ctx := context.Background()
	catalogDir := t.TempDir()
	writeCatalogEntry(t, catalogDir, "alpha.yaml", "Alpha")
	writeCatalogEntry(t, catalogDir, "beta.yaml", "Beta")

	catalog := &v1.MCPCatalog{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       "MCPCatalog",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      system.DefaultCatalog,
			Namespace: system.DefaultNamespace,
		},
		Spec: v1.MCPCatalogSpec{
			DisplayName: "Default",
			SourceURLs:  []string{catalogDir},
		},
	}
	storageClient := newCatalogSyncFakeClient(catalog)
	gatewayClient := newCatalogGatewayClient(t, storageClient)
	handler := &Handler{gatewayClient: gatewayClient}

	resp := &router.ResponseWrapper{}
	require.NoError(t, handler.Sync(syncRequest(ctx, storageClient, catalog), resp))
	require.ElementsMatch(t, []string{"Alpha", "Beta"}, catalogEntryManifestNames(ctx, t, storageClient))

	require.NoError(t, os.Remove(filepath.Join(catalogDir, "beta.yaml")))
	synced := getCatalog(ctx, t, storageClient)

	resp = &router.ResponseWrapper{}
	require.NoError(t, handler.Sync(syncRequest(ctx, storageClient, synced), resp))
	require.True(t, resp.Delay > 0 && resp.Delay <= time.Hour)
	require.ElementsMatch(t, []string{"Alpha", "Beta"}, catalogEntryManifestNames(ctx, t, storageClient))

	forceSync := getCatalog(ctx, t, storageClient)
	forceSync.Annotations[v1.MCPCatalogSyncAnnotation] = "true"
	require.NoError(t, storageClient.Update(ctx, forceSync))

	resp = &router.ResponseWrapper{}
	require.NoError(t, handler.Sync(syncRequest(ctx, storageClient, getCatalog(ctx, t, storageClient)), resp))
	require.Equal(t, time.Hour, resp.Delay)
	require.Equal(t, []string{"Alpha"}, catalogEntryManifestNames(ctx, t, storageClient))

	afterForce := getCatalog(ctx, t, storageClient)
	require.NotContains(t, afterForce.Annotations, v1.MCPCatalogSyncAnnotation)
}

func TestSyncRetriesSourceFailuresAfterShortBackoffWithoutPruning(t *testing.T) {
	ctx := context.Background()
	catalogDir := t.TempDir()
	writeCatalogEntry(t, catalogDir, "alpha.yaml", "Alpha")

	catalog := &v1.MCPCatalog{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       "MCPCatalog",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      system.DefaultCatalog,
			Namespace: system.DefaultNamespace,
		},
		Spec: v1.MCPCatalogSpec{
			DisplayName: "Default",
			SourceURLs:  []string{catalogDir},
		},
	}
	storageClient := newCatalogSyncFakeClient(catalog)
	handler := &Handler{gatewayClient: newCatalogGatewayClient(t, storageClient)}

	resp := &router.ResponseWrapper{}
	require.NoError(t, handler.Sync(syncRequest(ctx, storageClient, catalog), resp))
	require.Equal(t, []string{"Alpha"}, catalogEntryManifestNames(ctx, t, storageClient))

	failingCatalog := getCatalog(ctx, t, storageClient)
	failingSource := filepath.Join(t.TempDir(), "missing")
	failingCatalog.Spec.SourceURLs = []string{failingSource}
	failingCatalog.Annotations[v1.MCPCatalogSyncAnnotation] = "true"
	require.NoError(t, storageClient.Update(ctx, failingCatalog))

	resp = &router.ResponseWrapper{}
	require.NoError(t, handler.Sync(syncRequest(ctx, storageClient, getCatalog(ctx, t, storageClient)), resp))
	require.Equal(t, 30*time.Second, resp.Delay)
	require.Equal(t, []string{"Alpha"}, catalogEntryManifestNames(ctx, t, storageClient))
	require.Contains(t, getCatalog(ctx, t, storageClient).Status.SyncErrors, failingSource)

	resp = &router.ResponseWrapper{}
	require.NoError(t, handler.Sync(syncRequest(ctx, storageClient, getCatalog(ctx, t, storageClient)), resp))
	require.True(t, resp.Delay > 0 && resp.Delay <= 30*time.Second)
}

func TestSyncSystemRetriesSourceFailuresAfterShortBackoffWithoutPruning(t *testing.T) {
	ctx := context.Background()
	catalogDir := t.TempDir()
	writeCatalogEntry(t, catalogDir, "alpha.yaml", "Alpha")

	catalog := &v1.SystemMCPCatalog{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       "SystemMCPCatalog",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system",
			Namespace: system.DefaultNamespace,
		},
		Spec: v1.SystemMCPCatalogSpec{
			DisplayName: "System",
			SourceURLs:  []string{catalogDir},
		},
	}
	storageClient := newCatalogSyncFakeClient(catalog)
	handler := &Handler{gatewayClient: newCatalogGatewayClient(t, storageClient)}

	resp := &router.ResponseWrapper{}
	require.NoError(t, handler.SyncSystem(syncRequestForObject(ctx, storageClient, catalog), resp))
	require.Equal(t, []string{"Alpha"}, systemCatalogEntryManifestNames(ctx, t, storageClient))

	failingCatalog := getSystemCatalog(ctx, t, storageClient, catalog.Name)
	failingSource := filepath.Join(t.TempDir(), "missing")
	failingCatalog.Spec.SourceURLs = []string{failingSource}
	failingCatalog.Annotations[v1.SystemMCPCatalogSyncAnnotation] = "true"
	require.NoError(t, storageClient.Update(ctx, failingCatalog))

	resp = &router.ResponseWrapper{}
	require.NoError(t, handler.SyncSystem(syncRequestForObject(ctx, storageClient, getSystemCatalog(ctx, t, storageClient, catalog.Name)), resp))
	require.Equal(t, 30*time.Second, resp.Delay)
	require.Equal(t, []string{"Alpha"}, systemCatalogEntryManifestNames(ctx, t, storageClient))
	require.Contains(t, getSystemCatalog(ctx, t, storageClient, catalog.Name).Status.SyncErrors, failingSource)

	resp = &router.ResponseWrapper{}
	require.NoError(t, handler.SyncSystem(syncRequestForObject(ctx, storageClient, getSystemCatalog(ctx, t, storageClient, catalog.Name)), resp))
	require.True(t, resp.Delay > 0 && resp.Delay <= 30*time.Second)
}

func newCatalogSyncFakeClient(objects ...kclient.Object) kclient.WithWatch {
	restMapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{v1.SchemeGroupVersion})
	restMapper.Add(v1.SchemeGroupVersion.WithKind("MCPCatalog"), meta.RESTScopeNamespace)
	restMapper.Add(v1.SchemeGroupVersion.WithKind("MCPServerCatalogEntry"), meta.RESTScopeNamespace)
	restMapper.Add(v1.SchemeGroupVersion.WithKind("SystemMCPCatalog"), meta.RESTScopeNamespace)
	restMapper.Add(v1.SchemeGroupVersion.WithKind("SystemMCPServerCatalogEntry"), meta.RESTScopeNamespace)

	return fake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithRESTMapper(restMapper).
		WithIndex(&v1.MCPServerCatalogEntry{}, "spec.mcpCatalogName", func(obj kclient.Object) []string {
			entry := obj.(*v1.MCPServerCatalogEntry)
			if entry.Spec.MCPCatalogName == "" {
				return nil
			}
			return []string{entry.Spec.MCPCatalogName}
		}).
		WithIndex(&v1.MCPServer{}, "spec.mcpServerCatalogEntryName", func(obj kclient.Object) []string {
			server := obj.(*v1.MCPServer)
			if server.Spec.MCPServerCatalogEntryName == "" {
				return nil
			}
			return []string{server.Spec.MCPServerCatalogEntryName}
		}).
		WithStatusSubresource(&v1.MCPCatalog{}, &v1.MCPServerCatalogEntry{}, &v1.SystemMCPCatalog{}, &v1.SystemMCPServerCatalogEntry{}).
		WithObjects(objects...).
		Build()
}

func newCatalogGatewayClient(t *testing.T, storageClient kclient.WithWatch) *gatewayclient.Client {
	t.Helper()

	services, err := storageservices.New(storageservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())

	ctx, cancel := context.WithCancel(context.Background())
	client := gatewayclient.New(ctx, db, storageClient, nil, nil, nil, nil, time.Hour, 100, 1, 1, 1, true)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, client.Close())
	})
	return client
}

func syncRequest(ctx context.Context, storageClient kclient.WithWatch, catalog *v1.MCPCatalog) router.Request {
	return router.Request{
		Client:    storageClient,
		Object:    catalog,
		Ctx:       ctx,
		Namespace: catalog.Namespace,
		Name:      catalog.Name,
		Key:       catalog.Namespace + "/" + catalog.Name,
	}
}

func syncRequestForObject(ctx context.Context, storageClient kclient.WithWatch, object kclient.Object) router.Request {
	return router.Request{
		Client:    storageClient,
		Object:    object,
		Ctx:       ctx,
		Namespace: object.GetNamespace(),
		Name:      object.GetName(),
		Key:       object.GetNamespace() + "/" + object.GetName(),
	}
}

func writeCatalogEntry(t *testing.T, dir, filename, name string) {
	t.Helper()

	content := `name: ` + name + `
description: ` + name + ` MCP
runtime: npx
serverUserType: multiUser
npxConfig:
  package: test-server
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o600))
}

func catalogEntryManifestNames(ctx context.Context, t *testing.T, storageClient kclient.Client) []string {
	t.Helper()

	var entries v1.MCPServerCatalogEntryList
	require.NoError(t, storageClient.List(ctx, &entries, kclient.InNamespace(system.DefaultNamespace)))
	names := make([]string, 0, len(entries.Items))
	for _, entry := range entries.Items {
		names = append(names, entry.Spec.Manifest.Name)
	}
	slices.Sort(names)
	return names
}

func systemCatalogEntryManifestNames(ctx context.Context, t *testing.T, storageClient kclient.Client) []string {
	t.Helper()

	var entries v1.SystemMCPServerCatalogEntryList
	require.NoError(t, storageClient.List(ctx, &entries, kclient.InNamespace(system.DefaultNamespace)))
	names := make([]string, 0, len(entries.Items))
	for _, entry := range entries.Items {
		names = append(names, entry.Spec.Manifest.Name)
	}
	slices.Sort(names)
	return names
}

func getCatalog(ctx context.Context, t *testing.T, storageClient kclient.Client) *v1.MCPCatalog {
	t.Helper()

	var catalog v1.MCPCatalog
	require.NoError(t, storageClient.Get(ctx, kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: system.DefaultCatalog}, &catalog))
	if catalog.Annotations == nil {
		catalog.Annotations = map[string]string{}
	}
	return &catalog
}

func getSystemCatalog(ctx context.Context, t *testing.T, storageClient kclient.Client, name string) *v1.SystemMCPCatalog {
	t.Helper()

	var catalog v1.SystemMCPCatalog
	require.NoError(t, storageClient.Get(ctx, kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: name}, &catalog))
	if catalog.Annotations == nil {
		catalog.Annotations = map[string]string{}
	}
	return &catalog
}
