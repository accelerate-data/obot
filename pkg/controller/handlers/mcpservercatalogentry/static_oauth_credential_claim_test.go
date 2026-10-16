package mcpservercatalogentry

// Fork-only guarantee (fork #37, restored by VD-6903): static OAuth status fails closed for a
// credential that is incomplete for the current manifest, and cleanup is serialized with catalog
// mutation and removes only the grants and pending proofs the application issued. Kept in its own
// file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/obot-platform/nah/pkg/router"
	"github.com/obot-platform/obot/apiclient/types"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storageservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	claimFixedURL = "https://mcp.example/api"
)

type recordingTriggerBackend struct {
	lock sync.Mutex
	keys []string
}

func (r *recordingTriggerBackend) Trigger(_ context.Context, _ schema.GroupVersionKind, key string, _ time.Duration) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.keys = append(r.keys, key)
	return nil
}

func (r *recordingTriggerBackend) triggered() []string {
	r.lock.Lock()
	defer r.lock.Unlock()
	return append([]string(nil), r.keys...)
}

// newClaimGateway builds a real gateway client so the credential store, the grant tables and the
// credential locks under test are the production ones.
func newClaimGateway(t *testing.T, storageClient kclient.WithWatch, backend *recordingTriggerBackend) (*gatewayclient.Client, *gorm.DB) {
	t.Helper()
	if backend == nil {
		backend = &recordingTriggerBackend{}
	}
	services, err := storageservices.New(storageservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	database, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, database.AutoMigrate())
	gateway := gatewayclient.New(t.Context(), database, storageClient, nil, backend, nil, nil, time.Hour, 10, 0, 0, 0, false)
	t.Cleanup(func() { require.NoError(t, gateway.Close()) })
	return gateway, services.DB.DB
}

func claimEntry(runtime types.Runtime, staticRequired bool) *v1.MCPServerCatalogEntry {
	manifest := types.MCPServerCatalogEntryManifest{Runtime: runtime}
	if runtime == types.RuntimeRemote {
		manifest.RemoteConfig = &types.RemoteCatalogConfig{FixedURL: claimFixedURL, StaticOAuthRequired: staticRequired}
	} else {
		manifest.ContainerizedConfig = &types.ContainerizedRuntimeConfig{Image: "example/mcp:latest"}
	}
	entry := newMCPServerCatalogEntry("entry-1", manifest)
	entry.Status.OAuthCredentialConfigured = true
	return entry
}

func readyStaticSecrets() map[string]string {
	return map[string]string{
		"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "MCP_URL": claimFixedURL, "GENERATION": "generation-1",
	}
}

func upsertStaticCredential(t *testing.T, gateway *gatewayclient.Client, entryName string, secrets map[string]string) {
	t.Helper()
	require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName), Name: system.StaticOAuthCredentialName, Secrets: secrets,
	}))
}

func entryRequest(t *testing.T, storageClient kclient.WithWatch, entry *v1.MCPServerCatalogEntry) router.Request {
	t.Helper()
	return router.Request{Client: storageClient, Ctx: t.Context(), Object: entry, Namespace: entry.Namespace, Name: entry.Name}
}

func countRows(t *testing.T, db *gorm.DB, model any, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(model).Where(query, args...).Count(&n).Error)
	return n
}

// A credential that cannot complete OAuth for the entry's current FixedURL must not be reported
// as configured, even when the status already says so and no sync annotation forces a recheck: a
// manifest edit never sets that annotation.
func TestEnsureOAuthCredentialStatusFailsClosedForIncompleteCredential(t *testing.T) {
	for _, tt := range []struct {
		name    string
		secrets map[string]string
	}{
		{name: "client secret missing", secrets: map[string]string{
			"CLIENT_ID": "client", "MCP_URL": claimFixedURL, "GENERATION": "generation-1",
		}},
		{name: "generation missing", secrets: map[string]string{
			"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "MCP_URL": claimFixedURL,
		}},
		{name: "bound to a previous fixed URL", secrets: map[string]string{
			"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "MCP_URL": "https://old.example/api", "GENERATION": "generation-1",
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entry := claimEntry(types.RuntimeRemote, true)
			storageClient := newFakeClient(entry)
			gateway, _ := newClaimGateway(t, storageClient, nil)
			upsertStaticCredential(t, gateway, entry.Name, tt.secrets)

			require.NoError(t, reconcileOAuthCredential(entryRequest(t, storageClient, entry), gateway))

			var updated v1.MCPServerCatalogEntry
			require.NoError(t, storageClient.Get(t.Context(), router.Key(entry.Namespace, entry.Name), &updated))
			require.False(t, updated.Status.OAuthCredentialConfigured)
		})
	}
}

// A queued cleanup pass can observe an entry that an admin has since switched back to static
// OAuth. Holding the catalog mutation lock while the restore lands proves cleanup waits for it
// and re-reads the entry instead of deleting the restored application.
func TestStaticOAuthControllerCleanupPreservesRestoredProviderState(t *testing.T) {
	staleEntry := claimEntry(types.RuntimeRemote, false)
	storageClient := newFakeClient(staleEntry)
	gateway, db := newClaimGateway(t, storageClient, nil)
	upsertStaticCredential(t, gateway, staleEntry.Name, readyStaticSecrets())
	require.NoError(t, db.Create(&gatewaytypes.MCPOAuthToken{
		MCPID: "deployment-1", UserID: "user-1", CatalogEntryName: staleEntry.Name, CatalogCredentialGeneration: "generation-1",
	}).Error)

	releaseCatalogMutationLock, err := gateway.AcquireCredentialLock(t.Context(), system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	defer releaseCatalogMutationLock()

	cleanupDone := make(chan error, 1)
	go func() {
		cleanupDone <- reconcileOAuthCredential(entryRequest(t, storageClient, staleEntry.DeepCopy()), gateway)
	}()

	select {
	case err := <-cleanupDone:
		t.Fatalf("cleanup finished without waiting for the catalog mutation lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	restoredEntry := staleEntry.DeepCopy()
	restoredEntry.Spec.Manifest.RemoteConfig.StaticOAuthRequired = true
	require.NoError(t, storageClient.Update(t.Context(), restoredEntry))
	releaseCatalogMutationLock()
	require.NoError(t, <-cleanupDone)

	_, err = gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(staleEntry.Name)}, system.StaticOAuthCredentialName)
	require.NoError(t, err, "restored static OAuth application must survive the stale cleanup")
	require.EqualValues(t, 1, countRows(t, db, &gatewaytypes.MCPOAuthToken{}, "catalog_entry_name = ?", staleEntry.Name))
	var stored v1.MCPServerCatalogEntry
	require.NoError(t, storageClient.Get(t.Context(), router.Key(staleEntry.Namespace, staleEntry.Name), &stored))
	require.True(t, stored.Status.OAuthCredentialConfigured, "a stale pass must not clear the restored entry's status")
}

// Removing a static OAuth application deletes the grants it issued, its pending connection
// proofs and the credential, and re-evaluates the entry's deployments. Users' own grants on those
// deployments survive while the entry does; deleting the entry revokes them too. Other entries'
// grants are always left in place.
func TestStaticOAuthControllerCleanupScopesGrantRemovalByLifecycle(t *testing.T) {
	for _, tt := range []struct {
		name    string
		entry   func() *v1.MCPServerCatalogEntry
		secrets map[string]string
		cleanup func(router.Request, credentialClient) error
	}{
		{
			name:    "provider no longer requires static OAuth",
			entry:   func() *v1.MCPServerCatalogEntry { return claimEntry(types.RuntimeRemote, false) },
			cleanup: reconcileOAuthCredential,
		},
		{
			// A credential written before generations existed issued untracked grants
			// only, so nothing ties a deployment's grant to it; it must still be removed.
			name:    "credential without a generation",
			entry:   func() *v1.MCPServerCatalogEntry { return claimEntry(types.RuntimeRemote, false) },
			secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "MCP_URL": claimFixedURL},
			cleanup: reconcileOAuthCredential,
		},
		{
			name:    "provider changed to a non-remote runtime",
			entry:   func() *v1.MCPServerCatalogEntry { return claimEntry(types.RuntimeContainerized, false) },
			cleanup: reconcileOAuthCredential,
		},
		{
			name: "catalog entry deletion",
			entry: func() *v1.MCPServerCatalogEntry {
				entry := claimEntry(types.RuntimeRemote, true)
				entry.DeletionTimestamp = &metav1.Time{Time: time.Now()}
				entry.Finalizers = []string{v1.MCPServerCatalogEntryFinalizer}
				return entry
			},
			cleanup: removeOAuthCredentials,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entry := tt.entry()
			server := newMCPServer(system.MCPServerPrefix+"server", types.MCPServerManifest{Runtime: types.RuntimeRemote})
			server.Spec.MCPServerCatalogEntryName = entry.Name
			instance := &v1.MCPServerInstance{
				Name: system.MCPServerInstancePrefix + "instance", Namespace: entry.Namespace,
				Spec: v1.MCPServerInstanceSpec{MCPServerCatalogEntryName: entry.Name, MCPServerName: server.Name},
			}
			storageClient := newFakeClient(entry, server, instance)
			backend := &recordingTriggerBackend{}
			gateway, db := newClaimGateway(t, storageClient, backend)
			secrets := tt.secrets
			if secrets == nil {
				secrets = readyStaticSecrets()
			}
			upsertStaticCredential(t, gateway, entry.Name, secrets)
			require.NoError(t, db.Create(&[]gatewaytypes.MCPOAuthToken{
				{MCPID: "fenced-grant", UserID: "user-1", CatalogEntryName: entry.Name, CatalogCredentialGeneration: "generation-1"},
				{MCPID: server.Name, UserID: "user-2"},
				{MCPID: instance.Name, UserID: "user-3"},
				{MCPID: "unrelated", UserID: "user-4", CatalogEntryName: "other-entry"},
			}).Error)
			require.NoError(t, db.Create(&gatewaytypes.MCPOAuthPendingState{
				HashedState: "pending-hash", MCPID: entry.Name, StaticOAuthTest: true,
			}).Error)

			require.NoError(t, tt.cleanup(entryRequest(t, storageClient, entry), gateway))

			_, err := gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(entry.Name)}, system.StaticOAuthCredentialName)
			require.Error(t, err, "static OAuth credential must be removed")
			require.Zero(t, countRows(t, db, &gatewaytypes.MCPOAuthToken{}, "catalog_entry_name = ?", entry.Name), "grants issued by the application")
			require.Zero(t, countRows(t, db, &gatewaytypes.MCPOAuthPendingState{}, "mcp_id = ? AND static_o_auth_test = ?", entry.Name, true), "pending connection proofs")
			require.EqualValues(t, 1, countRows(t, db, &gatewaytypes.MCPOAuthToken{}, "mcp_id = ?", "unrelated"), "another entry's grant")
			require.Contains(t, backend.triggered(), system.DefaultNamespace+"/"+server.Name, "deployments must re-evaluate their OAuth state")
			deploymentGrants := countRows(t, db, &gatewaytypes.MCPOAuthToken{}, "mcp_id IN ?", []string{server.Name, instance.Name})
			if entry.DeletionTimestamp.IsZero() {
				require.EqualValues(t, 2, deploymentGrants, "users' own grants on a deployment that outlives the application")
			} else {
				require.Zero(t, deploymentGrants, "grants on the deployments of a deleted entry")
			}
		})
	}
}
