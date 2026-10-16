package mcpcatalog

// Fork-only guarantee (VD-4883, restored by VD-6903): a catalog sync holds the
// static OAuth catalog mutation lock across removed-entry reconciliation and
// apply, so a static OAuth credential write that checked its entry still exists
// cannot interleave with that entry's removal. A sync cancelled while waiting
// for the lock changes nothing. Kept in its own file so an upstream sync cannot
// drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/nah/pkg/router"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestPartialCatalogSyncWaitsForMutationLockBeforeApply(t *testing.T) {
	ctx := context.Background()
	catalogDir := t.TempDir()
	writeCatalogEntry(t, catalogDir, "alpha.yaml", "Alpha")
	missingSource := filepath.Join(t.TempDir(), "missing")
	catalog := &v1.MCPCatalog{
		APIVersion: v1.SchemeGroupVersion.String(),
		Kind:       "MCPCatalog",
		Name:       system.DefaultCatalog,
		Namespace:  system.DefaultNamespace,
		Spec:       v1.MCPCatalogSpec{DisplayName: "Default", SourceURLs: []string{catalogDir, missingSource}},
	}
	entryCreated := make(chan struct{}, 1)
	storageClient := newCatalogSyncFakeClientWithInterceptor(interceptor.Funcs{
		Create: func(ctx context.Context, c kclient.WithWatch, obj kclient.Object, opts ...kclient.CreateOption) error {
			if _, ok := obj.(*v1.MCPServerCatalogEntry); ok {
				entryCreated <- struct{}{}
			}
			return c.Create(ctx, obj, opts...)
		},
	}, catalog)
	gatewayClient := newCatalogGatewayClient(t, storageClient)
	releaseLock, err := gatewayClient.AcquireCredentialLock(ctx, system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	released := false
	defer func() {
		if !released {
			releaseLock()
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- (&Handler{gatewayClient: gatewayClient}).Sync(syncRequest(ctx, storageClient, catalog), &router.ResponseWrapper{})
	}()
	require.Eventually(t, func() bool {
		return getCatalog(ctx, t, storageClient).Status.SyncErrors[missingSource] != ""
	}, 5*time.Second, 10*time.Millisecond)

	select {
	case <-entryCreated:
		t.Fatal("partial catalog apply ran before acquiring the mutation lock")
	case err := <-done:
		t.Fatalf("partial catalog sync returned before the mutation lock was released: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	releaseLock()
	released = true
	require.NoError(t, <-done)
	select {
	case <-entryCreated:
	case <-time.After(5 * time.Second):
		t.Fatal("partial catalog apply did not run after releasing the mutation lock")
	}
}

func TestCleanCatalogSyncWaitsForMutationLockBeforeRemoval(t *testing.T) {
	ctx := context.Background()
	catalogDir := t.TempDir()
	writeCatalogEntry(t, catalogDir, "alpha.yaml", "Alpha")
	catalog := &v1.MCPCatalog{
		APIVersion: v1.SchemeGroupVersion.String(),
		Kind:       "MCPCatalog",
		Name:       system.DefaultCatalog,
		Namespace:  system.DefaultNamespace,
		Spec:       v1.MCPCatalogSpec{DisplayName: "Default", SourceURLs: []string{catalogDir}},
	}
	entryDeleted := make(chan struct{}, 1)
	storageClient := newCatalogSyncFakeClientWithInterceptor(interceptor.Funcs{
		Delete: func(ctx context.Context, c kclient.WithWatch, obj kclient.Object, opts ...kclient.DeleteOption) error {
			if _, ok := obj.(*v1.MCPServerCatalogEntry); ok {
				entryDeleted <- struct{}{}
			}
			return c.Delete(ctx, obj, opts...)
		},
	}, catalog)
	gatewayClient := newCatalogGatewayClient(t, storageClient)
	handler := &Handler{gatewayClient: gatewayClient}
	require.NoError(t, handler.Sync(syncRequest(ctx, storageClient, catalog), &router.ResponseWrapper{}))
	require.Equal(t, []string{"Alpha"}, catalogEntryManifestNames(ctx, t, storageClient))
	require.NoError(t, os.Remove(filepath.Join(catalogDir, "alpha.yaml")))
	forced := getCatalog(ctx, t, storageClient)
	forced.Annotations[v1.MCPCatalogSyncAnnotation] = "true"
	require.NoError(t, storageClient.Update(ctx, forced))

	releaseLock, err := gatewayClient.AcquireCredentialLock(ctx, system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	released := false
	defer func() {
		if !released {
			releaseLock()
		}
	}()
	done := make(chan error, 1)
	go func() {
		done <- handler.Sync(syncRequest(ctx, storageClient, getCatalog(ctx, t, storageClient)), &router.ResponseWrapper{})
	}()
	require.Eventually(t, func() bool {
		return getCatalog(ctx, t, storageClient).Annotations[v1.MCPCatalogSyncAnnotation] == ""
	}, 5*time.Second, 10*time.Millisecond)

	select {
	case <-entryDeleted:
		t.Fatal("removed-entry reconciliation ran before acquiring the mutation lock")
	case err := <-done:
		t.Fatalf("clean catalog sync returned before the mutation lock was released: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	releaseLock()
	released = true
	require.NoError(t, <-done)
	select {
	case <-entryDeleted:
	case <-time.After(5 * time.Second):
		t.Fatal("removed-entry reconciliation did not run after releasing the mutation lock")
	}
}

func TestCleanCatalogRemovalAndApplyShareMutationLock(t *testing.T) {
	ctx := context.Background()
	catalogDir := t.TempDir()
	writeCatalogEntry(t, catalogDir, "alpha.yaml", "Alpha")
	catalog := &v1.MCPCatalog{
		APIVersion: v1.SchemeGroupVersion.String(),
		Kind:       "MCPCatalog",
		Name:       system.DefaultCatalog,
		Namespace:  system.DefaultNamespace,
		Spec:       v1.MCPCatalogSpec{DisplayName: "Default", SourceURLs: []string{catalogDir}},
	}
	baseClient := newCatalogSyncFakeClient(catalog)
	gatewayClient := newCatalogGatewayClient(t, baseClient)
	handler := &Handler{gatewayClient: gatewayClient}
	require.NoError(t, handler.Sync(syncRequest(ctx, baseClient, catalog), &router.ResponseWrapper{}))
	require.Equal(t, []string{"Alpha"}, catalogEntryManifestNames(ctx, t, baseClient))

	require.NoError(t, os.Remove(filepath.Join(catalogDir, "alpha.yaml")))
	writeCatalogEntry(t, catalogDir, "beta.yaml", "Beta")
	forced := getCatalog(ctx, t, baseClient)
	forced.Annotations[v1.MCPCatalogSyncAnnotation] = "true"
	require.NoError(t, baseClient.Update(ctx, forced))

	removalObserved := make(chan struct{})
	allowRemoval := make(chan struct{})
	applyEntered := make(chan struct{})
	releaseApply := make(chan struct{})
	var removalOnce, applyOnce sync.Once
	defer func() {
		removalOnce.Do(func() { close(removalObserved) })
		applyOnce.Do(func() { close(applyEntered) })
		select {
		case <-allowRemoval:
		default:
			close(allowRemoval)
		}
		select {
		case <-releaseApply:
		default:
			close(releaseApply)
		}
	}()
	storageClient := interceptor.NewClient(baseClient, interceptor.Funcs{
		Delete: func(ctx context.Context, c kclient.WithWatch, obj kclient.Object, opts ...kclient.DeleteOption) error {
			if _, ok := obj.(*v1.MCPServerCatalogEntry); ok {
				removalOnce.Do(func() { close(removalObserved) })
				<-allowRemoval
			}
			return c.Delete(ctx, obj, opts...)
		},
		Create: func(ctx context.Context, c kclient.WithWatch, obj kclient.Object, opts ...kclient.CreateOption) error {
			if _, ok := obj.(*v1.MCPServerCatalogEntry); ok {
				select {
				case <-removalObserved:
				default:
					return errors.New("catalog apply entered before removed-entry reconciliation")
				}
				applyOnce.Do(func() { close(applyEntered) })
				<-releaseApply
			}
			return c.Create(ctx, obj, opts...)
		},
	})

	syncDone := make(chan error, 1)
	go func() {
		syncDone <- handler.Sync(
			syncRequest(ctx, storageClient, getCatalog(ctx, t, baseClient)),
			&router.ResponseWrapper{},
		)
	}()
	select {
	case <-removalObserved:
	case <-time.After(5 * time.Second):
		t.Fatal("removed-entry reconciliation did not start")
	}

	close(allowRemoval)
	select {
	case <-applyEntered:
	case err := <-syncDone:
		t.Fatalf("clean catalog sync returned before apply: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("catalog apply did not start after removed-entry reconciliation")
	}
	waiterCtx, cancelWaiter := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancelWaiter()
	waiterDone := make(chan error, 1)
	go func() {
		release, err := gatewayClient.AcquireCredentialLock(waiterCtx, system.MCPStaticOAuthCatalogMutationLock)
		if err == nil {
			release()
		}
		waiterDone <- err
	}()
	require.ErrorIs(t, <-waiterDone, context.DeadlineExceeded)

	close(releaseApply)
	require.NoError(t, <-syncDone)
	releaseLock, err := gatewayClient.AcquireCredentialLock(ctx, system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	releaseLock()
	require.Equal(t, []string{"Beta"}, catalogEntryManifestNames(ctx, t, baseClient))
}

func TestCleanCatalogSyncCancellationWhileWaitingForMutationLockDoesNotRemoveOrApply(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	catalogDir := t.TempDir()
	writeCatalogEntry(t, catalogDir, "alpha.yaml", "Alpha")
	catalog := &v1.MCPCatalog{
		APIVersion: v1.SchemeGroupVersion.String(),
		Kind:       "MCPCatalog",
		Name:       system.DefaultCatalog,
		Namespace:  system.DefaultNamespace,
		Spec:       v1.MCPCatalogSpec{DisplayName: "Default", SourceURLs: []string{catalogDir}},
	}
	baseClient := newCatalogSyncFakeClient(catalog)
	gatewayClient := newCatalogGatewayClient(t, baseClient)
	handler := &Handler{gatewayClient: gatewayClient}
	require.NoError(t, handler.Sync(syncRequest(ctx, baseClient, catalog), &router.ResponseWrapper{}))
	require.Equal(t, []string{"Alpha"}, catalogEntryManifestNames(ctx, t, baseClient))

	require.NoError(t, os.Remove(filepath.Join(catalogDir, "alpha.yaml")))
	writeCatalogEntry(t, catalogDir, "beta.yaml", "Beta")
	forced := getCatalog(ctx, t, baseClient)
	forced.Annotations[v1.MCPCatalogSyncAnnotation] = "true"
	require.NoError(t, baseClient.Update(ctx, forced))

	var entryDeletes, entryCreates atomic.Int32
	storageClient := interceptor.NewClient(baseClient, interceptor.Funcs{
		Delete: func(ctx context.Context, c kclient.WithWatch, obj kclient.Object, opts ...kclient.DeleteOption) error {
			if _, ok := obj.(*v1.MCPServerCatalogEntry); ok {
				entryDeletes.Add(1)
			}
			return c.Delete(ctx, obj, opts...)
		},
		Create: func(ctx context.Context, c kclient.WithWatch, obj kclient.Object, opts ...kclient.CreateOption) error {
			if _, ok := obj.(*v1.MCPServerCatalogEntry); ok {
				entryCreates.Add(1)
			}
			return c.Create(ctx, obj, opts...)
		},
	})
	releaseLock, err := gatewayClient.AcquireCredentialLock(context.Background(), system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	defer releaseLock()

	done := make(chan error, 1)
	go func() {
		done <- handler.Sync(
			syncRequest(ctx, storageClient, getCatalog(context.Background(), t, baseClient)),
			&router.ResponseWrapper{},
		)
	}()
	require.Eventually(t, func() bool {
		return getCatalog(context.Background(), t, baseClient).Annotations[v1.MCPCatalogSyncAnnotation] == ""
	}, 5*time.Second, 10*time.Millisecond)
	cancel()

	err = <-done
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, entryDeletes.Load())
	require.Zero(t, entryCreates.Load())
	require.Equal(t, []string{"Alpha"}, catalogEntryManifestNames(context.Background(), t, baseClient))
}

func TestPartialCatalogSyncCancellationWhileWaitingForMutationLockDoesNotApply(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	catalogDir := t.TempDir()
	writeCatalogEntry(t, catalogDir, "alpha.yaml", "Alpha")
	missingSource := filepath.Join(t.TempDir(), "missing")
	catalog := &v1.MCPCatalog{
		APIVersion: v1.SchemeGroupVersion.String(),
		Kind:       "MCPCatalog",
		Name:       system.DefaultCatalog,
		Namespace:  system.DefaultNamespace,
		Spec:       v1.MCPCatalogSpec{DisplayName: "Default", SourceURLs: []string{catalogDir, missingSource}},
	}
	var entryCreates atomic.Int32
	storageClient := newCatalogSyncFakeClientWithInterceptor(interceptor.Funcs{
		Create: func(ctx context.Context, c kclient.WithWatch, obj kclient.Object, opts ...kclient.CreateOption) error {
			if _, ok := obj.(*v1.MCPServerCatalogEntry); ok {
				entryCreates.Add(1)
			}
			return c.Create(ctx, obj, opts...)
		},
	}, catalog)
	gatewayClient := newCatalogGatewayClient(t, storageClient)
	releaseLock, err := gatewayClient.AcquireCredentialLock(context.Background(), system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	defer releaseLock()

	done := make(chan error, 1)
	go func() {
		done <- (&Handler{gatewayClient: gatewayClient}).Sync(syncRequest(ctx, storageClient, catalog), &router.ResponseWrapper{})
	}()
	require.Eventually(t, func() bool {
		return getCatalog(context.Background(), t, storageClient).Status.SyncErrors[missingSource] != ""
	}, 5*time.Second, 10*time.Millisecond)
	cancel()

	err = <-done
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, entryCreates.Load())
}
