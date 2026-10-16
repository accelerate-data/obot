package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): creating a server from a
// static OAuth catalog entry checks the credential store, not the entry's cached
// status, inside the catalog mutation fence, and releases that fence before the
// response is written. Kept in its own file so an upstream sync cannot drop
// these tests by merging over a shared one.

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// blockingResponseWriter stalls the first header write until released, standing
// in for a slow client.
type blockingResponseWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release chan struct{}
}

func (w *blockingResponseWriter) WriteHeader(statusCode int) {
	close(w.started)
	<-w.release
	w.ResponseRecorder.WriteHeader(statusCode)
}

func lockStaticOAuthForCreateReady(t *testing.T, gateway *gatewayclient.Client, reader kclient.Reader, entry *v1.MCPServerCatalogEntry) bool {
	t.Helper()
	release, _, ready, err := lockStaticOAuthCredentialForCreate(t.Context(), gateway, reader, kclient.ObjectKeyFromObject(entry))
	require.NoError(t, err)
	release()
	return ready
}

func TestStaticOAuthCredentialReadyUsesCredentialStoreInsteadOfCachedStatus(t *testing.T) {
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	entry.Status.OAuthCredentialConfigured = true
	gateway := newOAuthCredentialTestGatewayClient(t)
	storageClient := newFakeStorage(t, entry)

	assert.False(t, lockStaticOAuthForCreateReady(t, gateway, storageClient, entry),
		"stale configured status must not authorize creation after clear")

	seedStaticOAuthCredential(t, gateway, entry.Name, "client-1", "", "")
	assert.False(t, lockStaticOAuthForCreateReady(t, gateway, storageClient, entry),
		"legacy credentials without provider binding and generation must fail closed")

	seedStaticOAuthCredential(t, gateway, entry.Name, "client-1", entry.Spec.Manifest.RemoteConfig.FixedURL, "generation-1")
	assert.True(t, lockStaticOAuthForCreateReady(t, gateway, storageClient, entry),
		"an exact provider-bound generated credential must authorize creation")
}

func newStaticOAuthCreateFixture(t *testing.T, fixedURL string) (*v1.MCPServerCatalogEntry, kclient.WithWatch, *gatewayclient.Client) {
	t.Helper()
	entry := staticOAuthTestEntry("entry-1", "default", fixedURL)
	entry.Spec.Manifest.Name = "entry-1"
	storageClient := newFakeStorage(t, &v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
	gateway := newOAuthCredentialTestGatewayClient(t)
	seedStaticOAuthCredential(t, gateway, entry.Name, "client-1", fixedURL, "generation-1")
	return entry, storageClient, gateway
}

func TestCreateServerRereadsStaticOAuthProviderInsideCatalogMutationFence(t *testing.T) {
	entry, storageClient, gateway := newStaticOAuthCreateFixture(t, "https://example.com/old")

	releaseCatalogMutation, err := gateway.AcquireCredentialLock(t.Context(), system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	req := newCreateServerSecretBindingRequest(t, storageClient, nil, "default", "", types.MCPServer{CatalogEntryID: entry.Name})
	req.GatewayClient = gateway
	result := make(chan error, 1)
	go func() {
		result <- newCreateServerSecretBindingTestHandler().CreateServer(req)
	}()

	select {
	case err := <-result:
		releaseCatalogMutation()
		t.Fatalf("server creation bypassed the catalog mutation fence: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	// The provider moves while creation waits; the credential stays bound to
	// the old provider, so the fenced re-read must refuse it.
	var updated v1.MCPServerCatalogEntry
	require.NoError(t, storageClient.Get(t.Context(), kclient.ObjectKeyFromObject(entry), &updated))
	updated.Spec.Manifest.RemoteConfig.FixedURL = "https://example.com/new"
	require.NoError(t, storageClient.Update(t.Context(), &updated))
	releaseCatalogMutation()

	select {
	case err := <-result:
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires OAuth configuration")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fenced server creation")
	}
	var servers v1.MCPServerList
	require.NoError(t, storageClient.List(t.Context(), &servers))
	require.Empty(t, servers.Items)
}

func TestCreateServerReleasesStaticOAuthFenceBeforeWritingResponse(t *testing.T) {
	entry, storageClient, gateway := newStaticOAuthCreateFixture(t, "https://example.com/mcp")

	response := &blockingResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		started:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	req := newCreateServerSecretBindingRequest(t, storageClient, nil, "default", "", types.MCPServer{CatalogEntryID: entry.Name})
	req.GatewayClient = gateway
	req.ResponseWriter = response
	handlerResult := make(chan error, 1)
	go func() {
		handlerResult <- newCreateServerSecretBindingTestHandler().CreateServer(req)
	}()

	select {
	case <-response.started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the post-create response")
	}

	type lockResult struct {
		release func()
		err     error
	}
	locked := make(chan lockResult, 1)
	go func() {
		release, err := gateway.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(entry.Name))
		locked <- lockResult{release: release, err: err}
	}()

	select {
	case result := <-locked:
		require.NoError(t, result.err)
		result.release()
		close(response.release)
		require.NoError(t, <-handlerResult)
	case <-time.After(time.Second):
		close(response.release)
		require.NoError(t, <-handlerResult)
		if result := <-locked; result.err == nil {
			result.release()
		}
		t.Fatal("static OAuth credential mutation remained blocked while the response writer stalled")
	}
}

func TestNonStaticCreateDoesNotAcquireStaticOAuthCredentialLock(t *testing.T) {
	entry := staticOAuthTestEntry("entry-1", "default", "https://example.com/mcp")
	entry.Spec.Manifest.RemoteConfig.StaticOAuthRequired = false
	storageClient := newFakeStorage(t, entry)
	gateway := newOAuthCredentialTestGatewayClient(t)

	releaseCredential, err := gateway.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(entry.Name))
	require.NoError(t, err)
	type lockResult struct {
		release func()
		ready   bool
		err     error
	}
	result := make(chan lockResult, 1)
	go func() {
		release, _, ready, err := lockStaticOAuthCredentialForCreate(t.Context(), gateway, storageClient, kclient.ObjectKeyFromObject(entry))
		result <- lockResult{release: release, ready: ready, err: err}
	}()

	select {
	case got := <-result:
		require.NoError(t, got.err)
		require.True(t, got.ready)
		got.release()
		releaseCredential()
	case <-time.After(time.Second):
		releaseCredential()
		if got := <-result; got.err == nil {
			got.release()
		}
		t.Fatal("non-static entry creation waited on the static OAuth credential lock")
	}
}
