package handlers

// Fork-only guarantees (restored by VD-6903): configuring a server replaces its
// credential under a per-credential lock, so concurrent configurations cannot
// interleave their delete and create, and it reconciles the owning server under
// its namespaced key (VD-4889). Kept in its own file so an upstream sync cannot
// drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nahbackend "github.com/obot-platform/nah/pkg/backend"
	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kschema "k8s.io/apimachinery/pkg/runtime/schema"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type noopConfigureServerTrigger struct{}

// recordingConfigureServerTrigger captures what a handler asked the controller to
// reconcile, so a test can assert the enqueued kind and key rather than only that
// some callback ran.
type recordingConfigureServerTrigger struct {
	lock sync.Mutex
	gvks []kschema.GroupVersionKind
	keys []string
}

func (noopConfigureServerTrigger) Trigger(context.Context, kschema.GroupVersionKind, string, time.Duration) error {
	return nil
}

func (r *recordingConfigureServerTrigger) Trigger(_ context.Context, gvk kschema.GroupVersionKind, key string, _ time.Duration) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.gvks = append(r.gvks, gvk)
	r.keys = append(r.keys, key)
	return nil
}

func (r *recordingConfigureServerTrigger) recorded() ([]kschema.GroupVersionKind, []string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	return append([]kschema.GroupVersionKind(nil), r.gvks...), append([]string(nil), r.keys...)
}

func configureServerClaimTestObjects() (v1.MCPServerCatalogEntry, v1.MCPServer) {
	entry := v1.MCPServerCatalogEntry{
		Name:      "entry",
		Namespace: system.DefaultNamespace,
		Spec: v1.MCPServerCatalogEntrySpec{
			MCPCatalogName: "default",
			Manifest: types.MCPServerCatalogEntryManifest{
				Name:    "entry",
				Runtime: types.RuntimeRemote,
			},
		},
	}
	server := v1.MCPServer{
		Name:      "server",
		Namespace: system.DefaultNamespace,
		Spec: v1.MCPServerSpec{
			MCPCatalogID:              "default",
			MCPServerCatalogEntryName: "entry",
			Manifest: types.MCPServerManifest{
				Name:         "server",
				Runtime:      types.RuntimeRemote,
				RemoteConfig: &types.RemoteRuntimeConfig{URL: "https://example.com/mcp"},
			},
		},
	}
	return entry, server
}

func configureServerClaimRequest(storage kclient.WithWatch, gatewayClient *gateway.Client, config string, shutdown func(string) error, backend nahbackend.Trigger) error {
	request := httptest.NewRequest(http.MethodPost, "/api/mcp-catalogs/default/servers/server/configure", strings.NewReader(config))
	request.SetPathValue("catalog_id", "default")
	request.SetPathValue("mcp_server_id", "server")

	return (&MCPHandler{
		controllerBackend: backend,
		shutdownMCPServer: shutdown,
	}).ConfigureServer(api.Context{
		ResponseWriter: httptest.NewRecorder(),
		Request:        request,
		Storage:        storage,
		GatewayClient:  gatewayClient,
		User:           testUser("owner"),
	})
}

func TestConfigureServerTriggersOwningServerUnderNamespacedKey(t *testing.T) {
	entry, server := configureServerClaimTestObjects()
	storage := newFakeStorage(t, &entry, &server)
	backend := &recordingConfigureServerTrigger{}

	require.NoError(t, configureServerClaimRequest(storage, newHandlerTestGateway(t), `{"TOKEN":"value"}`, func(string) error { return nil }, backend))

	gvks, keys := backend.recorded()
	// A bare name resolves to the empty namespace, where no MCPServer is ever
	// stored, so the reconcile would be dropped before any handler ran.
	assert.Equal(t, []string{system.DefaultNamespace + "/server"}, keys)
	for _, gvk := range gvks {
		assert.Equal(t, "MCPServer", gvk.Kind)
	}
}

func TestConfigureServerSerializesCredentialReplacement(t *testing.T) {
	entry, server := configureServerClaimTestObjects()
	storage := newFakeStorage(t, &entry, &server)
	gatewayClient := newHandlerTestGateway(t)
	require.NoError(t, gatewayClient.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: "default-server",
		Name:    "server",
		Secrets: map[string]string{"TOKEN": "initial"},
	}))

	firstDeleted := make(chan struct{})
	secondDeleted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var shutdownCalls atomic.Int32
	shutdown := func(string) error {
		switch shutdownCalls.Add(1) {
		case 1:
			close(firstDeleted)
			<-releaseFirst
		case 2:
			close(secondDeleted)
		}
		return nil
	}

	firstErr := make(chan error, 1)
	go func() {
		firstErr <- configureServerClaimRequest(storage, gatewayClient, `{"TOKEN":"first"}`, shutdown, noopConfigureServerTrigger{})
	}()

	select {
	case <-firstDeleted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first credential deletion")
	}
	_, err := gatewayClient.RevealCredential(t.Context(), []string{"default-server"}, "server")
	var notFound gateway.CredentialNotFoundError
	require.Error(t, err)
	require.True(t, errors.As(err, &notFound))

	secondErr := make(chan error, 1)
	go func() {
		secondErr <- configureServerClaimRequest(storage, gatewayClient, `{"TOKEN":"second"}`, shutdown, noopConfigureServerTrigger{})
	}()
	select {
	case <-secondDeleted:
		t.Fatal("second configuration replaced credentials before the first completed")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseFirst)
	require.NoError(t, <-firstErr)
	require.NoError(t, <-secondErr)
	credential, err := gatewayClient.RevealCredential(t.Context(), []string{"default-server"}, "server")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"TOKEN": "second"}, credential.Secrets)
}
