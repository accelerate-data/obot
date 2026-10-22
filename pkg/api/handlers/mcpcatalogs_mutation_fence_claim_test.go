package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): a static OAuth Save and
// every catalog entry update or deletion share one catalog mutation fence, so a
// provider URL cannot change between a Save's proof claim and its commit. Kept
// in its own file so an upstream sync cannot drop these tests by merging over a
// shared one.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obot-platform/obot/pkg/api"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
)

// requireWaitsForCatalogMutationFence holds the shared fence, proves the call
// blocks on it, then releases it and expects the call to finish cleanly.
func requireWaitsForCatalogMutationFence(t *testing.T, gateway *gatewayclient.Client, name string, call func() error) {
	t.Helper()
	// The literal lock name is asserted, not the constant, so a rename that
	// splits the handler and controller fences fails here.
	release, err := gateway.AcquireCredentialLock(t.Context(), "mcp-static-oauth-catalog-mutation")
	require.NoError(t, err)

	result := make(chan error, 1)
	go func() { result <- call() }()
	select {
	case err := <-result:
		release()
		t.Fatalf("%s bypassed the catalog mutation fence: %v", name, err)
	case <-time.After(250 * time.Millisecond):
	}
	release()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for fenced %s", name)
	}
}

func newEditableEntryRequest(t *testing.T, gateway *gatewayclient.Client, method, body string, entry *v1.MCPServerCatalogEntry) api.Context {
	t.Helper()
	req := newStaticOAuthTestRequest(t, method, "/", body, httptest.NewRecorder(), gateway,
		&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)
	return req
}

func TestStaticOAuthSaveAndProviderUpdateShareCatalogMutationFence(t *testing.T) {
	t.Run("Save waits for catalog mutation", func(t *testing.T) {
		gateway := newOAuthCredentialTestGatewayClient(t)
		entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
		proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
		req, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)

		requireWaitsForCatalogMutationFence(t, gateway, "Save", func() error {
			return (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).SetOAuthCredentials(req)
		})
	})

	t.Run("provider update waits for credential mutation", func(t *testing.T) {
		gateway := newOAuthCredentialTestGatewayClient(t)
		entry := staticOAuthTestEntry("entry-1", "default", "https://example.com/old")
		entry.Spec.Editable = true
		manifest := entry.Spec.Manifest
		remote := *manifest.RemoteConfig
		remote.FixedURL = "https://example.com/new"
		manifest.RemoteConfig = &remote
		body, err := json.Marshal(manifest)
		require.NoError(t, err)
		req := newEditableEntryRequest(t, gateway, http.MethodPut, string(body), entry)

		requireWaitsForCatalogMutationFence(t, gateway, "provider update", func() error {
			return (&MCPCatalogHandler{gatewayClient: gateway}).UpdateEntry(req)
		})
	})

	t.Run("entry deletion waits for credential mutation", func(t *testing.T) {
		gateway := newOAuthCredentialTestGatewayClient(t)
		entry := staticOAuthTestEntry("entry-1", "default", "https://example.com/old")
		entry.Spec.Editable = true
		req := newEditableEntryRequest(t, gateway, http.MethodDelete, "", entry)

		requireWaitsForCatalogMutationFence(t, gateway, "entry deletion", func() error {
			return (&MCPCatalogHandler{gatewayClient: gateway}).DeleteEntry(req)
		})
	})
}
