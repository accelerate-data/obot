package mcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func staticOAuthVMCPForClaim() *v1.VMCP {
	return &v1.VMCP{Name: "vmcp1static", Namespace: system.DefaultNamespace, Spec: v1.VMCPSpec{
		UserID: "user", Manifest: types.VMCPManifest{Components: []types.VMCPComponent{{ID: "one", Name: "Provider", MCPServerCatalogEntryID: "entry", CatalogEntry: types.MCPServerCatalogEntrySnapshot{Manifest: types.MCPServerCatalogEntryManifest{
			Runtime: types.RuntimeRemote, RemoteConfig: &types.RemoteCatalogConfig{FixedURL: "https://mcp.example/api", StaticOAuthRequired: true},
		}}}}},
	}, Status: v1.VMCPStatus{Components: []v1.VMCPComponentStatus{{Name: "Provider", OAuthCredentialConfigured: true, OAuthCredentialCheckHash: "stale-ready"}}}}
}

// A controller's stale ready status cannot admit a new connection after Clear,
// a provider edit, or an incomplete/unproved credential write.
func TestVMCPConnectRequiresProvedStaticOAuthBeforeCreatingInstance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secrets map[string]string
	}{
		{name: "cleared"},
		{name: "unproved", secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "MCP_URL": "https://mcp.example/api"}},
		{name: "other provider", secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "GENERATION": "proved", "MCP_URL": "https://other.example/api"}},
		{name: "incomplete", secrets: map[string]string{"CLIENT_ID": "client", "GENERATION": "proved", "MCP_URL": "https://mcp.example/api"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vmcp := staticOAuthVMCPForClaim()
			storage := newVMCPTestStorage(vmcp)
			gateway := newCatalogTokenStoreTestClient(t, "entry", "unused", true)
			if tc.secrets != nil {
				require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName("entry"), Name: system.StaticOAuthCredentialName, Secrets: tc.secrets}))
			}
			manager := &SessionManager{storageClient: storage, gatewayClient: gateway}
			_, err := manager.ServerConfigForVMCP(t.Context(), vmcp.Name, &kuser.DefaultInfo{UID: "user"})
			require.ErrorContains(t, err, "requires administrator static OAuth configuration")
			var instances v1.VMCPInstanceList
			require.NoError(t, storage.List(t.Context(), &instances))
			require.Empty(t, instances.Items)
		})
	}
}

func TestVMCPConnectHoldsStaticOAuthFenceThroughInstanceCreation(t *testing.T) {
	vmcp := staticOAuthVMCPForClaim()
	gateway := newCatalogTokenStoreTestClient(t, "entry", "unused", true)
	require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName("entry"), Name: system.StaticOAuthCredentialName, Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "GENERATION": "proved", "MCP_URL": "https://mcp.example/api"}}))
	enteredCreate := make(chan struct{})
	finishCreate := make(chan struct{})
	creationStopped := errors.New("stop after observing fenced creation")
	storage := interceptor.NewClient(newVMCPTestStorage(vmcp), interceptor.Funcs{Create: func(_ context.Context, _ kclient.WithWatch, obj kclient.Object, _ ...kclient.CreateOption) error {
		if _, ok := obj.(*v1.VMCPInstance); ok {
			close(enteredCreate)
			<-finishCreate
			return creationStopped
		}
		return errors.New("unexpected create")
	}})
	manager := &SessionManager{storageClient: storage, gatewayClient: gateway}
	connectDone := make(chan error, 1)
	go func() {
		_, err := manager.ServerConfigForVMCP(t.Context(), vmcp.Name, &kuser.DefaultInfo{UID: "user"})
		connectDone <- err
	}()
	select {
	case <-enteredCreate:
	case <-time.After(5 * time.Second):
		t.Fatal("connection never reached creation")
	}
	clearStarted := make(chan struct{})
	clearDone := make(chan error, 1)
	go func() {
		close(clearStarted)
		// Save/Clear handlers acquire catalog then credential before calling the
		// gateway mutation; the gateway method itself expects those caller locks.
		releaseCatalog, err := gateway.AcquireCredentialLock(t.Context(), system.MCPStaticOAuthCatalogMutationLock)
		if err != nil {
			clearDone <- err
			return
		}
		defer releaseCatalog()
		releaseCredential, err := gateway.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName("entry"))
		if err != nil {
			clearDone <- err
			return
		}
		defer releaseCredential()
		_, err = gateway.DeleteMCPStaticOAuthCredential(t.Context(), "entry")
		clearDone <- err
	}()
	<-clearStarted
	select {
	case err := <-clearDone:
		t.Fatalf("Clear crossed connection persistence fence: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(finishCreate)
	require.ErrorIs(t, <-connectDone, creationStopped)
	select {
	case err := <-clearDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Clear did not resume after persistence")
	}
}

func TestVMCPConnectRereadsDefinitionInsideCatalogFence(t *testing.T) {
	current := staticOAuthVMCPForClaim()
	stale := current.DeepCopy()
	stale.Spec.Manifest.Components[0].CatalogEntry.Manifest.RemoteConfig.StaticOAuthRequired = false
	storage := newVMCPTestStorage(current)
	gateway := newCatalogTokenStoreTestClient(t, "entry", "unused", true)
	manager := &SessionManager{storageClient: storage, gatewayClient: gateway}
	_, err := manager.serverConfigForVMCP(t.Context(), stale, nil, &kuser.DefaultInfo{UID: "user"})
	require.ErrorContains(t, err, "requires administrator static OAuth configuration")
	var instances v1.VMCPInstanceList
	require.NoError(t, storage.List(t.Context(), &instances))
	require.Empty(t, instances.Items)
}
