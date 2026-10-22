package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/storage"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type blockedConsentInstanceCreate struct {
	storage.Client
	entered chan struct{}
	release chan struct{}
	stopped error
}

func consentStaticOAuthVMCP() *v1.VMCP {
	vmcp, _ := vmcpConsentConfigurationTarget()
	c := &vmcp.Spec.Manifest.Components[0]
	c.MCPServerCatalogEntryID = "entry"
	c.CatalogEntry.Manifest.Runtime = types.RuntimeRemote
	c.CatalogEntry.Manifest.RemoteConfig = &types.RemoteCatalogConfig{FixedURL: "https://mcp.example/api", StaticOAuthRequired: true}
	vmcp.Status.Ready = true
	return vmcp
}

func TestVMCPConsentRejectsUnprovedStaticOAuthBeforeCreatingInstance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secrets map[string]string
	}{
		{name: "cleared"},
		{name: "unproved", secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "MCP_URL": "https://mcp.example/api"}},
		{name: "changed provider", secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "MCP_URL": "https://other.example/api", "GENERATION": "proved"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vmcp := consentStaticOAuthVMCP()
			gateway := vmcpConsentGateway(t)
			if tc.secrets != nil {
				require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName("entry"), Name: system.StaticOAuthCredentialName, Secrets: tc.secrets}))
			}
			storage := vmcpConsentStorage(vmcp)
			_, _, err := vmcpConsentTarget(vmcpConsentRequest(storage, gateway), vmcp.Name)
			require.ErrorContains(t, err, "requires administrator static OAuth configuration")
			var instances v1.VMCPInstanceList
			require.NoError(t, storage.List(t.Context(), &instances))
			require.Empty(t, instances.Items)
		})
	}
}

func (s *blockedConsentInstanceCreate) Create(_ context.Context, obj kclient.Object, _ ...kclient.CreateOption) error {
	if _, ok := obj.(*v1.VMCPInstance); !ok {
		return errors.New("unexpected create")
	}
	close(s.entered)
	<-s.release
	return s.stopped
}

func TestVMCPConsentHoldsStaticOAuthFenceThroughInstanceCreation(t *testing.T) {
	vmcp := consentStaticOAuthVMCP()
	gateway := vmcpConsentGateway(t)
	require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName("entry"), Name: system.StaticOAuthCredentialName, Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "MCP_URL": "https://mcp.example/api", "GENERATION": "proved"}}))
	storage := &blockedConsentInstanceCreate{Client: vmcpConsentStorage(vmcp), entered: make(chan struct{}), release: make(chan struct{}), stopped: errors.New("stop at create")}
	done := make(chan error, 1)
	go func() { _, _, err := vmcpConsentTarget(vmcpConsentRequest(storage, gateway), vmcp.Name); done <- err }()
	select {
	case <-storage.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("consent did not reach creation")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	unlock, err := gateway.AcquireCredentialLocks(ctx, system.MCPStaticOAuthCatalogMutationLock, system.MCPOAuthCredentialName("entry"))
	if err == nil {
		unlock()
	}
	close(storage.release)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, <-done, storage.stopped)
}

func TestVMCPConsentRereadsComponentsAfterCatalogFence(t *testing.T) {
	vmcp, _ := vmcpConsentConfigurationTarget()
	storage := vmcpConsentStorage(vmcp)
	gateway := vmcpConsentGateway(t)
	unlock, err := gateway.AcquireCredentialLock(t.Context(), system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	defer unlock()
	done := make(chan error, 1)
	go func() { _, _, err := vmcpConsentTarget(vmcpConsentRequest(storage, gateway), vmcp.Name); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("consent crossed catalog fence: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	var current v1.VMCP
	require.NoError(t, storage.Get(t.Context(), kclient.ObjectKeyFromObject(vmcp), &current))
	component := consentStaticOAuthVMCP().Spec.Manifest.Components[0]
	current.Spec.Manifest.Components = []types.VMCPComponent{component}
	require.NoError(t, storage.Update(t.Context(), &current))
	unlock()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "requires administrator static OAuth configuration")
	case <-time.After(5 * time.Second):
		t.Fatal("consent did not resume")
	}
	var instances v1.VMCPInstanceList
	require.NoError(t, storage.List(t.Context(), &instances))
	require.Empty(t, instances.Items)
}
