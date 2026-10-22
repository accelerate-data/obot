package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type vmcpBlockingResponseWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release chan struct{}
}

func (w *vmcpBlockingResponseWriter) WriteHeader(status int) {
	close(w.started)
	<-w.release
	w.ResponseRecorder.WriteHeader(status)
}

func vmcpStaticClaimRequest(t *testing.T, storage kclient.WithWatch, gw *gateway.Client, writer http.ResponseWriter) api.Context {
	t.Helper()
	body, err := json.Marshal(testVMCPManifest())
	require.NoError(t, err)
	return api.Context{Request: httptest.NewRequest(http.MethodPost, "/api/vmcps", bytes.NewReader(body)), ResponseWriter: writer, Storage: storage, GatewayClient: gw, User: &kuser.DefaultInfo{UID: "user-1", Groups: []string{types.GroupAdmin}}}
}
func vmcpStaticClaimEntry() *v1.MCPServerCatalogEntry {
	entry := vmcpCatalogEntryForTest("entry")
	entry.Spec.Manifest.RemoteConfig = &types.RemoteCatalogConfig{FixedURL: "https://example.com/mcp", StaticOAuthRequired: true}
	entry.Status.OAuthCredentialConfigured = true
	return entry
}
func seedVMCPStaticClaim(t *testing.T, gw *gateway.Client, entry *v1.MCPServerCatalogEntry) {
	t.Helper()
	require.NoError(t, gw.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName(entry.Name), Name: system.StaticOAuthCredentialName, Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "GENERATION": "proved", "MCP_URL": entry.Spec.Manifest.RemoteConfig.FixedURL}}))
}

func TestVMCPCreateIgnoresStaleStaticOAuthReadyStatus(t *testing.T) {
	entry := vmcpStaticClaimEntry()
	storage := newVMCPTestStorage(entry)
	gw := newHandlerTestGateway(t)
	require.NoError(t, gw.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName(entry.Name), Name: system.StaticOAuthCredentialName, Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret"}}))
	err := vmcpHandlerForTest(t, storage).Create(vmcpStaticClaimRequest(t, storage, gw, httptest.NewRecorder()))
	require.ErrorContains(t, err, "requires administrator static OAuth configuration")
	var vmcps v1.VMCPList
	require.NoError(t, storage.List(t.Context(), &vmcps))
	require.Empty(t, vmcps.Items)
}

func TestVMCPCreateRereadsStaticOAuthProviderInsideCatalogFence(t *testing.T) {
	entry := vmcpStaticClaimEntry()
	storage := newVMCPTestStorage(entry)
	gw := newHandlerTestGateway(t)
	seedVMCPStaticClaim(t, gw, entry)
	release, err := gw.AcquireCredentialLock(t.Context(), system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	var once sync.Once
	unlock := func() { once.Do(release) }
	defer unlock()
	result := make(chan error, 1)
	req := vmcpStaticClaimRequest(t, storage, gw, httptest.NewRecorder())
	go func() { result <- vmcpHandlerForTest(t, storage).Create(req) }()
	select {
	case err := <-result:
		t.Fatalf("creation crossed catalog fence: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	entry.Spec.Manifest.RemoteConfig.FixedURL = "https://other.example/mcp"
	require.NoError(t, storage.Update(t.Context(), entry))
	unlock()
	select {
	case err := <-result:
		require.ErrorContains(t, err, "requires administrator static OAuth configuration")
	case <-time.After(5 * time.Second):
		t.Fatal("creation did not resume")
	}
	var vmcps v1.VMCPList
	require.NoError(t, storage.List(t.Context(), &vmcps))
	require.Empty(t, vmcps.Items)
}

func TestVMCPCreateReleasesStaticOAuthFenceBeforeWritingResponse(t *testing.T) {
	entry := vmcpStaticClaimEntry()
	storage := newVMCPTestStorage(entry)
	gw := newHandlerTestGateway(t)
	seedVMCPStaticClaim(t, gw, entry)
	writer := &vmcpBlockingResponseWriter{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	finish := func() { once.Do(func() { close(writer.release) }) }
	defer finish()
	result := make(chan error, 1)
	req := vmcpStaticClaimRequest(t, storage, gw, writer)
	go func() { result <- vmcpHandlerForTest(t, storage).Create(req) }()
	select {
	case <-writer.started:
	case err := <-result:
		t.Fatalf("creation returned before response: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("response not started")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	unlock, err := gw.AcquireCredentialLock(ctx, system.MCPStaticOAuthCatalogMutationLock)
	require.NoError(t, err)
	unlock()
	finish()
	require.NoError(t, <-result)
}

func TestVMCPNonStaticCreateDoesNotAcquireStaticCredentialLock(t *testing.T) {
	entry := vmcpCatalogEntryForTest("entry")
	entry.Spec.Manifest.RemoteConfig = &types.RemoteCatalogConfig{FixedURL: "https://example.com/mcp"}
	storage := newVMCPTestStorage(entry)
	gw := newHandlerTestGateway(t)
	unlock, err := gw.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(entry.Name))
	require.NoError(t, err)
	defer unlock()
	req := vmcpStaticClaimRequest(t, storage, gw, httptest.NewRecorder())
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	req.Request = req.WithContext(ctx)
	require.NoError(t, vmcpHandlerForTest(t, storage).Create(req))
}
