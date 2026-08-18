package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/obot-platform/obot/pkg/tunnel"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEffectiveKubernetesResourceMaximums(t *testing.T) {
	maximum := resource.MustParse("500m")
	storageClient := fake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithObjects(&v1.K8sSettings{
			ObjectMeta: metav1.ObjectMeta{
				Name:      system.K8sSettingsName,
				Namespace: system.DefaultNamespace,
			},
			Spec: v1.K8sSettingsSpec{MaxCPURequest: &maximum},
		}).
		Build()

	t.Run("Kubernetes backend uses persisted maximum", func(t *testing.T) {
		manager := &SessionManager{runtimeBackend: RuntimeBackendKubernetes}
		got, err := manager.EffectiveKubernetesResourceMaximums(t.Context(), storageClient)
		require.NoError(t, err)
		require.NotNil(t, got.CPURequest)
		require.Zero(t, got.CPURequest.Cmp(maximum))
	})

	t.Run("runtime ignores startup maximum", func(t *testing.T) {
		startupMaximum := resource.MustParse("100m")
		manager := &SessionManager{
			runtimeBackend:   RuntimeBackendKubernetes,
			resourceMaximums: ResourceMaximums{CPURequest: &startupMaximum},
		}
		got, err := manager.EffectiveKubernetesResourceMaximums(t.Context(), storageClient)
		require.NoError(t, err)
		require.NotNil(t, got.CPURequest)
		require.Zero(t, got.CPURequest.Cmp(maximum))
	})

	t.Run("startup uses strictest persisted and configured maximum", func(t *testing.T) {
		startupMaximum := resource.MustParse("100m")
		manager := &SessionManager{
			runtimeBackend:   RuntimeBackendKubernetes,
			resourceMaximums: ResourceMaximums{CPURequest: &startupMaximum},
		}
		got, err := manager.StartupKubernetesResourceMaximums(t.Context(), storageClient)
		require.NoError(t, err)
		require.NotNil(t, got.CPURequest)
		require.Zero(t, got.CPURequest.Cmp(startupMaximum))
	})

	t.Run("startup uses configured maximum before settings exist", func(t *testing.T) {
		startupMaximum := resource.MustParse("100m")
		manager := &SessionManager{
			runtimeBackend:   RuntimeBackendKubernetes,
			resourceMaximums: ResourceMaximums{CPURequest: &startupMaximum},
		}
		emptyStorageClient := fake.NewClientBuilder().WithScheme(storagescheme.Scheme).Build()
		got, err := manager.StartupKubernetesResourceMaximums(t.Context(), emptyStorageClient)
		require.NoError(t, err)
		require.NotNil(t, got.CPURequest)
		require.Zero(t, got.CPURequest.Cmp(startupMaximum))
	})

	t.Run("non-Kubernetes backend ignores persisted maximum", func(t *testing.T) {
		manager := &SessionManager{runtimeBackend: runtimeBackendDocker}
		got, err := manager.EffectiveKubernetesResourceMaximums(t.Context(), nil)
		require.NoError(t, err)
		require.True(t, got.Empty())
	})
}

func TestHTTPClientForServer(t *testing.T) {
	const timeout = 3 * time.Second
	backend := &kubernetesBackend{
		httpListenPort:   8080,
		mcpNamespace:     "obot-mcp",
		mcpClusterDomain: "cluster.local",
		serviceFQDN:      "obot.obot-system.svc.cluster.local",
	}

	t.Run("direct server", func(t *testing.T) {
		httpClient, err := (&SessionManager{backend: backend}).HTTPClientForServer(ServerConfig{}, nil, nil, timeout)
		if err != nil {
			t.Fatal(err)
		}
		if httpClient.Timeout != timeout {
			t.Fatalf("client timeout = %v, want %v", httpClient.Timeout, timeout)
		}
		if httpClient.Transport == nil {
			t.Fatal("direct client uses the default transport")
		}
	})

	t.Run("direct server options", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Header.Get("X-MCP-Test") != "injected" {
				t.Errorf("injected header = %q, want injected", req.Header.Get("X-MCP-Test"))
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		httpClient, err := (&SessionManager{backend: backend}).HTTPClientForServer(
			ServerConfig{},
			[]string{serverURL.Host},
			http.Header{"X-MCP-Test": {"injected"}},
			timeout,
		)
		if err != nil {
			t.Fatal(err)
		}

		response, err := httpClient.Get(server.URL)
		if err != nil {
			t.Fatalf("allow-listed direct request failed: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("response status = %d, want %d", response.StatusCode, http.StatusNoContent)
		}
	})

	t.Run("direct server uses Kubernetes backend allow list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		httpClient, err := (&SessionManager{
			backend: &kubernetesBackend{
				serviceFQDN: serverURL.Host,
			},
		}).HTTPClientForServer(ServerConfig{}, nil, nil, timeout)
		if err != nil {
			t.Fatal(err)
		}

		response, err := httpClient.Get(server.URL)
		if err != nil {
			t.Fatalf("request to backend-allowlisted server failed: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("response status = %d, want %d", response.StatusCode, http.StatusNoContent)
		}
	})

	t.Run("tunnel manager required", func(t *testing.T) {
		_, err := (&SessionManager{}).HTTPClientForServer(ServerConfig{TunnelName: "office"}, nil, nil, timeout)
		if err == nil {
			t.Fatal("tunneled server without tunnel manager returned no error")
		}
	})

	t.Run("tunneled server", func(t *testing.T) {
		tunnelManager, err := tunnel.NewManager(t.Context(), "http://127.0.0.1:8080", fake.NewClientBuilder().Build(), tunnel.PeerConfig{})
		if err != nil {
			t.Fatal(err)
		}
		defer tunnelManager.Close()

		httpClient, err := (&SessionManager{tunnelManager: tunnelManager}).HTTPClientForServer(
			ServerConfig{TunnelName: "office"},
			nil,
			nil,
			timeout,
		)
		if err != nil {
			t.Fatal(err)
		}
		if httpClient.Timeout != timeout {
			t.Fatalf("client timeout = %v, want %v", httpClient.Timeout, timeout)
		}
		if httpClient.Transport == nil {
			t.Fatal("tunneled client uses the default transport")
		}
	})

	t.Run("invalid tunnel name", func(t *testing.T) {
		tunnelManager, err := tunnel.NewManager(t.Context(), "http://127.0.0.1:8080", fake.NewClientBuilder().Build(), tunnel.PeerConfig{})
		if err != nil {
			t.Fatal(err)
		}
		defer tunnelManager.Close()

		_, err = (&SessionManager{tunnelManager: tunnelManager}).HTTPClientForServer(
			ServerConfig{TunnelName: "Office"},
			nil,
			nil,
			timeout,
		)
		if err == nil {
			t.Fatal("invalid tunnel name returned no error")
		}
	})
}

// ctxCapturingBackend implements backend, recording the ctx it was called
// with so tests can assert on the deadline SessionManager.ensureDeployment
// hands down to it.
type ctxCapturingBackend struct {
	capturedCtx context.Context
}

func (b *ctxCapturingBackend) ensureServerDeployment(ctx context.Context, server ServerConfig) (ServerConfig, error) {
	b.capturedCtx = ctx
	return server, nil
}

func (b *ctxCapturingBackend) deployServer(context.Context, ServerConfig) error { return nil }

func (b *ctxCapturingBackend) streamServerLogs(context.Context, string) (io.ReadCloser, error) {
	return nil, nil
}

func (b *ctxCapturingBackend) getServerDetails(context.Context, string) (types.MCPServerDetails, error) {
	return types.MCPServerDetails{}, nil
}

func (b *ctxCapturingBackend) restartServer(context.Context, ServerConfig) error { return nil }

func (b *ctxCapturingBackend) shutdownServer(context.Context, string, bool) error { return nil }

func (b *ctxCapturingBackend) transformObotHostname(url string) string { return url }

func (b *ctxCapturingBackend) remoteConfig(globalConfig RemoteMCPURLValidationConfig) (RemoteMCPURLValidationConfig, []string) {
	return globalConfig, nil
}

// Image acquisition can be slow (registry pull), and that time must not be
// carved out of the tight StartupTimeout budget meant for container
// creation/start/readiness. ensureDeployment used to wrap the ctx it handed
// to the backend in its own StartupTimeout-derived deadline; that
// responsibility now belongs to each backend individually, applied after
// image acquisition rather than before it.
func TestEnsureDeployment_DoesNotImposeItsOwnStartupTimeout(t *testing.T) {
	backend := &ctxCapturingBackend{}
	sm := &SessionManager{backend: backend}

	server := ServerConfig{
		Runtime:        types.RuntimeNPX,
		StartupTimeout: 5 * time.Millisecond,
	}

	_, err := sm.ensureDeployment(context.Background(), server)
	if err != nil {
		t.Fatalf("ensureDeployment() error = %v", err)
	}
	if backend.capturedCtx == nil {
		t.Fatal("backend.ensureServerDeployment was never called")
	}
	if _, ok := backend.capturedCtx.Deadline(); ok {
		t.Fatal("ensureDeployment must not impose its own StartupTimeout-derived deadline; that responsibility now belongs to each backend")
	}
}
