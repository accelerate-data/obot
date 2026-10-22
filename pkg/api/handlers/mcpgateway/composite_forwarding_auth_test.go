package mcpgateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	"github.com/obot-platform/obot/pkg/jwt/persistent"
	"github.com/obot-platform/obot/pkg/mcp"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/obot-platform/obot/pkg/tunnel"
	vmcpconfig "github.com/obot-platform/obot/pkg/vmcp"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestProxyCompositeForwardingPreservesScopedLoopbackBearer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Disabled components need no deployment. The aggregate still resolves an
	// authenticated connection and travels through the real owner tunnel.
	definition := &v1.VMCP{
		Name:      "vmcp1forwarded",
		Namespace: system.DefaultNamespace,
		Spec: v1.VMCPSpec{Manifest: types.VMCPManifest{
			Components: []types.VMCPComponent{{ID: "disabled"}},
		}},
	}
	instance := &v1.VMCPInstance{
		Name:      "vmcpi1forwarded",
		Namespace: system.DefaultNamespace,
		Spec: v1.VMCPInstanceSpec{
			UserID:   "user-1",
			Manifest: types.VMCPInstanceManifest{VMCPID: definition.Name},
		},
		Status: v1.VMCPInstanceStatus{
			ConfigurationCheckHash: vmcpconfig.ConfigurationCheckHash([]types.VMCPComponent{}, ""),
		},
	}
	storage := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(definition, instance).Build()
	tokenContext := compositeTestTokenContext()
	tokenContext.MCPID = instance.Name
	received := make(chan string, 1)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	tokenContext.Audience = server.URL + "/mcp-connect-composite/" + instance.Name
	original := compositeTestToken(t, tokenContext, time.Now().Add(time.Minute))
	manager, err := tunnel.NewManager(ctx, server.URL, storage, tunnel.PeerConfig{})
	require.NoError(t, err)
	defer manager.Close()
	mux.HandleFunc("GET /tunnel/composite/register/{key}", manager.ServeCompositeRegistration)
	mux.HandleFunc("/mcp-connect-composite/{mcp_id}", func(w http.ResponseWriter, r *http.Request) {
		present, valid := manager.ConsumeCompositeOwnerRequest(r)
		if !present || !valid {
			http.Error(w, "invalid owner marker", http.StatusForbidden)
			return
		}
		received <- r.Header.Get("Authorization")
		if r.Header.Get("Authorization") != "Bearer "+original {
			http.Error(w, "composite identity lost", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	sessions, err := mcp.NewSessionManager(ctx, true, false, nil, nil, server.URL, 8080, mcp.Options{MCPRuntimeBackend: mcp.RuntimeBackendKubernetes, MCPNamespace: "obot-mcp"}, nil, &rest.Config{Host: "http://kube.invalid"}, storage, storage, storage, nil, system.DefaultNamespace, manager)
	require.NoError(t, err)
	minted := false
	h := &Handler{ctx: ctx, mcpSessionManager: sessions, tunnelManager: manager, mintToken: func(context.Context, persistent.TokenContext) (string, error) {
		minted = true
		return "single-server-token", nil
	}}
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/mcp-connect-composite/"+instance.Name, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	request.SetPathValue("mcp_id", instance.Name)
	request.Header.Set("Authorization", "Bearer "+original)
	recorder := httptest.NewRecorder()
	require.NoError(t, h.Proxy(api.Context{Request: request, ResponseWriter: recorder, Storage: storage, User: &user.DefaultInfo{UID: "user-1", Groups: []string{types.GroupMCP, types.GroupCompositeMCP, types.GroupAuthenticated}}}))
	require.Equal(t, http.StatusAccepted, recorder.Code, recorder.Body.String())
	require.Equal(t, "Bearer "+original, <-received)
	require.False(t, minted, "a composite-control hop must retain its signed component scopes")
}
