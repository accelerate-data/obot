package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	"github.com/obot-platform/obot/pkg/storage"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type conflictingMCPServerDeleteClient struct {
	storage.Client
	deleteCalls int
	onConflict  func(context.Context, kclient.Object) error
}

func (c *conflictingMCPServerDeleteClient) Delete(ctx context.Context, obj kclient.Object, opts ...kclient.DeleteOption) error {
	c.deleteCalls++
	if c.deleteCalls == 1 {
		if err := c.onConflict(ctx, obj); err != nil {
			return err
		}
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestDeleteServerPreservesChangedServerBetweenReadAndDelete(t *testing.T) {
	for _, tc := range []struct {
		name       string
		change     func(*v1.MCPServer)
		statusCode int
	}{
		{"catalog scope", func(server *v1.MCPServer) { server.Spec.MCPCatalogID = "another-catalog" }, http.StatusNotFound},
		{"workspace scope", func(server *v1.MCPServer) { server.Spec.PowerUserWorkspaceID = "another-workspace" }, http.StatusNotFound},
		{"composite component", func(server *v1.MCPServer) { server.Spec.CompositeName = "ms1composite" }, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &v1.MCPServer{Name: "ms1test", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPCatalogID: system.DefaultCatalog, UserID: "1"}}
			base := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(server).Build()
			client := &conflictingMCPServerDeleteClient{
				Client: base,
				onConflict: func(ctx context.Context, obj kclient.Object) error {
					var latest v1.MCPServer
					if err := base.Get(ctx, kclient.ObjectKeyFromObject(obj), &latest); err != nil {
						return err
					}
					tc.change(&latest)
					return base.Update(ctx, &latest)
				},
			}
			request := httptest.NewRequest(http.MethodDelete, "/api/mcp-catalogs/default/servers/ms1test", nil)
			request.SetPathValue("catalog_id", system.DefaultCatalog)
			request.SetPathValue("mcp_server_id", server.Name)
			err := (&MCPHandler{}).DeleteServer(api.Context{Request: request, ResponseWriter: httptest.NewRecorder(), Storage: client, User: &kuser.DefaultInfo{UID: "1"}})
			var httpErr *types.ErrHTTP
			require.ErrorAs(t, err, &httpErr)
			require.Equal(t, tc.statusCode, httpErr.Code)
			require.Equal(t, 1, client.deleteCalls)
			var remaining v1.MCPServer
			require.NoError(t, base.Get(t.Context(), kclient.ObjectKeyFromObject(server), &remaining))
			expected := server.DeepCopy()
			tc.change(expected)
			require.Equal(t, expected.Spec, remaining.Spec)
		})
	}
}

func TestDeleteServerRetriesConflictAfterConcurrentUpdate(t *testing.T) {
	server := &v1.MCPServer{Name: "ms1test", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPCatalogID: system.DefaultCatalog, UserID: "1"}}
	base := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(server).Build()
	client := &conflictingMCPServerDeleteClient{
		Client: base,
		onConflict: func(ctx context.Context, obj kclient.Object) error {
			var latest v1.MCPServer
			if err := base.Get(ctx, kclient.ObjectKeyFromObject(obj), &latest); err != nil {
				return err
			}
			latest.Annotations = map[string]string{"controller": "updated"}
			return base.Update(ctx, &latest)
		},
	}
	request := httptest.NewRequest(http.MethodDelete, "/api/mcp-catalogs/default/servers/ms1test", nil)
	request.SetPathValue("catalog_id", system.DefaultCatalog)
	request.SetPathValue("mcp_server_id", server.Name)
	err := (&MCPHandler{}).DeleteServer(api.Context{Request: request, ResponseWriter: httptest.NewRecorder(), Storage: client, User: &kuser.DefaultInfo{UID: "1"}})
	require.NoError(t, err)
	require.Equal(t, 2, client.deleteCalls)
	require.True(t, apierrors.IsNotFound(client.Get(t.Context(), kclient.ObjectKeyFromObject(server), &v1.MCPServer{})))
}

func TestDeleteServerProtectsComponents(t *testing.T) {
	for _, tc := range []struct {
		name   string
		spec   v1.MCPServerSpec
		parent string
	}{
		{
			name: "standalone",
		},
		{
			name:   "composite component",
			spec:   v1.MCPServerSpec{CompositeName: "ms1composite"},
			parent: "ms1composite",
		},
		{
			name: "shared vMCP component",
			spec: v1.MCPServerSpec{
				VMCPID:          "vmcp1shared",
				VMCPComponentID: "one",
			},
			parent: "vmcp1shared",
		},
		{
			name: "dedicated vMCP component",
			spec: v1.MCPServerSpec{
				VMCPInstanceID:  "vmcpi1dedicated",
				VMCPComponentID: "one",
			},
			parent: "vmcpi1dedicated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &v1.MCPServer{Name: "ms1test", Namespace: system.DefaultNamespace, Spec: tc.spec}
			server.Spec.UserID = "1"
			client := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(server).Build()
			request := httptest.NewRequest(http.MethodDelete, "/", nil)
			request.SetPathValue("mcp_server_id", server.Name)
			err := (&MCPHandler{}).DeleteServer(api.Context{
				Request:        request,
				ResponseWriter: httptest.NewRecorder(),
				Storage:        client,
				User:           &kuser.DefaultInfo{UID: "1"},
			})
			if tc.parent != "" {
				var httpErr *types.ErrHTTP
				require.ErrorAs(t, err, &httpErr)
				require.Equal(t, http.StatusForbidden, httpErr.Code)
				require.ErrorContains(t, err, tc.parent)
				require.NoError(t, client.Get(t.Context(), kclient.ObjectKeyFromObject(server), &v1.MCPServer{}))
			} else {
				require.NoError(t, err)
				require.True(t, apierrors.IsNotFound(client.Get(t.Context(), kclient.ObjectKeyFromObject(server), &v1.MCPServer{})))
			}
		})
	}
}

func TestDeleteServerInstanceProtectsCompositeComponents(t *testing.T) {
	for _, tc := range []struct {
		name      string
		composite string
		missing   bool
	}{
		{
			name: "standalone",
		},
		{
			name:      "composite component",
			composite: "ms1composite",
		},
		{
			name:    "already deleted",
			missing: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instance := &v1.MCPServerInstance{
				Name:      "msi1test",
				Namespace: system.DefaultNamespace,
				Spec:      v1.MCPServerInstanceSpec{CompositeName: tc.composite},
			}
			client := fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
			if !tc.missing {
				require.NoError(t, client.Create(t.Context(), instance))
			}
			request := httptest.NewRequest(http.MethodDelete, "/", nil)
			request.SetPathValue("mcp_server_instance_id", instance.Name)
			err := (&ServerInstancesHandler{}).DeleteServerInstance(api.Context{Request: request, Storage: client})
			if tc.composite != "" {
				var httpErr *types.ErrHTTP
				require.ErrorAs(t, err, &httpErr)
				require.Equal(t, http.StatusBadRequest, httpErr.Code)
				require.ErrorContains(t, err, tc.composite)
				require.NoError(t, client.Get(t.Context(), kclient.ObjectKeyFromObject(instance), &v1.MCPServerInstance{}))
			} else {
				require.NoError(t, err)
				require.True(t, apierrors.IsNotFound(client.Get(t.Context(), kclient.ObjectKeyFromObject(instance), &v1.MCPServerInstance{})))
			}
		})
	}
}
