package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"k8s.io/apiserver/pkg/authentication/user"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPowerUserAllowsWorkspaceOAuthCredentialWriteAndTestRoutes(t *testing.T) {
	workspace := &v1.PowerUserWorkspace{
		Name:      "workspace-1",
		Namespace: system.DefaultNamespace,
		Spec: v1.PowerUserWorkspaceSpec{
			UserID: "owner-uid",
		},
	}
	entry := &v1.MCPServerCatalogEntry{
		Name:      "entry-1",
		Namespace: system.DefaultNamespace,
		Spec: v1.MCPServerCatalogEntrySpec{
			PowerUserWorkspaceID: workspace.Name,
		},
	}
	storage := clientfake.NewClientBuilder().WithScheme(storagescheme.Scheme).WithObjects(workspace, entry).Build()
	authorizer := newCatalogEntryTestAuthorizer(t, storage, &v1.AccessControlRule{
		Name:      "entry-access",
		Namespace: system.DefaultNamespace,
		Spec: v1.AccessControlRuleSpec{
			PowerUserWorkspaceID: workspace.Name,
			Manifest: types.AccessControlRuleManifest{
				Subjects:  []types.Subject{{Type: types.SubjectTypeUser, ID: "owner-uid"}},
				Resources: []types.Resource{{Type: types.ResourceTypeMCPServerCatalogEntry, ID: entry.Name}},
			},
		},
	})
	powerUser := &user.DefaultInfo{
		Name:   "owner",
		UID:    "owner-uid",
		Groups: []string{types.GroupPowerUser, types.GroupAuthenticated},
	}

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "replace credentials",
			method: http.MethodPut,
			path:   "/api/workspaces/workspace-1/entries/entry-1/oauth-credentials",
		},
		{
			name:   "start credential test",
			method: http.MethodPost,
			path:   "/api/workspaces/workspace-1/entries/entry-1/oauth-credentials/test",
		},
		{
			name:   "read credential test status",
			method: http.MethodPost,
			path:   "/api/workspaces/workspace-1/entries/entry-1/oauth-credentials/test/status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if allowed := authorizer.Authorize(req, powerUser); !allowed {
				t.Fatal("Authorize() = false, want true")
			}
		})
	}
}

func TestAPIGroupAllowsOwnedMCPServerInstanceOAuthReadRoutes(t *testing.T) {
	storage := clientfake.NewClientBuilder().WithScheme(storagescheme.Scheme).WithObjects(&v1.MCPServerInstance{
		Name:      "instance-1",
		Namespace: system.DefaultNamespace,
		Spec: v1.MCPServerInstanceSpec{
			UserID: "owner-uid",
		},
	}).Build()
	authorizer := NewAuthorizer(nil, storage, storage, false, nil, nil, nil, false)
	apiUser := &user.DefaultInfo{
		Name:   "owner",
		UID:    "owner-uid",
		Groups: []string{types.GroupAPI, types.GroupAuthenticated},
	}

	for _, path := range []string{
		"/api/mcp-server-instances/instance-1/oauth-url",
		"/api/mcp-server-instances/instance-1/oauth-redirect",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			if allowed := authorizer.Authorize(req, apiUser); !allowed {
				t.Fatal("Authorize() = false, want true")
			}
		})
	}
}
