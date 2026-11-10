package authz

// Fork-only guarantee (fork #37, restored by VD-6903): default-catalog static
// OAuth credential routes are owner-only, and workspace credential test routes
// resolve only the workspace owner's entry. Kept in its own file so an upstream
// sync cannot drop these tests by merging over a shared one.

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

var (
	workspaceOAuthCredentialTestRoutes = []struct {
		name   string
		method string
		path   string
	}{
		{name: "start test", method: http.MethodPost, path: "/api/workspaces/workspace-1/entries/entry-1/oauth-credentials/test"},
		{name: "read status", method: http.MethodPost, path: "/api/workspaces/workspace-1/entries/entry-1/oauth-credentials/test/status"},
	}
)

// newWorkspaceOAuthClaimAuthorizer grants no access control rule, so access can
// come only from workspace ownership.
func newWorkspaceOAuthClaimAuthorizer(t *testing.T) *Authorizer {
	t.Helper()
	storage := clientfake.NewClientBuilder().WithScheme(storagescheme.Scheme).WithObjects(
		&v1.PowerUserWorkspace{
			Name: "workspace-1", Namespace: system.DefaultNamespace,
			Spec: v1.PowerUserWorkspaceSpec{UserID: "owner-user"},
		},
		&v1.MCPServerCatalogEntry{
			Name: "entry-1", Namespace: system.DefaultNamespace,
			Spec: v1.MCPServerCatalogEntrySpec{PowerUserWorkspaceID: "workspace-1"},
		},
	).Build()
	return newCatalogEntryTestAuthorizer(t, storage)
}

func TestDefaultCatalogOAuthCredentialMutationsRequireOwnerGroup(t *testing.T) {
	authorizer := newCatalogEntryTestAuthorizer(t, clientfake.NewClientBuilder().WithScheme(storagescheme.Scheme).Build())
	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/mcp-catalogs/default/entries/entry-1/oauth-credentials/test"},
		{method: http.MethodPost, path: "/api/mcp-catalogs/default/entries/entry-1/oauth-credentials/test/status"},
		{method: http.MethodGet, path: "/api/mcp-catalogs/default/entries/entry-1/oauth-credentials"},
		{method: http.MethodPost, path: "/api/mcp-catalogs/default/entries/entry-1/oauth-credentials"},
		{method: http.MethodPut, path: "/api/mcp-catalogs/default/entries/entry-1/oauth-credentials"},
		{method: http.MethodDelete, path: "/api/mcp-catalogs/default/entries/entry-1/oauth-credentials"},
	}
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			admin := &user.DefaultInfo{Name: "admin", UID: "admin", Groups: []string{types.GroupAdmin, types.GroupAuthenticated}}
			if authorizer.Authorize(req, admin) {
				t.Fatal("admin bypassed owner-only catalog OAuth boundary")
			}
			owner := &user.DefaultInfo{Name: "owner", UID: "owner", Groups: []string{types.GroupOwner, types.GroupAdmin, types.GroupAuthenticated}}
			if !authorizer.Authorize(req, owner) {
				t.Fatal("owner was denied catalog OAuth management")
			}
		})
	}
}

func TestPowerUserWorkspaceOAuthCredentialRoutesResolveOwnedEntry(t *testing.T) {
	authorizer := newWorkspaceOAuthClaimAuthorizer(t)
	owner := &user.DefaultInfo{
		Name:   "owner-user",
		UID:    "owner-user",
		Groups: []string{types.GroupPowerUser, types.GroupAuthenticated},
	}

	for _, route := range workspaceOAuthCredentialTestRoutes {
		t.Run(route.name, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			vars, matched := authorizer.apiResources[types.GroupPowerUser].Match(req)
			if !matched {
				t.Fatal("Power User OAuth credential test route is not authorized")
			}
			if vars("workspace_id") != "workspace-1" || vars("entry_id") != "entry-1" {
				t.Fatalf("route variables = workspace %q, entry %q", vars("workspace_id"), vars("entry_id"))
			}
			if !authorizer.Authorize(req, owner) {
				t.Fatal("Power User owner was denied access to their workspace entry")
			}
		})
	}
}

func TestWorkspaceOAuthCredentialTestRoutesRejectLowerRoleAndForeignOwner(t *testing.T) {
	authorizer := newWorkspaceOAuthClaimAuthorizer(t)
	users := []struct {
		name string
		user *user.DefaultInfo
	}{
		{
			name: "basic workspace owner",
			user: &user.DefaultInfo{Name: "owner-user", UID: "owner-user", Groups: []string{types.GroupBasic, types.GroupAuthenticated}},
		},
		{
			name: "foreign power user",
			user: &user.DefaultInfo{Name: "other-user", UID: "other-user", Groups: []string{types.GroupPowerUser, types.GroupAuthenticated}},
		},
	}

	for _, route := range workspaceOAuthCredentialTestRoutes {
		for _, tt := range users {
			t.Run(route.name+"/"+tt.name, func(t *testing.T) {
				req := httptest.NewRequest(route.method, route.path, nil)
				if authorizer.Authorize(req, tt.user) {
					t.Fatal("unauthorized user was allowed to use workspace OAuth credential test route")
				}
			})
		}
	}
}
