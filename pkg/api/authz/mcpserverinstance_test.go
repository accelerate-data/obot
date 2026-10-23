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

func TestMCPServerInstanceAdminMayOnlyDeleteAnotherUsersInstance(t *testing.T) {
	storage := clientfake.NewClientBuilder().WithScheme(storagescheme.Scheme).WithObjects(&v1.MCPServerInstance{
		Name:      "instance-1",
		Namespace: system.DefaultNamespace,
		Spec:      v1.MCPServerInstanceSpec{UserID: "owner-uid"},
	}).Build()
	authorizer := NewAuthorizer(nil, storage, storage, false, nil, nil, false)
	admin := &user.DefaultInfo{
		Name:   "studio-offboarding",
		UID:    "admin-uid",
		Groups: types.RoleAdmin.Groups(),
	}
	other := &user.DefaultInfo{
		Name:   "other",
		UID:    "other-uid",
		Groups: []string{types.GroupAPI, types.GroupAuthenticated},
	}

	for _, tc := range []struct {
		name    string
		method  string
		path    string
		who     *user.DefaultInfo
		allowed bool
	}{
		{name: "admin deletes another user's instance", method: http.MethodDelete, path: "/api/mcp-server-instances/instance-1", who: admin, allowed: true},
		{name: "admin cannot read another user's instance", method: http.MethodGet, path: "/api/mcp-server-instances/instance-1", who: admin},
		{name: "admin cannot reveal another user's instance", method: http.MethodPost, path: "/api/mcp-server-instances/instance-1/reveal", who: admin},
		{name: "admin cannot clear another user's oauth", method: http.MethodDelete, path: "/api/mcp-server-instances/instance-1/oauth", who: admin},
		{name: "non-admin cannot delete another user's instance", method: http.MethodDelete, path: "/api/mcp-server-instances/instance-1", who: other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if allowed := authorizer.Authorize(req, tc.who); allowed != tc.allowed {
				t.Fatalf("Authorize() = %v, want %v", allowed, tc.allowed)
			}
		})
	}
}
