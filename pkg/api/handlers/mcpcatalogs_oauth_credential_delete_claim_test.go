package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): clearing static OAuth
// credentials keeps sibling deployments and access rules while revoking every
// matching user token and no unrelated one. Kept in its own file so an
// upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/obot/pkg/api"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/storage"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"k8s.io/apiserver/pkg/authentication/user"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDeleteOAuthCredentialsRetainsSiblingDeploymentsAndClearsEveryUserToken(t *testing.T) {
	triggered := map[string]int{}
	gateway, rawDB := newOAuthCredentialClaimGatewayWithTrigger(t, func(_ context.Context, mcpID string) error {
		triggered[mcpID]++
		return nil
	})
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	servers := []*v1.MCPServer{
		{Name: "server-a", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: entry.Name}},
		{Name: "server-b", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: entry.Name}},
	}
	instances := []*v1.MCPServerInstance{
		{Name: "instance-a-user-1", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: servers[0].Name, MCPServerCatalogEntryName: entry.Name}},
		{Name: "instance-a-user-2", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-2", MCPServerName: servers[0].Name, MCPServerCatalogEntryName: entry.Name}},
		{Name: "instance-b-user-1", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: servers[1].Name, MCPServerCatalogEntryName: entry.Name}},
	}
	unrelatedServer := &v1.MCPServer{
		Name: "server-unrelated", Namespace: system.DefaultNamespace,
		Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: "entry-unrelated"},
	}
	unrelatedInstance := &v1.MCPServerInstance{
		Name: "instance-unrelated", Namespace: system.DefaultNamespace,
		Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: unrelatedServer.Name, MCPServerCatalogEntryName: "entry-unrelated"},
	}
	rules := []*v1.AccessControlRule{
		{Name: "acr-a", Namespace: system.DefaultNamespace, Spec: v1.AccessControlRuleSpec{MCPCatalogID: "default"}},
		{Name: "acr-b", Namespace: system.DefaultNamespace, Spec: v1.AccessControlRuleSpec{MCPCatalogID: "default"}},
	}
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName(entry.Name), Name: "oauth", Secrets: map[string]string{
		"CLIENT_ID": "saved-client", "CLIENT_SECRET": "saved-secret", "GENERATION": testStaticOAuthCredentialGeneration,
	}}); err != nil {
		t.Fatalf("seed OAuth credential: %v", err)
	}
	if err := gateway.DeleteMCPOAuthTokenForAllUsers(t.Context(), "trigger-probe"); err != nil || triggered["trigger-probe"] != 1 {
		t.Fatalf("token cleanup trigger fixture is not active: %#v, %v", triggered, err)
	}
	clear(triggered)
	for _, instance := range instances {
		seedCatalogOwnedOAuthToken(t, rawDB, instance.Spec.UserID, instance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, entry.Name, "instance-token-"+instance.Name)
	}
	for _, server := range servers {
		seedCatalogOwnedOAuthToken(t, rawDB, "single-user", server.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, entry.Name, "server-token-"+server.Name)
	}
	conf := &oauth2.Config{ClientID: "saved-client", ClientSecret: "saved-secret"}
	if err := gateway.ReplaceMCPOAuthToken(t.Context(), unrelatedInstance.Spec.UserID, unrelatedInstance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "", conf, &oauth2.Token{AccessToken: "unrelated-instance-token"}); err != nil {
		t.Fatalf("seed unrelated instance token: %v", err)
	}
	if err := gateway.ReplaceMCPOAuthToken(t.Context(), "single-user", unrelatedServer.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "", conf, &oauth2.Token{AccessToken: "unrelated-server-token"}); err != nil {
		t.Fatalf("seed unrelated server token: %v", err)
	}
	clear(triggered)

	objects := []kclient.Object{
		&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace},
		entry, servers[0], servers[1], instances[0], instances[1], instances[2], unrelatedServer, unrelatedInstance, rules[0], rules[1],
	}
	storageClient := fake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithIndex(&v1.MCPServer{}, "spec.mcpServerCatalogEntryName", func(object kclient.Object) []string {
			return []string{object.(*v1.MCPServer).Spec.MCPServerCatalogEntryName}
		}).
		WithIndex(&v1.MCPServerInstance{}, "spec.mcpServerCatalogEntryName", func(object kclient.Object) []string {
			return []string{object.(*v1.MCPServerInstance).Spec.MCPServerCatalogEntryName}
		}).
		WithObjects(objects...).
		Build()
	recorder := httptest.NewRecorder()
	req := api.Context{
		Request: httptest.NewRequest(
			http.MethodDelete, "/", strings.NewReader(`{"expectedGeneration":"`+testStaticOAuthCredentialGeneration+`"}`),
		),
		ResponseWriter: recorder,
		Storage:        storage.Client(storageClient),
		GatewayClient:  gateway,
		User:           &user.DefaultInfo{Name: "owner", UID: "user-1"},
	}
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)
	var indexedServers v1.MCPServerList
	if err := req.List(&indexedServers, kclient.MatchingFields{"spec.mcpServerCatalogEntryName": entry.Name}); err != nil || len(indexedServers.Items) != 2 {
		t.Fatalf("test server index returned %d siblings: %v", len(indexedServers.Items), err)
	}

	if err := (&MCPCatalogHandler{gatewayClient: gateway}).DeleteOAuthCredentials(req); err != nil {
		t.Fatalf("delete OAuth credentials: %v", err)
	}
	for _, server := range servers {
		var retained v1.MCPServer
		if err := req.Get(&retained, server.Name); err != nil {
			t.Fatalf("sibling deployment %s was removed: %v", server.Name, err)
		}
	}
	for _, instance := range instances {
		if _, err := gateway.GetMCPOAuthToken(t.Context(), instance.Spec.UserID, instance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("user token for %s remains: %v", instance.Name, err)
		}
	}
	for _, server := range servers {
		if _, err := gateway.GetMCPOAuthToken(t.Context(), "single-user", server.Name, entry.Spec.Manifest.RemoteConfig.FixedURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("server-name token for %s remains: %v", server.Name, err)
		}
	}
	if _, err := gateway.GetMCPOAuthToken(t.Context(), unrelatedInstance.Spec.UserID, unrelatedInstance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL); err != nil {
		t.Fatalf("unrelated instance token was removed: %v", err)
	}
	if _, err := gateway.GetMCPOAuthToken(t.Context(), "single-user", unrelatedServer.Name, entry.Spec.Manifest.RemoteConfig.FixedURL); err != nil {
		t.Fatalf("unrelated server token was removed: %v", err)
	}
	for _, rule := range rules {
		var retained v1.AccessControlRule
		if err := req.Get(&retained, rule.Name); err != nil {
			t.Fatalf("access control rule %s was removed: %v", rule.Name, err)
		}
	}
	for _, id := range []string{"server-a", "server-b", "instance-a-user-1", "instance-a-user-2", "instance-b-user-1"} {
		if triggered[id] != 1 {
			t.Fatalf("token cleanup triggers = %#v; %s count = %d, want 1", triggered, id, triggered[id])
		}
	}
	if len(triggered) != 5 {
		t.Fatalf("token cleanup triggers = %#v, want only matching servers and instances", triggered)
	}
	var updated v1.MCPServerCatalogEntry
	if err := req.Get(&updated, entry.Name); err != nil {
		t.Fatalf("get reconciled entry: %v", err)
	}
	if updated.Annotations[v1.MCPServerCatalogEntrySyncAnnotation] != "true" {
		t.Fatalf("entry was not marked for reconciliation: %#v", updated.Annotations)
	}
}
