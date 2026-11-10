package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): clearing static OAuth
// credentials rejects a stale generation, fails on list or token purge errors
// without reporting success, and retries the purge notification. Kept in its
// own file so an upstream sync cannot drop these tests by merging over a
// shared one.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"gorm.io/gorm"
)

func TestDeleteOAuthCredentialsRejectsStaleGenerationWithoutRemovingCurrentApp(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	credentialName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: credentialName,
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "current-client",
			"CLIENT_SECRET": "current-secret",
			"MCP_URL":       entry.Spec.Manifest.RemoteConfig.FixedURL,
			"GENERATION":    "generation-2",
		},
	}); err != nil {
		t.Fatalf("seed current OAuth credential: %v", err)
	}
	req := newDeleteOAuthCredentialRequest(t, gateway, entry)
	req.Request = httptest.NewRequest(
		http.MethodDelete,
		"/",
		strings.NewReader(`{"expectedGeneration":"generation-1"}`),
	)
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)

	err := (&MCPCatalogHandler{gatewayClient: gateway}).DeleteOAuthCredentials(req)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("stale Clear error = %v, want generation conflict", err)
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{credentialName}, "oauth")
	if err != nil {
		t.Fatalf("stale Clear removed current OAuth credential: %v", err)
	}
	if credential.Secrets["GENERATION"] != "generation-2" {
		t.Fatalf("current OAuth credential changed: %#v", credential.Secrets)
	}
}

func TestDeleteOAuthCredentialsReturnsServerListFailure(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{
		"CLIENT_ID": "saved-client", "CLIENT_SECRET": "saved-secret", "GENERATION": testStaticOAuthCredentialGeneration,
	}}); err != nil {
		t.Fatalf("seed OAuth credential: %v", err)
	}
	req := newDeleteOAuthCredentialRequest(t, gateway, entry)
	req.Storage = oauthServerListErrorStorage{Client: req.Storage}

	if err := (&MCPCatalogHandler{gatewayClient: gateway}).DeleteOAuthCredentials(req); err == nil {
		t.Fatal("Clear reported success after server list failure")
	}
	if _, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth"); err != nil {
		t.Fatalf("server-list failure removed the shared credential: %v", err)
	}
}

func TestDeleteOAuthCredentialsReturnsInstanceListFailure(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{
		"CLIENT_ID": "saved-client", "CLIENT_SECRET": "saved-secret", "GENERATION": testStaticOAuthCredentialGeneration,
	}}); err != nil {
		t.Fatalf("seed OAuth credential: %v", err)
	}
	req := newDeleteOAuthCredentialRequest(t, gateway, entry)
	req.Storage = oauthInstanceListErrorStorage{Client: req.Storage}

	if err := (&MCPCatalogHandler{gatewayClient: gateway}).DeleteOAuthCredentials(req); err == nil {
		t.Fatal("Clear reported success after instance list failure")
	}
	if _, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth"); err != nil {
		t.Fatalf("instance-list failure removed the shared credential: %v", err)
	}
}

func TestDeleteOAuthCredentialsReturnsServerTokenPurgeFailure(t *testing.T) {
	failPurge := false
	triggered := map[string]int{}
	gateway, rawDB := newOAuthCredentialClaimGatewayWithTrigger(t, func(_ context.Context, mcpID string) error {
		triggered[mcpID]++
		if failPurge && mcpID == "instance-a-user-1" {
			return errors.New("token purge trigger unavailable")
		}
		return nil
	})
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	server := &v1.MCPServer{Name: "server-a", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: entry.Name}}
	instances := []*v1.MCPServerInstance{
		{Name: "instance-a-user-1", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: server.Name, MCPServerCatalogEntryName: entry.Name}},
		{Name: "instance-a-user-2", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-2", MCPServerName: server.Name, MCPServerCatalogEntryName: entry.Name}},
	}
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{
		"CLIENT_ID": "saved-client", "CLIENT_SECRET": "saved-secret", "GENERATION": testStaticOAuthCredentialGeneration,
	}}); err != nil {
		t.Fatalf("seed OAuth credential: %v", err)
	}
	for _, instance := range instances {
		seedCatalogOwnedOAuthToken(t, rawDB, instance.Spec.UserID, instance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, entry.Name, "token-"+instance.Name)
	}
	clear(triggered)
	failPurge = true
	req := newDeleteOAuthCredentialRequest(t, gateway, entry, server, instances[0], instances[1])

	if err := (&MCPCatalogHandler{gatewayClient: gateway}).DeleteOAuthCredentials(req); err == nil {
		t.Fatal("Clear reported success after per-instance token purge failure")
	}
	for _, instance := range instances {
		if triggered[instance.Name] != 1 {
			t.Fatalf("cleanup did not attempt every matching instance: %#v", triggered)
		}
		if _, err := gateway.GetMCPOAuthToken(t.Context(), instance.Spec.UserID, instance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("token for %s remained after partial cleanup failure: %v", instance.Name, err)
		}
	}
}

func TestDeleteOAuthCredentialsRetryAfterTriggerFailureRetriesNotification(t *testing.T) {
	purgeAttempts := 0
	gateway, rawDB := newOAuthCredentialClaimGatewayWithTrigger(t, func(_ context.Context, mcpID string) error {
		if mcpID != "instance-a-user-1" {
			return nil
		}
		purgeAttempts++
		if purgeAttempts == 1 {
			return errors.New("token purge trigger unavailable")
		}
		return nil
	})
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	server := &v1.MCPServer{Name: "server-a", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: entry.Name}}
	instance := &v1.MCPServerInstance{Name: "instance-a-user-1", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: server.Name, MCPServerCatalogEntryName: entry.Name}}
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{
		"CLIENT_ID": "saved-client", "CLIENT_SECRET": "saved-secret", "GENERATION": testStaticOAuthCredentialGeneration,
	}}); err != nil {
		t.Fatalf("seed OAuth credential: %v", err)
	}
	seedCatalogOwnedOAuthToken(t, rawDB, instance.Spec.UserID, instance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, entry.Name, "token")
	req := newDeleteOAuthCredentialRequest(t, gateway, entry, server, instance)
	handler := &MCPCatalogHandler{gatewayClient: gateway}

	if err := handler.DeleteOAuthCredentials(req); err == nil {
		t.Fatal("first Clear reported success after token purge failure")
	}
	if _, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth"); !errors.As(err, &gatewayclient.CredentialNotFoundError{}) {
		t.Fatalf("shared credential remained after first Clear: %v", err)
	}
	if err := handler.DeleteOAuthCredentials(newDeleteOAuthCredentialRequest(t, gateway, entry, server, instance)); err != nil {
		t.Fatalf("retry Clear after credential removal: %v", err)
	}
	if purgeAttempts != 2 {
		t.Fatalf("token purge attempts = %d, want both Clear attempts", purgeAttempts)
	}
	if _, err := gateway.GetMCPOAuthToken(t.Context(), instance.Spec.UserID, instance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("user token remained after retry: %v", err)
	}
}
