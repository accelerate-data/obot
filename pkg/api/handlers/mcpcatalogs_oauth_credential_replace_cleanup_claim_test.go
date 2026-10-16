package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): a static OAuth Replace
// swaps the application atomically, clears only that entry's user tokens,
// cannot recreate a cleared application, and works in workspace scope. Kept in
// its own file so an upstream sync cannot drop these tests by merging over a
// shared one.

import (
	"context"
	"errors"
	"strings"
	"testing"

	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"gorm.io/gorm"
)

func TestReplaceOAuthCredentialsCleanupFailureLeavesNewConfigurationAndRequiresFreshProofToRetry(t *testing.T) {
	failCleanup := false
	gateway, rawDB := newOAuthCredentialClaimGatewayWithTrigger(t, func(_ context.Context, mcpID string) error {
		if failCleanup && mcpID == "instance-a-user-1" {
			return errors.New("instance token reconciliation unavailable")
		}
		return nil
	})
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	server := &v1.MCPServer{Name: "server-a", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: entry.Name}}
	instance := &v1.MCPServerInstance{Name: "instance-a-user-1", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: server.Name, MCPServerCatalogEntryName: entry.Name}}
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"}}); err != nil {
		t.Fatalf("seed active OAuth credential: %v", err)
	}
	seedCatalogOwnedOAuthToken(t, rawDB, instance.Spec.UserID, instance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, entry.Name, "active-token")
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, instance.Spec.UserID)
	failCleanup = true
	handler := &MCPCatalogHandler{gatewayClient: gateway}
	req := newReplaceOAuthCredentialRequest(t, gateway, entry.DeepCopy(), instance.Spec.UserID, "candidate-client", "candidate-secret", proof, server, instance)

	err := handler.ReplaceOAuthCredentials(req)
	if err == nil || !strings.Contains(err.Error(), instance.Name) {
		t.Fatalf("Replace cleanup error = %v, want instance-scoped error", err)
	}
	credential, revealErr := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	if revealErr != nil {
		t.Fatalf("reveal credential after cleanup failure: %v", revealErr)
	}
	if credential.Secrets["CLIENT_ID"] != "candidate-client" || credential.Secrets["CLIENT_SECRET"] != "candidate-secret" {
		t.Fatalf("replacement credential after cleanup failure = %#v", credential.Secrets)
	}
	if _, err := gateway.GetMCPOAuthToken(t.Context(), instance.Spec.UserID, instance.Name, entry.Spec.Manifest.RemoteConfig.FixedURL); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("instance token remained after cleanup trigger failure: %v", err)
	}

	retryReq := newReplaceOAuthCredentialRequest(t, gateway, entry.DeepCopy(), instance.Spec.UserID, "candidate-client", "candidate-secret", proof, server, instance)
	if err := handler.ReplaceOAuthCredentials(retryReq); err == nil {
		t.Fatal("Replace reused the proof consumed by the applied replacement")
	}
	failCleanup = false
	freshProof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, instance.Spec.UserID)
	freshReq := newReplaceOAuthCredentialRequest(t, gateway, entry.DeepCopy(), instance.Spec.UserID, "candidate-client", "candidate-secret", freshProof, server, instance)
	if err := handler.ReplaceOAuthCredentials(freshReq); err != nil {
		t.Fatalf("Replace with a fresh proof did not retry cleanup: %v", err)
	}
}

func TestReplaceOAuthCredentialsSupportsWorkspaceScope(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "", "https://mcp.example/api")
	entry.Spec.PowerUserWorkspaceID = "workspace-1"
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entry.Name),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"},
	}); err != nil {
		t.Fatalf("seed workspace OAuth credential: %v", err)
	}
	workspace := &v1.PowerUserWorkspace{Name: "workspace-1", Namespace: system.DefaultNamespace, Spec: v1.PowerUserWorkspaceSpec{UserID: "user-1"}}
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
	req := newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof, workspace)
	req.SetPathValue("catalog_id", "")
	req.SetPathValue("workspace_id", workspace.Name)

	if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).ReplaceOAuthCredentials(req); err != nil {
		t.Fatalf("replace workspace OAuth app: %v", err)
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(entry.Name)}, "oauth")
	if err != nil {
		t.Fatalf("reveal workspace OAuth credential: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != "candidate-client" {
		t.Fatalf("workspace replacement credential = %#v", credential.Secrets)
	}
}

func TestReplaceOAuthCredentialsCannotRecreateApplicationAfterClear(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	credentialName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: credentialName,
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret",
			"GENERATION": testStaticOAuthCredentialGeneration,
		},
	}); err != nil {
		t.Fatalf("seed active OAuth credential: %v", err)
	}
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
	handler := &MCPCatalogHandler{gatewayClient: gateway}

	if err := handler.DeleteOAuthCredentials(newDeleteOAuthCredentialRequest(t, gateway, entry.DeepCopy())); err != nil {
		t.Fatalf("clear OAuth credential: %v", err)
	}
	replace := newReplaceOAuthCredentialRequest(t, gateway, entry.DeepCopy(), "user-1", "candidate-client", "candidate-secret", proof)
	if err := handler.ReplaceOAuthCredentials(replace); err == nil {
		t.Fatal("stale replacement proof recreated a cleared OAuth application")
	}
	if _, err := gateway.RevealCredential(t.Context(), []string{credentialName}, "oauth"); !errors.As(err, &gatewayclient.CredentialNotFoundError{}) {
		t.Fatalf("cleared credential was recreated: %v", err)
	}
}

func TestReplaceOAuthCredentialsAtomicallySwapsAppAndClearsOnlyMatchingTokens(t *testing.T) {
	gateway, rawDB := newOAuthCredentialTestGatewayClientWithOptionsAndDB(t, staticOAuthTestEncryptionConfig(), nil)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	server := &v1.MCPServer{Name: "server-a", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: entry.Name}}
	instance := &v1.MCPServerInstance{Name: "instance-a-user-1", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: server.Name, MCPServerCatalogEntryName: entry.Name}}
	unrelatedServer := &v1.MCPServer{Name: "server-unrelated", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: "entry-unrelated"}}
	unrelatedInstance := &v1.MCPServerInstance{Name: "instance-unrelated", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: unrelatedServer.Name, MCPServerCatalogEntryName: "entry-unrelated"}}
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{"CLIENT_ID": "old-client", "CLIENT_SECRET": "old-secret"}}); err != nil {
		t.Fatalf("seed old OAuth credential: %v", err)
	}
	for _, mcpID := range []string{server.Name, instance.Name} {
		seedCatalogOwnedOAuthToken(t, rawDB, instance.Spec.UserID, mcpID, entry.Spec.Manifest.RemoteConfig.FixedURL, entry.Name, "old-token-"+mcpID)
	}
	for _, mcpID := range []string{unrelatedServer.Name, unrelatedInstance.Name} {
		seedCatalogOwnedOAuthToken(t, rawDB, instance.Spec.UserID, mcpID, entry.Spec.Manifest.RemoteConfig.FixedURL, "entry-unrelated", "old-token-"+mcpID)
	}

	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, instance.Spec.UserID)
	req := newReplaceOAuthCredentialRequest(t, gateway, entry.DeepCopy(), instance.Spec.UserID, "candidate-client", "candidate-secret", proof, server, instance, unrelatedServer, unrelatedInstance)
	if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).ReplaceOAuthCredentials(req); err != nil {
		t.Fatalf("replace OAuth app: %v", err)
	}

	for _, mcpID := range []string{server.Name, instance.Name} {
		if _, err := gateway.GetMCPOAuthToken(t.Context(), instance.Spec.UserID, mcpID, entry.Spec.Manifest.RemoteConfig.FixedURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("old matching token for %s survived OAuth app replacement: %v", mcpID, err)
		}
	}
	for _, mcpID := range []string{unrelatedServer.Name, unrelatedInstance.Name} {
		if _, err := gateway.GetMCPOAuthToken(t.Context(), instance.Spec.UserID, mcpID, entry.Spec.Manifest.RemoteConfig.FixedURL); err != nil {
			t.Fatalf("unrelated token for %s was removed: %v", mcpID, err)
		}
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	if err != nil {
		t.Fatalf("reveal replacement OAuth credential: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != "candidate-client" || credential.Secrets["CLIENT_SECRET"] != "candidate-secret" {
		t.Fatalf("replacement credential = %#v", credential.Secrets)
	}
}
