package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): a static OAuth Replace
// leaves the active application untouched on a mismatched proof or a failed
// list or upsert, consumes its proof, rotates the generation, and serializes
// same-proof requests. Kept in its own file so an upstream sync cannot drop
// these tests by merging over a shared one.

import (
	"strings"
	"testing"
	"time"

	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
)

func TestReplaceOAuthCredentialsRejectsMismatchedProofWithoutMutatingActiveConfiguration(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	server := &v1.MCPServer{Name: "server-a", Namespace: system.DefaultNamespace, Spec: v1.MCPServerSpec{MCPServerCatalogEntryName: entry.Name}}
	instance := &v1.MCPServerInstance{Name: "instance-a-user-1", Namespace: system.DefaultNamespace, Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: server.Name, MCPServerCatalogEntryName: entry.Name}}
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"}}); err != nil {
		t.Fatalf("seed active OAuth credential: %v", err)
	}
	for _, mcpID := range []string{server.Name, instance.Name} {
		if err := gateway.ReplaceMCPOAuthToken(t.Context(), instance.Spec.UserID, mcpID, entry.Spec.Manifest.RemoteConfig.FixedURL, "", &oauth2.Config{}, &oauth2.Token{AccessToken: "active-token-" + mcpID}); err != nil {
			t.Fatalf("seed active user token for %s: %v", mcpID, err)
		}
	}
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, instance.Spec.UserID)
	req := newReplaceOAuthCredentialRequest(t, gateway, entry, instance.Spec.UserID, "changed-after-test", "candidate-secret", proof, server, instance)

	if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).ReplaceOAuthCredentials(req); err == nil {
		t.Fatal("Replace accepted credentials that did not match the successful proof")
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	if err != nil {
		t.Fatalf("reveal active credential after rejected replacement: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != "active-client" || credential.Secrets["CLIENT_SECRET"] != "active-secret" {
		t.Fatalf("active credential changed after rejected replacement: %#v", credential.Secrets)
	}
	for _, mcpID := range []string{server.Name, instance.Name} {
		if _, err := gateway.GetMCPOAuthToken(t.Context(), instance.Spec.UserID, mcpID, entry.Spec.Manifest.RemoteConfig.FixedURL); err != nil {
			t.Fatalf("active user token for %s was removed after rejected replacement: %v", mcpID, err)
		}
	}
	retry := newReplaceOAuthCredentialRequest(t, gateway, entry, instance.Spec.UserID, "candidate-client", "candidate-secret", proof, server, instance)
	if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).ReplaceOAuthCredentials(retry); err == nil || !strings.Contains(err.Error(), "invalid or expired OAuth credential test") {
		t.Fatalf("rejected replacement left proof reusable: %v", err)
	}
}

func TestReplaceOAuthCredentialsRotatesGenerationForSameValueReplacement(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: credName,
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"},
	}); err != nil {
		t.Fatalf("seed active OAuth credential: %v", err)
	}
	proof := successfulStaticOAuthCredentialProofFor(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1", "active-client", "active-secret")
	req := newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "active-client", "active-secret", proof)

	if err := (&MCPCatalogHandler{gatewayClient: gateway}).ReplaceOAuthCredentials(req); err != nil {
		t.Fatalf("same-value replacement failed: %v", err)
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	if err != nil {
		t.Fatalf("reveal replaced credential: %v", err)
	}
	if credential.Secrets["GENERATION"] == "" {
		t.Fatal("same-value replacement did not rotate the credential generation")
	}
}

func TestReplaceOAuthCredentialsListFailureLeavesActiveConfigurationAndConsumesProof(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"}}); err != nil {
		t.Fatalf("seed active OAuth credential: %v", err)
	}
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
	req := newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
	req.Storage = oauthInstanceListErrorStorage{Client: req.Storage}

	if err := (&MCPCatalogHandler{gatewayClient: gateway}).ReplaceOAuthCredentials(req); err == nil {
		t.Fatal("Replace reported success after instance list failure")
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	if err != nil {
		t.Fatalf("reveal active credential after list failure: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != "active-client" || credential.Secrets["CLIENT_SECRET"] != "active-secret" {
		t.Fatalf("active credential changed after list failure: %#v", credential.Secrets)
	}
	retry := newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
	if err := (&MCPCatalogHandler{gatewayClient: gateway}).ReplaceOAuthCredentials(retry); err == nil || !strings.Contains(err.Error(), "invalid or expired OAuth credential test") {
		t.Fatalf("list failure left proof reusable: %v", err)
	}
}

func TestReplaceOAuthCredentialsUpsertFailureLeavesActiveConfigurationAndConsumesProof(t *testing.T) {
	transformer := &toggleCredentialWriteErrorTransformer{}
	gateway := newOAuthCredentialClaimGatewayWithEncryption(t, &encryptionconfig.EncryptionConfiguration{Transformers: map[schema.GroupResource]value.Transformer{
		{Group: "obot.obot.ai", Resource: "credentials"}: transformer,
	}})
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"}}); err != nil {
		t.Fatalf("seed active OAuth credential: %v", err)
	}
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
	transformer.failWrite = true
	req := newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)

	if err := (&MCPCatalogHandler{gatewayClient: gateway}).ReplaceOAuthCredentials(req); err == nil {
		t.Fatal("Replace reported success after credential upsert failure")
	}
	transformer.failWrite = false
	credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	if err != nil {
		t.Fatalf("reveal active credential after upsert failure: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != "active-client" || credential.Secrets["CLIENT_SECRET"] != "active-secret" {
		t.Fatalf("active credential changed after upsert failure: %#v", credential.Secrets)
	}
	retry := newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
	if err := (&MCPCatalogHandler{gatewayClient: gateway}).ReplaceOAuthCredentials(retry); err == nil || !strings.Contains(err.Error(), "invalid or expired OAuth credential test") {
		t.Fatalf("upsert failure left proof reusable: %v", err)
	}
}

func TestReplaceOAuthCredentialsSerializesConcurrentSameProofRequests(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	credName := system.MCPOAuthCredentialName(entry.Name)
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: credName, Name: "oauth", Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"}}); err != nil {
		t.Fatalf("seed active OAuth credential: %v", err)
	}
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
	handler := &MCPCatalogHandler{gatewayClient: gateway}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		req := newReplaceOAuthCredentialRequest(t, gateway, entry.DeepCopy(), "user-1", "candidate-client", "candidate-secret", proof)
		go func() {
			<-start
			results <- handler.ReplaceOAuthCredentials(req)
		}()
	}
	close(start)

	var successes int
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				successes++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent replacements")
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent replacement successes = %d, want exactly 1", successes)
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	if err != nil {
		t.Fatalf("reveal credential after concurrent replacements: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != "candidate-client" || credential.Secrets["CLIENT_SECRET"] != "candidate-secret" {
		t.Fatalf("credential after concurrent replacements = %#v", credential.Secrets)
	}
}
